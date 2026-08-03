package endpoints

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/andres-erbsen/clock"
	"github.com/sirupsen/logrus"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/common/telemetry"
	server_telemetry "github.com/spiffe/spire/pkg/common/telemetry/server"
	"github.com/spiffe/spire/pkg/server/api"
	"github.com/spiffe/spire/pkg/server/authorizedentries"
	"github.com/spiffe/spire/pkg/server/cache/nodecache"
	"github.com/spiffe/spire/pkg/server/datastore"
)

var _ api.AuthorizedEntryFetcher = (*AuthorizedEntryFetcherEvents)(nil)

// defaultPageSize is how many rows each cache load page requests when the
// operator has not configured a size.
const defaultPageSize = 10000

// maxPageSize caps the configured page size. Pages are held in memory whole
// and several are in flight at once, so an unbounded value would trade the
// startup win for an out-of-memory risk.
const maxPageSize = 100000

// defaultStartupGapWindow is how many event IDs below the startup watermark
// are checked for transactions that were in flight when the cache snapshot was
// read. A deeper gap would need that many event IDs to be allocated by
// transactions that all commit after the snapshot; the full cache reload is
// the backstop if that ever happens.
const defaultStartupGapWindow = 10000

// Log field names used by the cache build instrumentation.
const (
	logFieldPages      = "pages"
	logFieldDurationMS = "duration_ms"
	logFieldEntries    = "entries"
	logFieldAliases    = "aliases"
	logFieldAgents     = "agents"
	logFieldNodes      = "nodes"
	logFieldEvents     = "events"
	logFieldPageSize   = "page_size"
	logFieldTracked    = "tracked"
	logFieldGapWindow  = "gap_window"
)

func durationMS(d time.Duration) int64 {
	return d.Milliseconds()
}

type AuthorizedEntryFetcherEventsConfig struct {
	clk                     clock.Clock
	log                     logrus.FieldLogger
	cacheReloadInterval     time.Duration
	fullCacheReloadInterval time.Duration
	pruneEventsOlderThan    time.Duration
	eventTimeout            time.Duration
	ds                      datastore.DataStore
	nodeCache               *nodecache.Cache
	metrics                 telemetry.Metrics

	// pageSize is how many rows each cache load page requests. Zero selects
	// defaultPageSize.
	pageSize int32

	// startupGapWindow is how many event IDs below the startup watermark are
	// checked for transactions that were in flight when the cache was built.
	// Nil selects defaultStartupGapWindow; an explicit zero restores the
	// pre-existing behavior of scanning the entire retained event history.
	startupGapWindow *uint
}

type AuthorizedEntryFetcherEvents struct {
	c AuthorizedEntryFetcherEventsConfig

	// cache is published atomically. A cache is only ever stored here once it
	// is fully built, so readers can never observe a partial cache.
	cache atomic.Pointer[authorizedentries.Cache]

	registrationEntries eventsBasedCache
	attestedNodes       eventsBasedCache
	trustDomain         string
}

type eventsBasedCache interface {
	updateCache(ctx context.Context) error
	loadCache(ctx context.Context, sink authorizedentries.CacheSink) error
	swapCache(cache *authorizedentries.Cache)
}

func NewAuthorizedEntryFetcherEvents(ctx context.Context, trustDomain string, c AuthorizedEntryFetcherEventsConfig) (*AuthorizedEntryFetcherEvents, error) {
	switch {
	case c.pageSize == 0:
		c.pageSize = defaultPageSize
	case c.pageSize < 0 || c.pageSize > maxPageSize:
		return nil, fmt.Errorf("entry cache page size must be between 1 and %d, got %d", maxPageSize, c.pageSize)
	}

	if c.startupGapWindow == nil {
		gapWindow := uint(defaultStartupGapWindow)
		c.startupGapWindow = &gapWindow
	}

	authorizedEntryFetcher := &AuthorizedEntryFetcherEvents{
		c:           c,
		trustDomain: trustDomain,
	}

	c.log.WithFields(logrus.Fields{
		logFieldPageSize:  c.pageSize,
		logFieldGapWindow: *c.startupGapWindow,
	}).Info("Building event-based in-memory entry cache")
	start := time.Now()
	if err := authorizedEntryFetcher.buildCache(ctx); err != nil {
		return nil, err
	}
	server_telemetry.MeasureEntryCacheBuildPhase(c.metrics, server_telemetry.EntryCacheBuildPhaseTotal, start)

	stats := authorizedEntryFetcher.cache.Load().Stats()
	c.log.WithFields(logrus.Fields{
		logFieldEntries:    stats.EntriesByEntryID,
		logFieldAliases:    stats.AliasesByEntryID,
		logFieldAgents:     stats.AgentsByID,
		logFieldDurationMS: durationMS(time.Since(start)),
	}).Info("Completed building event-based in-memory entry cache")

	return authorizedEntryFetcher, nil
}

func (a *AuthorizedEntryFetcherEvents) LookupAuthorizedEntries(_ context.Context, agentID spiffeid.ID, entryIDs map[string]struct{}) (map[string]api.ReadOnlyEntry, error) {
	return a.cache.Load().LookupAuthorizedEntries(agentID, entryIDs), nil
}

func (a *AuthorizedEntryFetcherEvents) FetchAuthorizedEntries(_ context.Context, agentID spiffeid.ID) ([]api.ReadOnlyEntry, error) {
	return a.cache.Load().GetAuthorizedEntries(agentID), nil
}

// RunUpdateCacheTask starts a ticker which rebuilds the in-memory entry cache.
func (a *AuthorizedEntryFetcherEvents) RunUpdateCacheTask(ctx context.Context) error {
	var fullCacheReload bool

	cacheReloadTicker, fullCacheReloadTicker := a.startTickers()
	defer cacheReloadTicker.Stop()
	defer fullCacheReloadTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			a.c.log.Debug("Stopping in-memory entry cache hydrator")
			return ctx.Err()
		case <-cacheReloadTicker.C:
			if fullCacheReload {
				if err := a.reloadCache(ctx); err != nil {
					a.c.log.WithError(err).Error("Failed to full refresh entry cache")
					continue
				}
				fullCacheReload = false
			} else {
				if err := a.updateCache(ctx); err != nil {
					a.c.log.WithError(err).Error("Failed to update entry cache")
				}
				if pruned := a.cache.Load().PruneExpiredAgents(); pruned > 0 {
					a.c.log.WithField("count", pruned).Debug("Pruned expired agents from entry cache")
				}
			}
		case <-fullCacheReloadTicker.C:
			fullCacheReload = true
		}
	}
}

// PruneEventsTask start a ticker which prunes old events
func (a *AuthorizedEntryFetcherEvents) PruneEventsTask(ctx context.Context) error {
	for {
		select {
		case <-ctx.Done():
			a.c.log.Debug("Stopping event pruner")
			return ctx.Err()
		case <-a.c.clk.After(a.c.pruneEventsOlderThan / 2):
			a.c.log.Debug("Pruning events")
			if err := a.pruneEvents(ctx, a.c.pruneEventsOlderThan); err != nil {
				a.c.log.WithError(err).Error("Failed to prune events")
			}
		}
	}
}

func (a *AuthorizedEntryFetcherEvents) pruneEvents(ctx context.Context, olderThan time.Duration) error {
	pruneRegistrationEntryEventsErr := a.c.ds.PruneRegistrationEntryEvents(ctx, olderThan)
	pruneAttestedNodeEventsErr := a.c.ds.PruneAttestedNodeEvents(ctx, olderThan)

	return errors.Join(pruneRegistrationEntryEventsErr, pruneAttestedNodeEventsErr)
}

func (a *AuthorizedEntryFetcherEvents) updateCache(ctx context.Context) error {
	updateRegistrationEntriesCacheErr := a.registrationEntries.updateCache(ctx)
	updateAttestedNodesCacheErr := a.attestedNodes.updateCache(ctx)

	return errors.Join(updateRegistrationEntriesCacheErr, updateAttestedNodesCacheErr)
}

// newCacheBuilder returns a builder presized from the currently published
// cache. On the first build there is nothing to size from and the maps simply
// grow. Counting rows up front is deliberately not an option: the datastore's
// CountRegistrationEntries paginates the entire entry set at page size 1000,
// so it would cost more than the growth it avoids.
func (a *AuthorizedEntryFetcherEvents) newCacheBuilder() *authorizedentries.CacheBuilder {
	var hint authorizedentries.CacheSizeHint
	if current := a.cache.Load(); current != nil {
		stats := current.Stats()
		hint.Entries = stats.EntriesByEntryID
		hint.Agents = stats.AgentsByID
	}
	return authorizedentries.NewCacheBuilder(a.c.clk, a.trustDomain, hint)
}

func (a *AuthorizedEntryFetcherEvents) reloadCache(ctx context.Context) error {
	builder := a.newCacheBuilder()

	if err := a.registrationEntries.loadCache(ctx, builder); err != nil {
		return err
	}

	if err := a.attestedNodes.loadCache(ctx, builder); err != nil {
		return err
	}

	cache := builder.Build()
	a.registrationEntries.swapCache(cache)
	a.attestedNodes.swapCache(cache)
	a.cache.Store(cache)

	return nil
}

func (a *AuthorizedEntryFetcherEvents) buildCache(ctx context.Context) error {
	builder := a.newCacheBuilder()

	registrationEntries, err := buildRegistrationEntriesCache(ctx, a.c.log, a.c.metrics, a.c.ds, a.c.clk, builder, a.c.pageSize, a.c.cacheReloadInterval, a.c.eventTimeout, *a.c.startupGapWindow)
	if err != nil {
		return err
	}

	attestedNodes, err := buildAttestedNodesCache(ctx, a.c.log, a.c.metrics, a.c.ds, a.c.clk, builder, a.c.nodeCache, a.c.pageSize, a.c.cacheReloadInterval, a.c.eventTimeout, *a.c.startupGapWindow)
	if err != nil {
		return err
	}

	a.c.log.WithFields(logrus.Fields{
		logFieldEvents:     len(registrationEntries.fetchEntries),
		logFieldDurationMS: durationMS(registrationEntries.eventsDuration),
	}).Info("Scanned registration entry events for entry cache build")
	a.c.log.WithFields(logrus.Fields{
		logFieldEntries:    registrationEntries.loadedEntries,
		logFieldPages:      registrationEntries.loadedPages,
		logFieldDurationMS: durationMS(registrationEntries.loadDuration),
	}).Info("Loaded registration entries for entry cache build")
	a.c.log.WithFields(logrus.Fields{
		logFieldEvents:     len(attestedNodes.fetchNodes),
		logFieldDurationMS: durationMS(attestedNodes.eventsDuration),
	}).Info("Scanned attested node events for entry cache build")
	a.c.log.WithFields(logrus.Fields{
		logFieldNodes:      attestedNodes.loadedNodes,
		logFieldPages:      attestedNodes.loadedPages,
		logFieldDurationMS: durationMS(attestedNodes.loadDuration),
	}).Info("Loaded attested nodes for entry cache build")

	// The cache only becomes reachable once both loads have succeeded and the
	// indexes are materialized.
	cache := builder.Build()
	registrationEntries.cache = cache
	attestedNodes.cache = cache

	a.registrationEntries = registrationEntries
	a.attestedNodes = attestedNodes
	a.cache.Store(cache)

	return nil
}

func (a *AuthorizedEntryFetcherEvents) startTickers() (*clock.Ticker, *clock.Ticker) {
	cacheReloadTicker := a.c.clk.Ticker(a.c.cacheReloadInterval)
	fullCacheReloadTicker := a.c.clk.Ticker(a.c.fullCacheReloadInterval)

	return cacheReloadTicker, fullCacheReloadTicker
}
