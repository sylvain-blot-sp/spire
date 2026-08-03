package endpoints

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
	"time"

	"github.com/andres-erbsen/clock"
	"github.com/sirupsen/logrus"

	"github.com/spiffe/spire/pkg/common/telemetry"
	server_telemetry "github.com/spiffe/spire/pkg/common/telemetry/server"
	"github.com/spiffe/spire/pkg/server/api"
	"github.com/spiffe/spire/pkg/server/authorizedentries"
	"github.com/spiffe/spire/pkg/server/cache/nodecache"
	"github.com/spiffe/spire/pkg/server/datastore"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type attestedNodes struct {
	cache     *authorizedentries.Cache
	nodeCache *nodecache.Cache
	clk       clock.Clock
	ds        datastore.DataStore
	log       logrus.FieldLogger
	metrics   telemetry.Metrics

	eventsBeforeFirst map[uint]struct{}

	firstEvent     uint
	firstEventTime time.Time
	lastEvent      uint

	eventTracker *eventTracker
	eventTimeout time.Duration
	pageSize     int32

	// startupGapWindow is how many event IDs below the startup watermark are
	// checked for in-flight transactions. Zero disables bounded seeding and
	// falls back to scanning the entire retained event history.
	startupGapWindow uint

	fetchNodes map[string]struct{}

	// build instrumentation, reported by buildCache
	loadedNodes    int
	loadedPages    int
	eventsDuration time.Duration
	loadDuration   time.Duration

	// metrics change detection
	skippedNodeEvents int
	lastCacheStats    authorizedentries.CacheStats
}

func (a *attestedNodes) captureChangedNodes(ctx context.Context) error {
	if err := a.searchBeforeFirstEvent(ctx); err != nil {
		return err
	}
	a.selectPolledEvents(ctx)
	return a.scanForNewEvents(ctx)
}

func (a *attestedNodes) searchBeforeFirstEvent(ctx context.Context) error {
	// First event detected, and startup was less than a transaction timout away.
	if !a.firstEventTime.IsZero() && a.clk.Now().Sub(a.firstEventTime) <= a.eventTimeout {
		resp, err := a.ds.ListAttestedNodeEvents(ctx, &datastore.ListAttestedNodeEventsRequest{
			// With bounded seeding the first event is the watermark, so an
			// unbounded scan below it would read the whole events table on
			// every poll. Only the same gap window can hold a transaction
			// that was still in flight at startup.
			GreaterThanEventID: a.startupWindowLowerBound(a.firstEvent),
			LessThanEventID:    a.firstEvent,
		})
		if err != nil {
			return err
		}
		for _, event := range resp.Events {
			// if we have seen it before, don't reload it.
			if _, seen := a.eventsBeforeFirst[event.EventID]; !seen {
				a.fetchNodes[event.SpiffeID] = struct{}{}
				a.eventsBeforeFirst[event.EventID] = struct{}{}
			}
		}
		return nil
	}

	// zero out unused event tracker
	if len(a.eventsBeforeFirst) != 0 {
		a.eventsBeforeFirst = make(map[uint]struct{})
	}

	return nil
}

func (a *attestedNodes) selectPolledEvents(ctx context.Context) {
	// check if the polled events have appeared out-of-order
	selectedEvents := a.eventTracker.SelectEvents()
	defer a.eventTracker.FreeEvents(selectedEvents)

	for _, eventID := range selectedEvents {
		log := a.log.WithField(telemetry.EventID, eventID)
		event, err := a.ds.FetchAttestedNodeEvent(ctx, eventID)
		if errors.Is(err, context.Canceled) {
			return
		}

		switch status.Code(err) {
		case codes.OK:
		case codes.NotFound:
			continue
		default:
			log.WithError(err).Errorf("Failed to fetch info about skipped node event %d", eventID)
			continue
		}

		a.fetchNodes[event.SpiffeID] = struct{}{}
		a.eventTracker.StopTracking(eventID)
	}
}

// seedEvents establishes the event state the cache build starts from. With
// bounded seeding it costs two indexed reads; without it, it scans the entire
// retained event history and marks every node it finds for re-fetch, which is
// the behavior that predates the gap window.
func (a *attestedNodes) seedEvents(ctx context.Context) error {
	if a.startupGapWindow == 0 {
		return a.captureChangedNodes(ctx)
	}
	return a.seedWatermark(ctx)
}

// startupWindowLowerBound returns the exclusive lower bound of the startup gap
// window below watermark, or zero when bounded seeding is disabled.
func (a *attestedNodes) startupWindowLowerBound(watermark uint) uint {
	if a.startupGapWindow == 0 || watermark <= a.startupGapWindow {
		return 0
	}
	return watermark - a.startupGapWindow
}

// seedWatermark establishes the initial event watermark without listing the
// entire events table and without marking every node for re-fetch. See
// registrationEntries.seedWatermark for why this preserves correctness.
func (a *attestedNodes) seedWatermark(ctx context.Context) error {
	latest, err := a.ds.FetchLatestAttestedNodeEventID(ctx)
	if err != nil {
		return fmt.Errorf("failed to fetch latest attested node event id: %w", err)
	}
	if latest == 0 {
		return nil
	}

	lowerBound := a.startupWindowLowerBound(latest)
	resp, err := a.ds.ListAttestedNodeEvents(ctx, &datastore.ListAttestedNodeEventsRequest{
		GreaterThanEventID: lowerBound,
		LessThanEventID:    latest + 1,
	})
	if err != nil {
		return fmt.Errorf("failed to list attested node events in the startup gap window: %w", err)
	}

	present := make(map[uint]struct{}, len(resp.Events))
	oldest := latest
	for _, event := range resp.Events {
		present[event.EventID] = struct{}{}
		oldest = min(oldest, event.EventID)
	}

	// See registrationEntries.seedWatermark for why a truncated window cannot
	// skip the pruned prefix.
	trackFrom := lowerBound + 1
	if lowerBound == 0 {
		trackFrom = oldest + 1
	}

	tracked := 0
	for eventID := trackFrom; eventID < latest; eventID++ {
		if _, ok := present[eventID]; !ok {
			a.eventTracker.StartTracking(eventID)
			tracked++
		}
	}

	a.firstEvent = latest
	a.lastEvent = latest
	a.firstEventTime = a.clk.Now()

	a.log.WithFields(logrus.Fields{
		telemetry.EventID: latest,
		logFieldEvents:    len(resp.Events),
		logFieldTracked:   tracked,
	}).Debug("Seeded attested node event watermark")

	return nil
}

func (a *attestedNodes) scanForNewEvents(ctx context.Context) error {
	resp, err := a.ds.ListAttestedNodeEvents(ctx, &datastore.ListAttestedNodeEventsRequest{
		DataConsistency:    datastore.TolerateStale,
		GreaterThanEventID: a.lastEvent,
	})
	if err != nil {
		return err
	}

	for _, event := range resp.Events {
		// event time determines if we have seen the first event.
		if a.firstEventTime.IsZero() {
			a.firstEvent = event.EventID
			a.lastEvent = event.EventID
			a.fetchNodes[event.SpiffeID] = struct{}{}
			a.firstEventTime = a.clk.Now()
			continue
		}

		// track any skipped event ids, should they appear later.
		for skipped := a.lastEvent + 1; skipped < event.EventID; skipped++ {
			a.eventTracker.StartTracking(skipped)
		}

		// every event adds its entry to the entry fetch list.
		a.fetchNodes[event.SpiffeID] = struct{}{}
		a.lastEvent = event.EventID
	}
	return nil
}

func (a *attestedNodes) loadCache(ctx context.Context, sink authorizedentries.CacheSink) error {
	a.loadedNodes = 0
	a.loadedPages = 0

	// Nodes carry their selectors, so an unpaginated list holds every node and
	// every selector row in memory at once, on top of the entry pages already
	// in flight. Paginating caps that at one page.
	var token string
	for {
		nodesResp, err := a.ds.ListAttestedNodes(ctx, &datastore.ListAttestedNodesRequest{
			FetchSelectors: true,
			Pagination: &datastore.Pagination{
				Token:    token,
				PageSize: a.pageSize,
			},
		})
		if err != nil {
			return fmt.Errorf("failed to list attested nodes: %w", err)
		}

		for _, node := range nodesResp.Nodes {
			agentExpiresAt := time.Unix(node.CertNotAfter, 0)
			if agentExpiresAt.Before(a.clk.Now()) {
				continue
			}
			sink.UpdateAgent(node.SpiffeId, agentExpiresAt, api.ProtoFromSelectors(node.Selectors))
			a.nodeCache.UpdateAttestedNode(node)
			a.loadedNodes++
		}
		a.loadedPages++

		token = nodesResp.Pagination.Token
		if token == "" {
			return nil
		}
	}
}

// buildAttestedNodesCache fetches all attested nodes and writes the unexpired
// ones into sink. It runs once at startup. The caller is responsible for
// assigning the finished cache once the sink has produced it.
func buildAttestedNodesCache(ctx context.Context, log logrus.FieldLogger, metrics telemetry.Metrics, ds datastore.DataStore, clk clock.Clock, sink authorizedentries.CacheSink, nodeCache *nodecache.Cache, pageSize int32, cacheReloadInterval, eventTimeout time.Duration, startupGapWindow uint) (*attestedNodes, error) {
	if pageSize <= 0 {
		return nil, fmt.Errorf("page size must be positive, got %d", pageSize)
	}

	pollPeriods := PollPeriods(cacheReloadInterval, eventTimeout)

	attestedNodes := &attestedNodes{
		nodeCache:        nodeCache,
		clk:              clk,
		ds:               ds,
		log:              log,
		metrics:          metrics,
		eventTimeout:     eventTimeout,
		pageSize:         pageSize,
		startupGapWindow: startupGapWindow,

		eventsBeforeFirst: make(map[uint]struct{}),
		fetchNodes:        make(map[string]struct{}),

		eventTracker: NewEventTracker(pollPeriods),

		// initialize gauges to nonsense values to force a change.
		skippedNodeEvents: -1,
		lastCacheStats: authorizedentries.CacheStats{
			AgentsByID:        -1,
			AgentsByExpiresAt: -1,
		},
	}

	eventsStart := time.Now()
	if err := attestedNodes.seedEvents(ctx); err != nil {
		return nil, err
	}
	attestedNodes.eventsDuration = time.Since(eventsStart)
	server_telemetry.MeasureEntryCacheBuildPhase(metrics, server_telemetry.EntryCacheBuildPhaseNodeEvents, eventsStart)

	loadStart := time.Now()
	if err := attestedNodes.loadCache(ctx, sink); err != nil {
		return nil, err
	}
	attestedNodes.loadDuration = time.Since(loadStart)
	server_telemetry.MeasureEntryCacheBuildPhase(metrics, server_telemetry.EntryCacheBuildPhaseNodeLoad, loadStart)

	attestedNodes.emitMetrics(sink.Stats())

	return attestedNodes, nil
}

// updateCache Fetches all the events since the last time this function was running and updates
// the cache with all the changes.
func (a *attestedNodes) updateCache(ctx context.Context) error {
	if err := a.captureChangedNodes(ctx); err != nil {
		return err
	}
	if err := a.updateCachedNodes(ctx); err != nil {
		return err
	}
	a.emitMetrics(a.cache.Stats())

	return nil
}

func (a *attestedNodes) updateCachedNodes(ctx context.Context) error {
	spiffeIds := slices.Collect(maps.Keys(a.fetchNodes))
	for pageStart := 0; pageStart < len(spiffeIds); pageStart += int(a.pageSize) {
		fetchNodes := a.fetchNodesPage(spiffeIds, pageStart)
		nodes, err := a.ds.FetchAttestedNodes(ctx, fetchNodes)
		if err != nil {
			return err
		}

		for _, spiffeId := range fetchNodes {
			node, ok := nodes[spiffeId]
			// Node was deleted (absent from the response, or explicitly nil)
			if !ok || node == nil {
				a.nodeCache.RemoveAttestedNode(spiffeId)
				a.cache.RemoveAgent(spiffeId)
				delete(a.fetchNodes, spiffeId)
				continue
			}

			agentExpiresAt := time.Unix(node.CertNotAfter, 0)
			a.cache.UpdateAgent(node.SpiffeId, agentExpiresAt, api.ProtoFromSelectors(node.Selectors))
			a.nodeCache.UpdateAttestedNode(node)
			delete(a.fetchNodes, spiffeId)
		}
	}
	return nil
}

// fetchNodesPage gets the range for the page starting at pageStart
func (a *attestedNodes) fetchNodesPage(spiffeIds []string, pageStart int) []string {
	pageEnd := min(len(spiffeIds), pageStart+int(a.pageSize))
	return spiffeIds[pageStart:pageEnd]
}

func (a *attestedNodes) swapCache(cache *authorizedentries.Cache) {
	a.cache = cache
	a.fetchNodes = make(map[string]struct{})
}

// emitMetrics reports the gauges for cacheStats, which during a build belong
// to the cache being built rather than the published one.
func (a *attestedNodes) emitMetrics(cacheStats authorizedentries.CacheStats) {
	if a.skippedNodeEvents != a.eventTracker.EventCount() {
		a.skippedNodeEvents = a.eventTracker.EventCount()
		server_telemetry.SetSkippedNodeEventIDsCacheCountGauge(a.metrics, a.skippedNodeEvents)
	}

	// AgentsByID and AgentsByExpiresAt should be the same.
	if a.lastCacheStats.AgentsByID != cacheStats.AgentsByID {
		a.lastCacheStats.AgentsByID = cacheStats.AgentsByID
		server_telemetry.SetAgentsByIDCacheCountGauge(a.metrics, a.lastCacheStats.AgentsByID)
	}
	if a.lastCacheStats.AgentsByExpiresAt != cacheStats.AgentsByExpiresAt {
		a.lastCacheStats.AgentsByExpiresAt = cacheStats.AgentsByExpiresAt
		server_telemetry.SetAgentsByExpiresAtCacheCountGauge(a.metrics, a.lastCacheStats.AgentsByExpiresAt)
	}
}
