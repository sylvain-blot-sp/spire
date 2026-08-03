package endpoints

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"runtime"
	"slices"
	"sync"
	"time"

	"github.com/andres-erbsen/clock"
	"github.com/sirupsen/logrus"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"github.com/spiffe/spire/pkg/common/telemetry"
	server_telemetry "github.com/spiffe/spire/pkg/common/telemetry/server"
	"github.com/spiffe/spire/pkg/server/api"
	"github.com/spiffe/spire/pkg/server/authorizedentries"
	"github.com/spiffe/spire/pkg/server/datastore"
	"github.com/spiffe/spire/proto/spire/common"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type registrationEntries struct {
	cache   *authorizedentries.Cache
	clk     clock.Clock
	ds      datastore.DataStore
	log     logrus.FieldLogger
	metrics telemetry.Metrics

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

	fetchEntries map[string]struct{}

	// build instrumentation, reported by buildCache
	loadedEntries  int
	loadedPages    int
	eventsDuration time.Duration
	loadDuration   time.Duration

	// metrics change detection
	skippedEntryEvents int
	lastCacheStats     authorizedentries.CacheStats
}

func (a *registrationEntries) captureChangedEntries(ctx context.Context) error {
	if err := a.searchBeforeFirstEvent(ctx); err != nil {
		return err
	}
	a.selectPolledEvents(ctx)
	return a.scanForNewEvents(ctx)
}

func (a *registrationEntries) searchBeforeFirstEvent(ctx context.Context) error {
	// First event detected, and startup was less than a transaction timout away.
	if !a.firstEventTime.IsZero() && a.clk.Now().Sub(a.firstEventTime) <= a.eventTimeout {
		resp, err := a.ds.ListRegistrationEntryEvents(ctx, &datastore.ListRegistrationEntryEventsRequest{
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
				a.fetchEntries[event.EntryID] = struct{}{}
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

func (a *registrationEntries) selectPolledEvents(ctx context.Context) {
	// check if the polled events have appeared out-of-order
	selectedEvents := a.eventTracker.SelectEvents()
	defer a.eventTracker.FreeEvents(selectedEvents)

	for _, eventID := range selectedEvents {
		log := a.log.WithField(telemetry.EventID, eventID)
		event, err := a.ds.FetchRegistrationEntryEvent(ctx, eventID)

		if errors.Is(err, context.Canceled) {
			return
		}

		switch status.Code(err) {
		case codes.OK:
		case codes.NotFound:
			continue
		default:
			log.WithError(err).Errorf("Failed to fetch info about skipped event %d", eventID)
			continue
		}

		a.fetchEntries[event.EntryID] = struct{}{}
		a.eventTracker.StopTracking(eventID)
	}
}

// startupWindowLowerBound returns the exclusive lower bound of the startup gap
// window below watermark, or zero when bounded seeding is disabled.
func (a *registrationEntries) startupWindowLowerBound(watermark uint) uint {
	if a.startupGapWindow == 0 || watermark <= a.startupGapWindow {
		return 0
	}
	return watermark - a.startupGapWindow
}

// seedEvents establishes the event state the cache build starts from. With
// bounded seeding it costs two indexed reads; without it, it scans the entire
// retained event history and marks every entry it finds for re-fetch, which is
// the behavior that predates the gap window.
func (a *registrationEntries) seedEvents(ctx context.Context) error {
	if a.startupGapWindow == 0 {
		return a.captureChangedEntries(ctx)
	}
	return a.seedWatermark(ctx)
}

// seedWatermark establishes the initial event watermark without listing the
// entire events table and without marking every entry for re-fetch.
//
// It must run before the cache load reads its snapshot. The event row and the
// entity row are written in the same transaction, so an event that is visible
// here has data that is also visible to the load. That leaves three cases:
// events committed before this read are in the snapshot; events committed
// after it get an ID above the watermark and are replayed by the first
// incremental update; and IDs that were allocated before this read but commit
// after the snapshot are absent from the window and are tracked for replay.
func (a *registrationEntries) seedWatermark(ctx context.Context) error {
	latest, err := a.ds.FetchLatestRegistrationEntryEventID(ctx)
	if err != nil {
		return fmt.Errorf("failed to fetch latest registration entry event id: %w", err)
	}
	if latest == 0 {
		// No events have ever been recorded. Leaving the watermark at zero
		// lets the first real event be picked up by the normal scan.
		return nil
	}

	lowerBound := a.startupWindowLowerBound(latest)
	resp, err := a.ds.ListRegistrationEntryEvents(ctx, &datastore.ListRegistrationEntryEventsRequest{
		GreaterThanEventID: lowerBound,
		LessThanEventID:    latest + 1,
	})
	if err != nil {
		return fmt.Errorf("failed to list registration entry events in the startup gap window: %w", err)
	}

	present := make(map[uint]struct{}, len(resp.Events))
	oldest := latest
	for _, event := range resp.Events {
		present[event.EventID] = struct{}{}
		oldest = min(oldest, event.EventID)
	}

	// When the window covers the whole ID space, IDs below the oldest event
	// were pruned rather than reserved, and tracking them would only produce
	// futile lookups. A truncated window cannot tell a pruned ID from a
	// reserved one, so it tracks both; the cost of the pruned ones is bounded
	// by the window.
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
	}).Debug("Seeded registration entry event watermark")

	return nil
}

func (a *registrationEntries) scanForNewEvents(ctx context.Context) error {
	resp, err := a.ds.ListRegistrationEntryEvents(ctx, &datastore.ListRegistrationEntryEventsRequest{
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
			a.fetchEntries[event.EntryID] = struct{}{}
			a.firstEventTime = a.clk.Now()
			continue
		}

		// track any skipped event ids, should they appear later.
		for skipped := a.lastEvent + 1; skipped < event.EventID; skipped++ {
			a.eventTracker.StartTracking(skipped)
		}

		// every event adds its entry to the entry fetch list.
		a.fetchEntries[event.EntryID] = struct{}{}
		a.lastEvent = event.EventID
	}
	return nil
}

const (
	// loadCacheMaxWorkers bounds the goroutines converting pages from
	// datastore rows to protos.
	loadCacheMaxWorkers = 4

	// loadCachePrefetchPages is how many extra pages may be in flight beyond
	// the ones being converted. It bounds peak memory to a handful of pages
	// while still letting the next database round trip overlap the conversion
	// of the current page.
	loadCachePrefetchPages = 2
)

type rawEntryPage struct {
	index   int
	entries []*common.RegistrationEntry
}

type convertedEntryPage struct {
	index   int
	entries []*types.Entry
}

// loadCache walks every registration entry and writes it into sink.
//
// The pagination cursor is walked by a single goroutine, so pages are still
// requested strictly in order and the snapshot the datastore returns is
// unchanged. Only the conversion from datastore rows to protos runs in
// parallel; converted pages are reordered before being applied, so the sink
// sees exactly the sequence a serial load would produce.
func (a *registrationEntries) loadCache(ctx context.Context, sink authorizedentries.CacheSink) error {
	a.loadedEntries = 0
	a.loadedPages = 0

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	workers := min(runtime.GOMAXPROCS(0), loadCacheMaxWorkers)
	inFlight := workers + loadCachePrefetchPages

	rawPages := make(chan rawEntryPage, inFlight)
	convertedPages := make(chan convertedEntryPage, inFlight)
	convertErrs := make(chan error, workers)

	var fetchErr error
	go func() {
		defer close(rawPages)
		fetchErr = a.listEntryPages(ctx, rawPages)
	}()

	var wg sync.WaitGroup
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// One interner per worker: the strings it shares are the ones that
			// repeat across the whole load, and a per-worker map keeps the
			// conversion lock-free at the cost of one copy per worker.
			interner := api.NewStringInterner()
			for page := range rawPages {
				entries, err := api.RegistrationEntriesToProtoInterned(page.entries, interner)
				if err != nil {
					convertErrs <- fmt.Errorf("failed to convert registration entries: %w", err)
					cancel()
					return
				}
				select {
				case convertedPages <- convertedEntryPage{index: page.index, entries: entries}:
				case <-ctx.Done():
					return
				}
			}
		}()
	}
	go func() {
		wg.Wait()
		close(convertedPages)
	}()

	// Apply pages in cursor order, holding out-of-order pages until their turn.
	// The reorder buffer is bounded by the number of pages in flight.
	pending := make(map[int][]*types.Entry, inFlight)
	next := 0
	for page := range convertedPages {
		pending[page.index] = page.entries
		for {
			entries, ok := pending[next]
			if !ok {
				break
			}
			delete(pending, next)
			next++

			for _, entry := range entries {
				sink.UpdateEntry(entry)
			}
			a.loadedEntries += len(entries)
			a.loadedPages++
		}
	}

	select {
	case err := <-convertErrs:
		return err
	default:
	}
	return fetchErr
}

// listEntryPages walks the pagination cursor, emitting one page per database
// round trip until the datastore reports the end of the walk.
func (a *registrationEntries) listEntryPages(ctx context.Context, pages chan<- rawEntryPage) error {
	var token string
	for index := 0; ; index++ {
		resp, err := a.ds.ListRegistrationEntries(ctx, &datastore.ListRegistrationEntriesRequest{
			DataConsistency: datastore.RequireCurrent, // preliminary loading should not be done via read-replicas
			Pagination: &datastore.Pagination{
				Token:    token,
				PageSize: a.pageSize,
			},
		})
		if err != nil {
			return fmt.Errorf("failed to list registration entries: %w", err)
		}

		token = resp.Pagination.Token
		if token == "" {
			return nil
		}

		select {
		case pages <- rawEntryPage{index: index, entries: resp.Entries}:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

// buildRegistrationEntriesCache fetches all registration entries and writes
// them into sink. The caller is responsible for assigning the finished cache
// once the sink has produced it.
func buildRegistrationEntriesCache(ctx context.Context, log logrus.FieldLogger, metrics telemetry.Metrics, ds datastore.DataStore, clk clock.Clock, sink authorizedentries.CacheSink, pageSize int32, cacheReloadInterval, eventTimeout time.Duration, startupGapWindow uint) (*registrationEntries, error) {
	pollPeriods := PollPeriods(cacheReloadInterval, eventTimeout)

	registrationEntries := &registrationEntries{
		clk:              clk,
		ds:               ds,
		log:              log,
		metrics:          metrics,
		eventTimeout:     eventTimeout,
		pageSize:         pageSize,
		startupGapWindow: startupGapWindow,

		eventsBeforeFirst: make(map[uint]struct{}),
		fetchEntries:      make(map[string]struct{}),

		eventTracker: NewEventTracker(pollPeriods),

		skippedEntryEvents: -1,
		lastCacheStats: authorizedentries.CacheStats{
			AliasesByEntryID:  -1,
			AliasesBySelector: -1,
			EntriesByEntryID:  -1,
		},
	}

	eventsStart := time.Now()
	if err := registrationEntries.seedEvents(ctx); err != nil {
		return nil, err
	}
	registrationEntries.eventsDuration = time.Since(eventsStart)
	server_telemetry.MeasureEntryCacheBuildPhase(metrics, server_telemetry.EntryCacheBuildPhaseEntryEvents, eventsStart)

	loadStart := time.Now()
	if err := registrationEntries.loadCache(ctx, sink); err != nil {
		return nil, err
	}
	registrationEntries.loadDuration = time.Since(loadStart)
	server_telemetry.MeasureEntryCacheBuildPhase(metrics, server_telemetry.EntryCacheBuildPhaseEntryLoad, loadStart)

	registrationEntries.emitMetrics(sink.Stats())

	return registrationEntries, nil
}

// updateCache Fetches all the events since the last time this function was running and updates
// the cache with all the changes.
func (a *registrationEntries) updateCache(ctx context.Context) error {
	if err := a.captureChangedEntries(ctx); err != nil {
		return err
	}
	if err := a.updateCachedEntries(ctx); err != nil {
		return err
	}
	a.emitMetrics(a.cache.Stats())

	return nil
}

// updateCacheEntry update/deletes/creates an individual registration entry in the cache.
func (a *registrationEntries) updateCachedEntries(ctx context.Context) error {
	entryIds := slices.Collect(maps.Keys(a.fetchEntries))
	for pageStart := 0; pageStart < len(entryIds); pageStart += int(a.pageSize) {
		fetchEntries := a.fetchEntriesPage(entryIds, pageStart)
		commonEntries, err := a.ds.FetchRegistrationEntries(ctx, fetchEntries)
		if err != nil {
			return err
		}

		for _, entryId := range fetchEntries {
			commonEntry, ok := commonEntries[entryId]
			if !ok {
				a.cache.RemoveEntry(entryId)
				delete(a.fetchEntries, entryId)
				continue
			}

			entry, err := api.RegistrationEntryToProto(commonEntry)
			if err != nil {
				a.cache.RemoveEntry(entryId)
				delete(a.fetchEntries, entryId)
				a.log.WithField(telemetry.RegistrationID, entryId).Warn("Removed malformed registration entry from cache")
				continue
			}

			a.cache.UpdateEntry(entry)
			delete(a.fetchEntries, entryId)
		}
	}

	return nil
}

// fetchEntriesPage gets the range for the page starting at pageStart
func (a *registrationEntries) fetchEntriesPage(entryIds []string, pageStart int) []string {
	pageEnd := min(len(entryIds), pageStart+int(a.pageSize))
	return entryIds[pageStart:pageEnd]
}

func (a *registrationEntries) swapCache(cache *authorizedentries.Cache) {
	a.cache = cache
	a.fetchEntries = make(map[string]struct{})
}

// emitMetrics reports the gauges for cacheStats, which during a build belong
// to the cache being built rather than the published one.
func (a *registrationEntries) emitMetrics(cacheStats authorizedentries.CacheStats) {
	if a.skippedEntryEvents != a.eventTracker.EventCount() {
		a.skippedEntryEvents = a.eventTracker.EventCount()
		server_telemetry.SetSkippedEntryEventIDsCacheCountGauge(a.metrics, a.skippedEntryEvents)
	}

	if a.lastCacheStats.AliasesByEntryID != cacheStats.AliasesByEntryID {
		a.lastCacheStats.AliasesByEntryID = cacheStats.AliasesByEntryID
		server_telemetry.SetNodeAliasesByEntryIDCacheCountGauge(a.metrics, a.lastCacheStats.AliasesByEntryID)
	}
	if a.lastCacheStats.AliasesBySelector != cacheStats.AliasesBySelector {
		a.lastCacheStats.AliasesBySelector = cacheStats.AliasesBySelector
		server_telemetry.SetNodeAliasesBySelectorCacheCountGauge(a.metrics, a.lastCacheStats.AliasesBySelector)
	}
	if a.lastCacheStats.EntriesByEntryID != cacheStats.EntriesByEntryID {
		a.lastCacheStats.EntriesByEntryID = cacheStats.EntriesByEntryID
		server_telemetry.SetEntriesByEntryIDCacheCountGauge(a.metrics, a.lastCacheStats.EntriesByEntryID)
	}
}
