package endpoints

import (
	"maps"
	"slices"
	"testing"

	"github.com/spiffe/spire/pkg/server/cache/nodecache"
	"github.com/spiffe/spire/pkg/server/datastore"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/stretchr/testify/require"
)

func TestSeedRegistrationEntryWatermark(t *testing.T) {
	for _, tt := range []struct {
		name  string
		setup *entryScenarioSetup

		expectedFirstEvent uint
		expectedLastEvent  uint
		expectedTracked    []uint
		// expectedFetches are the entries seeding marked for re-fetch. Bounded
		// seeding marks none of the entries the cache load already reads.
		expectedFetches []string
	}{
		{
			name: "no events leaves the watermark unset",
			setup: &entryScenarioSetup{
				pageSize:         1000,
				startupGapWindow: 100,
			},
		},
		{
			name: "contiguous history seeds the watermark without tracking or fetching",
			setup: &entryScenarioSetup{
				pageSize:                1000,
				startupGapWindow:        100,
				registrationEntries:     defaultRegistrationEntries,
				registrationEntryEvents: defaultRegistrationEntryEventsStartingAt60,
			},
			expectedFirstEvent: defaultLastEntryEvent,
			expectedLastEvent:  defaultLastEntryEvent,
		},
		{
			name: "an ID missing inside the window is tracked for replay",
			setup: &entryScenarioSetup{
				pageSize:            1000,
				startupGapWindow:    100,
				registrationEntries: defaultRegistrationEntries,
				registrationEntryEvents: []*datastore.RegistrationEntryEvent{
					{EventID: 60, EntryID: "47c96201-a4b1-4116-97fe-8aa9c2440aad"},
					// 61 and 62 belong to transactions that had not committed
					// when the watermark was read.
					{EventID: 63, EntryID: "1d78521b-cc92-47c1-85a5-28ce47f121f2"},
				},
			},
			expectedFirstEvent: 63,
			expectedLastEvent:  63,
			expectedTracked:    []uint{61, 62},
		},
		{
			name: "a gap the window does not reach back to is skipped",
			setup: &entryScenarioSetup{
				pageSize:            1000,
				startupGapWindow:    2,
				registrationEntries: defaultRegistrationEntries,
				registrationEntryEvents: []*datastore.RegistrationEntryEvent{
					{EventID: 55, EntryID: "47c96201-a4b1-4116-97fe-8aa9c2440aad"},
					{EventID: 61, EntryID: "1d78521b-cc92-47c1-85a5-28ce47f121f2"},
				},
			},
			expectedFirstEvent: defaultLastEntryEvent,
			expectedLastEvent:  defaultLastEntryEvent,
			expectedTracked:    []uint{60},
		},
		{
			name: "a zero window falls back to scanning the whole history",
			setup: &entryScenarioSetup{
				pageSize:                1000,
				registrationEntries:     defaultRegistrationEntries,
				registrationEntryEvents: defaultRegistrationEntryEventsStartingAt60,
			},
			expectedFirstEvent: defaultFirstEntryEvent,
			expectedLastEvent:  defaultLastEntryEvent,
			expectedFetches: []string{
				"47c96201-a4b1-4116-97fe-8aa9c2440aad",
				"1d78521b-cc92-47c1-85a5-28ce47f121f2",
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			scenario := NewEntryScenario(t, tt.setup)

			registrationEntries, err := buildRegistrationEntriesCache(scenario.ctx, scenario.log, scenario.metrics,
				scenario.ds, scenario.clk, scenario.cache, scenario.pageSize, defaultCacheReloadInterval,
				defaultEventTimeout, scenario.startupGapWindow)
			require.NoError(t, err)

			require.Equal(t, tt.expectedFirstEvent, registrationEntries.firstEvent)
			require.Equal(t, tt.expectedLastEvent, registrationEntries.lastEvent)
			require.ElementsMatch(t, tt.expectedTracked, slices.Collect(maps.Keys(registrationEntries.eventTracker.events)))
			require.ElementsMatch(t, tt.expectedFetches, slices.Collect(maps.Keys(registrationEntries.fetchEntries)))

			// Whatever seeding decided, the cache itself holds the full
			// snapshot the load read.
			require.Equal(t, len(tt.setup.registrationEntries), scenario.cache.Stats().EntriesByEntryID)
		})
	}
}

// TestSeedRegistrationEntryWatermarkReplaysInFlightEvent proves the case the gap
// window exists for: an event whose ID was allocated before the watermark was
// read, but that only becomes visible after the cache snapshot, is replayed by
// the first incremental update instead of being lost until the next full
// reload.
func TestSeedRegistrationEntryWatermarkReplaysInFlightEvent(t *testing.T) {
	scenario := NewEntryScenario(t, &entryScenarioSetup{
		pageSize:            1000,
		startupGapWindow:    100,
		registrationEntries: defaultRegistrationEntries,
		registrationEntryEvents: []*datastore.RegistrationEntryEvent{
			{EventID: 60, EntryID: "47c96201-a4b1-4116-97fe-8aa9c2440aad"},
			{EventID: 62, EntryID: "1d78521b-cc92-47c1-85a5-28ce47f121f2"},
		},
	})

	registrationEntries, err := buildRegistrationEntriesCache(scenario.ctx, scenario.log, scenario.metrics,
		scenario.ds, scenario.clk, scenario.cache, scenario.pageSize, defaultCacheReloadInterval,
		defaultEventTimeout, scenario.startupGapWindow)
	require.NoError(t, err)
	registrationEntries.cache = scenario.cache
	require.Equal(t, 2, scenario.cache.Stats().EntriesByEntryID)

	// The transaction holding event ID 61 commits after the cache snapshot.
	inFlight := &common.RegistrationEntry{
		EntryId:   "6837984a-bc44-462b-9ca6-5cd59be35066",
		ParentId:  "spiffe://example.org/test_node_1",
		SpiffeId:  "spiffe://example.org/test_job_1",
		Selectors: []*common.Selector{{Type: "testjob", Value: "1"}},
	}
	_, err = scenario.ds.CreateRegistrationEntry(scenario.ctx, inFlight)
	require.NoError(t, err)
	require.NoError(t, scenario.ds.PruneRegistrationEntryEvents(scenario.ctx, -5*defaultEventTimeout))
	require.NoError(t, scenario.ds.CreateRegistrationEntryEventForTesting(scenario.ctx, &datastore.RegistrationEntryEvent{
		EventID: 61,
		EntryID: inFlight.EntryId,
	}))

	// The tracker replays a tracked ID on a poll period boundary, so run the
	// poll cycle until it comes back around.
	for range PollPeriods(defaultCacheReloadInterval, defaultEventTimeout) {
		require.NoError(t, registrationEntries.updateCache(scenario.ctx))
		if scenario.cache.Stats().EntriesByEntryID == 3 {
			return
		}
	}
	t.Fatal("in-flight registration entry event was never replayed")
}

func TestSeedAttestedNodeWatermark(t *testing.T) {
	for _, tt := range []struct {
		name  string
		setup *nodeScenarioSetup

		expectedFirstEvent uint
		expectedLastEvent  uint
		expectedTracked    []uint
		expectedFetches    []string
	}{
		{
			name: "no events leaves the watermark unset",
			setup: &nodeScenarioSetup{
				startupGapWindow: 100,
			},
		},
		{
			name: "contiguous history seeds the watermark without tracking or fetching",
			setup: &nodeScenarioSetup{
				startupGapWindow:   100,
				attestedNodes:      defaultAttestedNodes,
				attestedNodeEvents: defaultNodeEventsStartingAt60,
			},
			expectedFirstEvent: defaultLastNodeEvent,
			expectedLastEvent:  defaultLastNodeEvent,
		},
		{
			name: "an ID missing inside the window is tracked for replay",
			setup: &nodeScenarioSetup{
				startupGapWindow: 100,
				attestedNodes:    defaultAttestedNodes,
				attestedNodeEvents: []*datastore.AttestedNodeEvent{
					{EventID: 60, SpiffeID: "spiffe://example.org/test_node_2"},
					{EventID: 63, SpiffeID: "spiffe://example.org/test_node_3"},
				},
			},
			expectedFirstEvent: 63,
			expectedLastEvent:  63,
			expectedTracked:    []uint{61, 62},
		},
		{
			name: "a zero window falls back to scanning the whole history",
			setup: &nodeScenarioSetup{
				attestedNodes:      defaultAttestedNodes,
				attestedNodeEvents: defaultNodeEventsStartingAt60,
			},
			expectedFirstEvent: defaultFirstNodeEvent,
			expectedLastEvent:  defaultLastNodeEvent,
			expectedFetches: []string{
				"spiffe://example.org/test_node_2",
				"spiffe://example.org/test_node_3",
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			scenario := NewNodeScenario(t, tt.setup)
			nodeCache, err := nodecache.New(scenario.ctx, scenario.log, scenario.ds, scenario.clk, false, true)
			require.NoError(t, err)

			attestedNodes, err := buildAttestedNodesCache(scenario.ctx, scenario.log, scenario.metrics, scenario.ds,
				scenario.clk, scenario.cache, nodeCache, scenario.pageSize, defaultCacheReloadInterval,
				defaultEventTimeout, scenario.startupGapWindow)
			require.NoError(t, err)

			require.Equal(t, tt.expectedFirstEvent, attestedNodes.firstEvent)
			require.Equal(t, tt.expectedLastEvent, attestedNodes.lastEvent)
			require.ElementsMatch(t, tt.expectedTracked, slices.Collect(maps.Keys(attestedNodes.eventTracker.events)))
			require.ElementsMatch(t, tt.expectedFetches, slices.Collect(maps.Keys(attestedNodes.fetchNodes)))
		})
	}
}
