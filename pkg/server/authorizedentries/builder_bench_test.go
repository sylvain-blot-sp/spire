package authorizedentries

import (
	"fmt"
	"testing"
	"time"

	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"github.com/spiffe/spire/pkg/common/idutil"
	"github.com/spiffe/spire/test/clock"
)

// builderBenchScales are the entry populations the cold load is measured at.
// The larger scales need several GB of heap; run them individually, e.g.
//
//	go test ./pkg/server/authorizedentries -run '^$' -bench 'CacheBuilder/1000000' -benchtime 1x -benchmem
var builderBenchScales = []int{100_000, 1_000_000, 5_000_000}

// BenchmarkCacheUpdateEntryLoop is the incremental baseline: one locked
// remove-then-insert per entry, in the order a paginated load produces.
func BenchmarkCacheUpdateEntryLoop(b *testing.B) {
	forEachBuilderBenchScale(b, func(b *testing.B, entries []*types.Entry, agents []benchAgent) {
		for b.Loop() {
			cache := NewCache(clock.NewMock(b), "domain.test")
			for _, entry := range entries {
				cache.UpdateEntry(entry)
			}
			for _, agent := range agents {
				cache.UpdateAgent(agent.id, agent.expiresAt, agent.selectors)
			}
		}
	})
}

// BenchmarkCacheBuilder is the bulk path over identical input. It is measured
// both with a size hint, which is what a reload gets from the cache it is
// replacing, and without one, which is what the very first build gets.
func BenchmarkCacheBuilder(b *testing.B) {
	forEachBuilderBenchScale(b, func(b *testing.B, entries []*types.Entry, agents []benchAgent) {
		run := func(b *testing.B, hint CacheSizeHint) {
			b.ReportAllocs()
			for b.Loop() {
				builder := NewCacheBuilder(clock.NewMock(b), "domain.test", hint)
				for _, entry := range entries {
					builder.UpdateEntry(entry)
				}
				for _, agent := range agents {
					builder.UpdateAgent(agent.id, agent.expiresAt, agent.selectors)
				}
				builder.Build()
			}
		}
		b.Run("hint", func(b *testing.B) {
			run(b, CacheSizeHint{Entries: len(entries), Agents: len(agents)})
		})
		b.Run("nohint", func(b *testing.B) {
			run(b, CacheSizeHint{})
		})
	})
}

type benchAgent struct {
	id        string
	expiresAt time.Time
	selectors []*types.Selector
}

func forEachBuilderBenchScale(b *testing.B, fn func(*testing.B, []*types.Entry, []benchAgent)) {
	for _, numEntries := range builderBenchScales {
		b.Run(fmt.Sprintf("%d", numEntries), func(b *testing.B) {
			entries, agents := buildBenchPopulation(numEntries)
			b.ReportAllocs()
			b.ResetTimer()
			fn(b, entries, agents)
		})
	}
}

// buildBenchPopulation mirrors the shape of a large installation: workloads
// fanned out through node aliases, with one agent per hundred workloads.
func buildBenchPopulation(numEntries int) ([]*types.Entry, []benchAgent) {
	numAliases := max(numEntries/1000, 1)
	numAgents := max(numEntries/100, 1)

	entries := make([]*types.Entry, 0, numEntries)
	for i := range numAliases {
		entries = append(entries, &types.Entry{
			Id:        fmt.Sprintf("alias-%d", i),
			ParentId:  &types.SPIFFEID{TrustDomain: "domain.test", Path: idutil.ServerIDPath},
			SpiffeId:  &types.SPIFFEID{TrustDomain: "domain.test", Path: fmt.Sprintf("/alias-%d", i)},
			Selectors: []*types.Selector{{Type: "alias", Value: fmt.Sprintf("%d", i)}},
		})
	}
	for i := numAliases; i < numEntries; i++ {
		entries = append(entries, &types.Entry{
			Id:       fmt.Sprintf("entry-%d", i),
			ParentId: &types.SPIFFEID{TrustDomain: "domain.test", Path: fmt.Sprintf("/alias-%d", i%numAliases)},
			SpiffeId: &types.SPIFFEID{TrustDomain: "domain.test", Path: fmt.Sprintf("/workload-%d", i)},
			Selectors: []*types.Selector{
				{Type: "unix", Value: fmt.Sprintf("uid:%d", i)},
				{Type: "unix", Value: fmt.Sprintf("gid:%d", i)},
			},
		})
	}

	expiresAt := now.Add(time.Hour)
	agents := make([]benchAgent, 0, numAgents)
	for i := range numAgents {
		agents = append(agents, benchAgent{
			id:        fmt.Sprintf("spiffe://domain.test/agent-%d", i),
			expiresAt: expiresAt,
			selectors: []*types.Selector{
				{Type: "alias", Value: fmt.Sprintf("%d", i%numAliases)},
				{Type: "node", Value: fmt.Sprintf("attr:%d", i)},
			},
		})
	}
	return entries, agents
}
