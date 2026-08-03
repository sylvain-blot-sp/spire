package authorizedentries

import (
	"fmt"
	"maps"
	"math/rand"
	"slices"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"github.com/spiffe/spire/pkg/common/idutil"
	"github.com/spiffe/spire/pkg/server/api"
	"github.com/spiffe/spire/test/clock"
	"github.com/stretchr/testify/require"
)

// TestCacheBuilderEquivalence asserts that a cache produced by CacheBuilder is
// indistinguishable from one produced by feeding the same writes through
// Cache.UpdateEntry and Cache.UpdateAgent, across a corpus that covers every
// classification the cache makes.
func TestCacheBuilderEquivalence(t *testing.T) {
	for _, tt := range []struct {
		name string
		corp *corpus
	}{
		{
			name: "empty",
			corp: newCorpus(),
		},
		{
			name: "workloads only",
			corp: newCorpus().withWorkloads(agent1, 5),
		},
		{
			name: "aliases only",
			corp: newCorpus().withAlias("alias-a", 1).withAlias("alias-b", 3),
		},
		{
			name: "alias with no selectors",
			corp: newCorpus().withAlias("alias-empty", 0),
		},
		{
			name: "agents and aliases and workloads",
			corp: newCorpus().
				withAlias("alias-a", 2).
				withAlias("alias-b", 1).
				withWorkloads(alias1, 4).
				withWorkloads(agent1, 3).
				withAgents(6, 2),
		},
		{
			name: "duplicate entry ids resolve last write wins",
			corp: newCorpus().
				withEntry(&types.Entry{
					Id:        "dup",
					ParentId:  api.ProtoFromID(agent1),
					SpiffeId:  api.ProtoFromID(delegatee),
					Selectors: []*types.Selector{sel1},
				}).
				withEntry(&types.Entry{
					Id:        "dup",
					ParentId:  api.ProtoFromID(agent2),
					SpiffeId:  api.ProtoFromID(delegatee),
					Selectors: []*types.Selector{sel2},
				}),
		},
		{
			name: "workload reclassified as alias",
			corp: newCorpus().
				withEntry(&types.Entry{
					Id:        "flip",
					ParentId:  api.ProtoFromID(agent1),
					SpiffeId:  api.ProtoFromID(alias1),
					Selectors: []*types.Selector{sel1},
				}).
				withEntry(&types.Entry{
					Id:        "flip",
					ParentId:  api.ProtoFromID(server),
					SpiffeId:  api.ProtoFromID(alias1),
					Selectors: []*types.Selector{sel1, sel2},
				}),
		},
		{
			name: "alias reclassified as workload",
			corp: newCorpus().
				withEntry(&types.Entry{
					Id:        "flip",
					ParentId:  api.ProtoFromID(server),
					SpiffeId:  api.ProtoFromID(alias1),
					Selectors: []*types.Selector{sel1, sel2, sel3},
				}).
				withEntry(&types.Entry{
					Id:        "flip",
					ParentId:  api.ProtoFromID(agent1),
					SpiffeId:  api.ProtoFromID(alias1),
					Selectors: []*types.Selector{sel1},
				}),
		},
		{
			name: "foreign trust domain entries are dropped",
			corp: newCorpus().
				withWorkloads(agent1, 2).
				withEntry(&types.Entry{
					Id:        "foreign-parent",
					ParentId:  &types.SPIFFEID{TrustDomain: "other.test", Path: "/agent"},
					SpiffeId:  api.ProtoFromID(delegatee),
					Selectors: []*types.Selector{sel1},
				}).
				withEntry(&types.Entry{
					Id:        "foreign-spiffeid",
					ParentId:  api.ProtoFromID(agent1),
					SpiffeId:  &types.SPIFFEID{TrustDomain: "other.test", Path: "/workload"},
					Selectors: []*types.Selector{sel1},
				}).
				withEntry(&types.Entry{
					Id:        "foreign-alias",
					ParentId:  &types.SPIFFEID{TrustDomain: "other.test", Path: idutil.ServerIDPath},
					SpiffeId:  api.ProtoFromID(alias2),
					Selectors: []*types.Selector{sel1},
				}),
		},
		{
			name: "expired agents",
			corp: newCorpus().
				withAlias("alias-a", 1).
				withWorkloads(alias1, 2).
				withExpiredAgents(3, 1),
		},
		{
			name: "shared alias selectors across aliases",
			corp: newCorpus().
				withAlias("alias-a", 2).
				withAlias("alias-b", 2).
				withAlias("alias-c", 2).
				withAgents(4, 2),
		},
		{
			name: "deep delegation chain",
			corp: newCorpus().withDelegationChain(agent1, 6),
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			assertBuilderEquivalent(t, tt.corp)
		})
	}
}

// TestCacheBuilderEquivalenceRandomized exercises the same equivalence over
// randomly generated corpora, including randomized write ordering, which is
// what a paginated load produces.
func TestCacheBuilderEquivalenceRandomized(t *testing.T) {
	for seed := range 25 {
		t.Run(fmt.Sprintf("seed-%d", seed), func(t *testing.T) {
			assertBuilderEquivalent(t, randomCorpus(rand.New(rand.NewSource(int64(seed)))))
		})
	}
}

func assertBuilderEquivalent(t *testing.T, corp *corpus) {
	t.Helper()

	incremental := NewCache(clock.NewMock(t), "domain.test")
	corp.fill(incremental)

	builder := NewCacheBuilder(clock.NewMock(t), "domain.test", CacheSizeHint{
		Entries: len(corp.entries),
		Agents:  len(corp.agents),
	})
	corp.fill(builder)
	built := builder.Build()

	require.Equal(t, incremental.Stats(), built.Stats(), "index sizes differ")

	// Every agent, including agents that were never attested, must see the
	// same authorized entries in the same set.
	for _, agentID := range corp.allAgentIDs() {
		wantEntries := entryIDs(incremental.GetAuthorizedEntries(agentID))
		gotEntries := entryIDs(built.GetAuthorizedEntries(agentID))
		require.Equal(t, wantEntries, gotEntries, "authorized entries differ for %s", agentID)

		// And the same must hold for the targeted lookup path, which walks the
		// same indexes with an early exit.
		requested := make(map[string]struct{}, len(wantEntries))
		for _, id := range wantEntries {
			requested[id] = struct{}{}
		}
		wantLookup := slices.Sorted(maps.Keys(incremental.LookupAuthorizedEntries(agentID, requested)))
		gotLookup := slices.Sorted(maps.Keys(built.LookupAuthorizedEntries(agentID, requested)))
		require.Equal(t, wantLookup, gotLookup, "looked up entries differ for %s", agentID)
	}

	// Pruning walks the expiry-ordered B-tree, so it also validates ordering.
	require.Equal(t, incremental.PruneExpiredAgents(), built.PruneExpiredAgents(), "pruned agent counts differ")
	require.Equal(t, incremental.Stats(), built.Stats(), "index sizes differ after pruning")
}

func entryIDs(entries []api.ReadOnlyEntry) []string {
	ids := make([]string, 0, len(entries))
	for _, entry := range entries {
		ids = append(ids, entry.GetId())
	}
	slices.Sort(ids)
	return ids
}

// corpus is an ordered log of cache writes, so that write order is part of
// what the equivalence test covers.
type corpus struct {
	entries []*types.Entry
	agents  []corpusAgent
	aliases []spiffeid.ID
}

type corpusAgent struct {
	id        spiffeid.ID
	expiresAt time.Time
	selectors []*types.Selector
}

func newCorpus() *corpus {
	return &corpus{}
}

func (c *corpus) fill(sink CacheSink) {
	for _, entry := range c.entries {
		sink.UpdateEntry(entry)
	}
	for _, agent := range c.agents {
		sink.UpdateAgent(agent.id.String(), agent.expiresAt, agent.selectors)
	}
}

func (c *corpus) withEntry(entry *types.Entry) *corpus {
	c.entries = append(c.entries, entry)
	return c
}

func (c *corpus) withAlias(name string, numSelectors int) *corpus {
	aliasID := spiffeid.RequireFromPathf(td, "/%s", name)
	selectors := make([]*types.Selector, 0, numSelectors)
	for i := range numSelectors {
		selectors = append(selectors, &types.Selector{Type: "alias", Value: fmt.Sprintf("%s-%d", name, i)})
	}
	c.aliases = append(c.aliases, aliasID)
	return c.withEntry(&types.Entry{
		Id:        "alias-entry-" + name,
		ParentId:  api.ProtoFromID(server),
		SpiffeId:  api.ProtoFromID(aliasID),
		Selectors: selectors,
	})
}

func (c *corpus) withWorkloads(parent spiffeid.ID, count int) *corpus {
	for i := range count {
		c.withEntry(&types.Entry{
			Id:        fmt.Sprintf("workload-%s-%d", parent.Path(), i),
			ParentId:  api.ProtoFromID(parent),
			SpiffeId:  spiffeIDProto(fmt.Sprintf("/workload-%d", i)),
			Selectors: []*types.Selector{sel1},
		})
	}
	return c
}

// withDelegationChain builds a chain where each entry parents the next, which
// is what exercises the recursive descendant crawl.
func (c *corpus) withDelegationChain(root spiffeid.ID, depth int) *corpus {
	parent := root
	for i := range depth {
		child := spiffeid.RequireFromPathf(td, "/delegatee-%d", i)
		c.withEntry(&types.Entry{
			Id:        fmt.Sprintf("delegatee-%d", i),
			ParentId:  api.ProtoFromID(parent),
			SpiffeId:  api.ProtoFromID(child),
			Selectors: []*types.Selector{sel1},
		})
		parent = child
	}
	return c
}

func (c *corpus) withAgents(count, selectorsPerAgent int) *corpus {
	for i := range count {
		agentID := spiffeid.RequireFromPathf(td, "/spire/agent/gen/%d", i)
		// Give the agent the selectors of one alias so that alias resolution
		// actually matches, plus some noise that matches nothing.
		selectors := make([]*types.Selector, 0, selectorsPerAgent)
		if len(c.aliases) > 0 {
			name := c.aliases[i%len(c.aliases)].Path()[1:]
			for j := range selectorsPerAgent {
				selectors = append(selectors, &types.Selector{Type: "alias", Value: fmt.Sprintf("%s-%d", name, j)})
			}
		}
		selectors = append(selectors, &types.Selector{Type: "noise", Value: fmt.Sprintf("%d", i)})

		c.agents = append(c.agents, corpusAgent{
			id:        agentID,
			expiresAt: now.Add(time.Hour * time.Duration(i+1)),
			selectors: selectors,
		})
	}
	return c
}

func (c *corpus) withExpiredAgents(count, selectorsPerAgent int) *corpus {
	for i := range count {
		agentID := spiffeid.RequireFromPathf(td, "/spire/agent/expired/%d", i)
		selectors := make([]*types.Selector, 0, selectorsPerAgent)
		for j := range selectorsPerAgent {
			selectors = append(selectors, &types.Selector{Type: "alias", Value: fmt.Sprintf("alias-a-%d", j)})
		}
		c.agents = append(c.agents, corpusAgent{
			id:        agentID,
			expiresAt: now.Add(-time.Hour * time.Duration(i+1)),
			selectors: selectors,
		})
	}
	return c
}

func (c *corpus) allAgentIDs() []spiffeid.ID {
	ids := []spiffeid.ID{agent1, agent2, agent3, agent4}
	for _, agent := range c.agents {
		ids = append(ids, agent.id)
	}
	return ids
}

func randomCorpus(rng *rand.Rand) *corpus {
	c := newCorpus()

	numAliases := rng.Intn(5)
	for i := range numAliases {
		c.withAlias(fmt.Sprintf("r%d", i), rng.Intn(4))
	}

	parents := []spiffeid.ID{agent1, agent2, agent3, agent4}
	parents = append(parents, c.aliases...)

	numEntries := rng.Intn(40)
	for i := range numEntries {
		parent := parents[rng.Intn(len(parents))]
		// Occasionally reuse an entry ID so that last-write-wins is covered.
		id := fmt.Sprintf("r-entry-%d", i)
		if i > 0 && rng.Intn(4) == 0 {
			id = fmt.Sprintf("r-entry-%d", rng.Intn(i))
		}
		if rng.Intn(8) == 0 {
			// A late alias for an ID that may already be a workload entry.
			c.withEntry(&types.Entry{
				Id:        id,
				ParentId:  api.ProtoFromID(server),
				SpiffeId:  spiffeIDProto(fmt.Sprintf("/r-alias-%d", i)),
				Selectors: []*types.Selector{{Type: "alias", Value: fmt.Sprintf("r%d-0", rng.Intn(max(numAliases, 1)))}},
			})
			continue
		}
		c.withEntry(&types.Entry{
			Id:        id,
			ParentId:  api.ProtoFromID(parent),
			SpiffeId:  spiffeIDProto(fmt.Sprintf("/r-workload-%d", rng.Intn(numEntries+1))),
			Selectors: []*types.Selector{sel1},
		})
	}

	c.withAgents(rng.Intn(6), 1+rng.Intn(3))
	c.withExpiredAgents(rng.Intn(3), 1)
	return c
}

func spiffeIDProto(path string) *types.SPIFFEID {
	return &types.SPIFFEID{TrustDomain: "domain.test", Path: path}
}
