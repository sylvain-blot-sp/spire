package authorizedentries

import (
	"slices"
	"time"

	"github.com/andres-erbsen/clock"
	"github.com/google/btree"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
)

// CacheSink is the write surface used to populate a cache. It is implemented
// by *Cache, which applies each write immediately under its lock, and by
// *CacheBuilder, which accumulates writes for a cache that is not yet visible
// to readers.
type CacheSink interface {
	UpdateEntry(entry *types.Entry)
	UpdateAgent(agentID string, expiresAt time.Time, selectors []*types.Selector)

	// Stats reports the index sizes the sink holds, so that callers can emit
	// cache gauges without caring which sink they were given.
	Stats() CacheStats
}

var (
	_ CacheSink = (*Cache)(nil)
	_ CacheSink = (*CacheBuilder)(nil)
)

// CacheSizeHint lets callers presize the builder when the population is known
// ahead of time. Zero values are fine; they just cost some map growth.
type CacheSizeHint struct {
	Entries int
	Agents  int
}

// CacheBuilder accumulates a complete cache snapshot and materializes its
// indexes once, in Build. Compared to feeding entries through Cache.UpdateEntry
// one at a time, it avoids a lock acquisition, a remove-then-insert cycle, and
// an alias B-tree probe per entry, and it fills the B-trees from sorted input
// instead of interleaving inserts and deletes.
//
// A CacheBuilder is not safe for concurrent use. The cache it produces is not
// reachable by readers until the caller publishes it, so a partially built
// cache can never be served.
type CacheBuilder struct {
	clk         clock.Clock
	trustDomain string

	// Workload entries are indexed exactly as the live cache indexes them, so
	// that Build hands the maps over without a regrouping pass. Aliases are
	// held unexpanded until Build, where the fan-out records can be sorted in
	// one shot instead of being inserted into B-trees one at a time.
	//
	// Repeated writes for the same entry ID resolve last-write-wins, exactly
	// as Cache.UpdateEntry's remove-then-insert does, including when an entry
	// changes between being a workload entry and a node alias.
	entriesByEntryID  map[string]*types.Entry
	entriesByParentID map[string]map[string]*types.Entry
	aliases           map[string]*types.Entry

	agents map[string]agentRecord
}

// NewCacheBuilder returns a builder for a cache in the given trust domain.
func NewCacheBuilder(clk clock.Clock, trustDomain string, hint CacheSizeHint) *CacheBuilder {
	return &CacheBuilder{
		clk:               clk,
		trustDomain:       trustDomain,
		entriesByEntryID:  make(map[string]*types.Entry, hint.Entries),
		entriesByParentID: make(map[string]map[string]*types.Entry),
		aliases:           make(map[string]*types.Entry),
		agents:            make(map[string]agentRecord, hint.Agents),
	}
}

// UpdateEntry records an entry for the cache under construction. It applies
// the same trust domain filter and the same node alias classification as
// Cache.UpdateEntry.
func (b *CacheBuilder) UpdateEntry(entry *types.Entry) {
	if entry.ParentId.TrustDomain != b.trustDomain {
		return
	}
	if entry.SpiffeId.TrustDomain != b.trustDomain {
		return
	}

	previous, seen := b.entriesByEntryID[entry.Id]
	if seen {
		delete(b.entriesByEntryID, entry.Id)
		b.removeFromParent(previous)
	}

	if isNodeAlias(entry) {
		b.aliases[entry.Id] = entry
		return
	}
	if !seen && len(b.aliases) > 0 {
		delete(b.aliases, entry.Id)
	}

	b.entriesByEntryID[entry.Id] = entry
	parentEntries, ok := b.entriesByParentID[entry.ParentId.Path]
	if !ok {
		parentEntries = make(map[string]*types.Entry)
		b.entriesByParentID[entry.ParentId.Path] = parentEntries
	}
	parentEntries[entry.Id] = entry
}

func (b *CacheBuilder) removeFromParent(entry *types.Entry) {
	parentEntries, ok := b.entriesByParentID[entry.ParentId.Path]
	if !ok {
		return
	}
	delete(parentEntries, entry.Id)
	if len(parentEntries) == 0 {
		delete(b.entriesByParentID, entry.ParentId.Path)
	}
}

// UpdateAgent records an agent for the cache under construction.
func (b *CacheBuilder) UpdateAgent(agentID string, expiresAt time.Time, selectors []*types.Selector) {
	b.agents[agentID] = agentRecord{
		ID:        agentID,
		ExpiresAt: expiresAt.Unix(),
		Selectors: selectorSetFromProto(selectors),
	}
}

// Stats reports the index sizes the cache will have once built.
func (b *CacheBuilder) Stats() CacheStats {
	aliasRecords := 0
	for _, entry := range b.aliases {
		aliasRecords += len(selectorSetFromProto(entry.Selectors))
	}
	return CacheStats{
		AgentsByID:        len(b.agents),
		AgentsByExpiresAt: len(b.agents),
		AliasesByEntryID:  aliasRecords,
		AliasesBySelector: aliasRecords,
		EntriesByEntryID:  len(b.entriesByEntryID),
	}
}

// Build materializes the cache. The builder must not be used afterwards.
func (b *CacheBuilder) Build() *Cache {
	cache := &Cache{
		clk:               b.clk,
		trustDomain:       b.trustDomain,
		agentsByID:        b.agents,
		agentsByExpiresAt: btree.NewG(agentRecordDegree, agentRecordByExpiresAt),
		aliasesByEntryID:  btree.NewG(aliasRecordDegree, aliasRecordByEntryID),
		aliasesBySelector: btree.NewG(aliasRecordDegree, aliasRecordBySelector),
		entriesByEntryID:  b.entriesByEntryID,
		entriesByParentID: b.entriesByParentID,
	}

	fillBTree(cache.agentsByExpiresAt, sortedAgentRecords(b.agents))

	aliasRecords := expandAliasRecords(b.aliases)
	fillBTree(cache.aliasesByEntryID, aliasRecords)
	// aliasesBySelector holds the same records under a different ordering, so
	// re-sort in place rather than expanding the aliases a second time.
	slices.SortFunc(aliasRecords, compareFunc(aliasRecordBySelector))
	fillBTree(cache.aliasesBySelector, aliasRecords)

	b.entriesByEntryID = nil
	b.entriesByParentID = nil
	b.aliases = nil
	b.agents = nil

	return cache
}

// expandAliasRecords fans each alias entry out into one record per selector,
// matching the expansion Cache.updateEntry performs.
func expandAliasRecords(aliases map[string]*types.Entry) []aliasRecord {
	total := 0
	for _, entry := range aliases {
		total += len(entry.Selectors)
	}

	records := make([]aliasRecord, 0, total)
	for _, entry := range aliases {
		ar := aliasRecord{
			EntryID:      entry.Id,
			AliasID:      entry.SpiffeId.Path,
			AllSelectors: selectorSetFromProto(entry.Selectors),
		}
		for selector := range ar.AllSelectors {
			ar.Selector = selector
			records = append(records, ar)
		}
	}
	slices.SortFunc(records, compareFunc(aliasRecordByEntryID))
	return records
}

func sortedAgentRecords(agents map[string]agentRecord) []agentRecord {
	records := make([]agentRecord, 0, len(agents))
	for _, agent := range agents {
		records = append(records, agent)
	}
	slices.SortFunc(records, compareFunc(agentRecordByExpiresAt))
	return records
}

// fillBTree inserts pre-sorted records. google/btree has no bulk load, but
// ascending insertion keeps the touched nodes on the right spine of the tree,
// which is far friendlier to the CPU cache than inserting in map order.
func fillBTree[T any](tree *btree.BTreeG[T], records []T) {
	for _, record := range records {
		tree.ReplaceOrInsert(record)
	}
}

func compareFunc[T any](less btree.LessFunc[T]) func(a, b T) int {
	return func(a, b T) int {
		switch {
		case less(a, b):
			return -1
		case less(b, a):
			return 1
		default:
			return 0
		}
	}
}
