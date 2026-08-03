// Package fakeentrydatastore provides a synthetic, read-only datastore that
// generates registration entries and attested nodes on demand. It exists so
// that entry cache load benchmarks can run at populations (millions of
// entries) that are impractical with fakedatastore, which is backed by a real
// SQLite database and inserts one row at a time.
//
// Only the read methods exercised by the event-based entry cache are
// implemented. Every other DataStore method panics, which keeps accidental
// use outside of benchmarks loud.
package fakeentrydatastore

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/spiffe/spire/pkg/server/datastore"
	"github.com/spiffe/spire/proto/spire/common"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Config describes the synthetic population.
type Config struct {
	// TrustDomain is the trust domain name, without the "spiffe://" scheme.
	TrustDomain string

	// NumEntries is the total number of registration entries, including
	// aliases.
	NumEntries int

	// NumAliases is how many of the entries are node aliases. Node aliases
	// are always the lowest-numbered entries so that page boundaries are
	// deterministic.
	NumAliases int

	// NumAgents is the number of attested nodes.
	NumAgents int

	// SelectorsPerEntry, DNSNamesPerEntry and FederatesWithPerEntry control
	// the per-entry fan-out that dominates row assembly and proto conversion
	// cost.
	SelectorsPerEntry     int
	DNSNamesPerEntry      int
	FederatesWithPerEntry int

	// SelectorsPerAgent is the number of node selectors on each attested node.
	SelectorsPerAgent int

	// NumEntryEvents and NumNodeEvents are the sizes of the retained event
	// streams. Event IDs are dense and start at 1.
	NumEntryEvents int
	NumNodeEvents  int
}

// DataStore is a synthetic read-only datastore. The zero value is not usable;
// construct one with New.
type DataStore struct {
	// Embedding the interface leaves unimplemented methods as nil, so calling
	// one panics rather than silently returning zero values.
	datastore.DataStore

	cfg Config

	trustDomainPrefix string
	serverID          string
	notAfter          int64
}

// New returns a synthetic datastore for the given population.
func New(cfg Config) *DataStore {
	if cfg.TrustDomain == "" {
		cfg.TrustDomain = "example.org"
	}
	prefix := "spiffe://" + cfg.TrustDomain
	return &DataStore{
		cfg:               cfg,
		trustDomainPrefix: prefix,
		serverID:          prefix + "/spire/server",
		// Far enough in the future that nothing is filtered as expired.
		notAfter: time.Now().Add(365 * 24 * time.Hour).Unix(),
	}
}

// Config returns the population this datastore was built with.
func (s *DataStore) Config() Config {
	return s.cfg
}

func (s *DataStore) CountRegistrationEntries(context.Context, *datastore.CountRegistrationEntriesRequest) (int32, error) {
	return int32(s.cfg.NumEntries), nil
}

func (s *DataStore) CountAttestedNodes(context.Context, *datastore.CountAttestedNodesRequest) (int32, error) {
	return int32(s.cfg.NumAgents), nil
}

// ListRegistrationEntries implements the same cursor pagination contract as
// sqlstore: the token is the index of the last returned entry, and a page with
// no entries carries an empty token to signal the end of the walk.
func (s *DataStore) ListRegistrationEntries(_ context.Context, req *datastore.ListRegistrationEntriesRequest) (*datastore.ListRegistrationEntriesResponse, error) {
	if req.Pagination == nil {
		entries := make([]*common.RegistrationEntry, 0, s.cfg.NumEntries)
		for i := range s.cfg.NumEntries {
			entries = append(entries, s.entry(i))
		}
		return &datastore.ListRegistrationEntriesResponse{Entries: entries}, nil
	}

	if req.Pagination.PageSize == 0 {
		return nil, status.Error(codes.InvalidArgument, "cannot paginate with pagesize = 0")
	}

	start, err := parseToken(req.Pagination.Token)
	if err != nil {
		return nil, err
	}

	end := min(start+int(req.Pagination.PageSize), s.cfg.NumEntries)
	resp := &datastore.ListRegistrationEntriesResponse{
		Pagination: &datastore.Pagination{PageSize: req.Pagination.PageSize},
	}
	if start >= end {
		return resp, nil
	}

	resp.Entries = make([]*common.RegistrationEntry, 0, end-start)
	for i := start; i < end; i++ {
		resp.Entries = append(resp.Entries, s.entry(i))
	}
	resp.Pagination.Token = strconv.Itoa(end)
	return resp, nil
}

func (s *DataStore) FetchRegistrationEntries(_ context.Context, entryIDs []string) (map[string]*common.RegistrationEntry, error) {
	entries := make(map[string]*common.RegistrationEntry, len(entryIDs))
	for _, entryID := range entryIDs {
		i, ok := indexFromID(entryID, "entry-")
		if !ok || i >= s.cfg.NumEntries {
			continue
		}
		entries[entryID] = s.entry(i)
	}
	return entries, nil
}

func (s *DataStore) ListAttestedNodes(_ context.Context, req *datastore.ListAttestedNodesRequest) (*datastore.ListAttestedNodesResponse, error) {
	start := 0
	end := s.cfg.NumAgents
	paginated := req.Pagination != nil
	if paginated {
		if req.Pagination.PageSize == 0 {
			return nil, status.Error(codes.InvalidArgument, "cannot paginate with pagesize = 0")
		}
		var err error
		if start, err = parseToken(req.Pagination.Token); err != nil {
			return nil, err
		}
		end = min(start+int(req.Pagination.PageSize), s.cfg.NumAgents)
	}

	resp := &datastore.ListAttestedNodesResponse{}
	if paginated {
		resp.Pagination = &datastore.Pagination{PageSize: req.Pagination.PageSize}
	}
	if start >= end {
		return resp, nil
	}

	resp.Nodes = make([]*common.AttestedNode, 0, end-start)
	for i := start; i < end; i++ {
		resp.Nodes = append(resp.Nodes, s.node(i, req.FetchSelectors))
	}
	if paginated {
		resp.Pagination.Token = strconv.Itoa(end)
	}
	return resp, nil
}

func (s *DataStore) FetchAttestedNodes(_ context.Context, spiffeIDs []string) (map[string]*common.AttestedNode, error) {
	nodes := make(map[string]*common.AttestedNode, len(spiffeIDs))
	for _, spiffeID := range spiffeIDs {
		i, ok := indexFromID(spiffeID, s.trustDomainPrefix+"/agent-")
		if !ok || i >= s.cfg.NumAgents {
			continue
		}
		nodes[spiffeID] = s.node(i, true)
	}
	return nodes, nil
}

func (s *DataStore) ListRegistrationEntryEvents(_ context.Context, req *datastore.ListRegistrationEntryEventsRequest) (*datastore.ListRegistrationEntryEventsResponse, error) {
	resp := &datastore.ListRegistrationEntryEventsResponse{}
	for _, id := range s.eventIDs(s.cfg.NumEntryEvents, req.GreaterThanEventID, req.LessThanEventID) {
		resp.Events = append(resp.Events, datastore.RegistrationEntryEvent{
			EventID: id,
			// Events churn over a small subset of entries, which is what a
			// busy installation looks like.
			EntryID: entryID(int(id-1) % max(s.cfg.NumEntries, 1)),
		})
	}
	return resp, nil
}

func (s *DataStore) ListAttestedNodeEvents(_ context.Context, req *datastore.ListAttestedNodeEventsRequest) (*datastore.ListAttestedNodeEventsResponse, error) {
	resp := &datastore.ListAttestedNodeEventsResponse{}
	for _, id := range s.eventIDs(s.cfg.NumNodeEvents, req.GreaterThanEventID, req.LessThanEventID) {
		resp.Events = append(resp.Events, datastore.AttestedNodeEvent{
			EventID:  id,
			SpiffeID: s.agentID(int(id-1) % max(s.cfg.NumAgents, 1)),
		})
	}
	return resp, nil
}

func (s *DataStore) FetchRegistrationEntryEvent(_ context.Context, eventID uint) (*datastore.RegistrationEntryEvent, error) {
	if eventID == 0 || eventID > uint(s.cfg.NumEntryEvents) {
		return nil, status.Error(codes.NotFound, "no such event")
	}
	return &datastore.RegistrationEntryEvent{
		EventID: eventID,
		EntryID: entryID(int(eventID-1) % max(s.cfg.NumEntries, 1)),
	}, nil
}

func (s *DataStore) FetchAttestedNodeEvent(_ context.Context, eventID uint) (*datastore.AttestedNodeEvent, error) {
	if eventID == 0 || eventID > uint(s.cfg.NumNodeEvents) {
		return nil, status.Error(codes.NotFound, "no such event")
	}
	return &datastore.AttestedNodeEvent{
		EventID:  eventID,
		SpiffeID: s.agentID(int(eventID-1) % max(s.cfg.NumAgents, 1)),
	}, nil
}

func (s *DataStore) FetchLatestRegistrationEntryEventID(context.Context) (uint, error) {
	return uint(s.cfg.NumEntryEvents), nil
}

func (s *DataStore) FetchLatestAttestedNodeEventID(context.Context) (uint, error) {
	return uint(s.cfg.NumNodeEvents), nil
}

// eventIDs returns the dense event IDs in (greaterThan, lessThan), where a
// zero bound means unbounded.
func (s *DataStore) eventIDs(count int, greaterThan, lessThan uint) []uint {
	first := uint(1)
	if greaterThan >= first {
		first = greaterThan + 1
	}
	last := uint(count)
	if lessThan != 0 && lessThan-1 < last {
		last = lessThan - 1
	}
	if first > last {
		return nil
	}
	ids := make([]uint, 0, last-first+1)
	for id := first; id <= last; id++ {
		ids = append(ids, id)
	}
	return ids
}

// entry builds entry i. Aliases occupy [0, NumAliases) and are parented to the
// server; the remaining entries are workloads spread across the aliases, or
// across the agents when there are no aliases.
func (s *DataStore) entry(i int) *common.RegistrationEntry {
	entry := &common.RegistrationEntry{
		EntryId:        entryID(i),
		RevisionNumber: int64(i),
		X509SvidTtl:    3600,
		JwtSvidTtl:     600,
	}

	switch {
	case i < s.cfg.NumAliases:
		entry.SpiffeId = fmt.Sprintf("%s/alias-%d", s.trustDomainPrefix, i)
		entry.ParentId = s.serverID
		// A node alias matches agents by a single dedicated selector.
		entry.Selectors = []*common.Selector{
			{Type: "alias", Value: strconv.Itoa(i)},
		}
		return entry
	default:
		entry.SpiffeId = fmt.Sprintf("%s/workload-%d", s.trustDomainPrefix, i)
		entry.ParentId = s.parentID(i)
	}

	entry.Selectors = make([]*common.Selector, 0, max(s.cfg.SelectorsPerEntry, 1))
	for j := range max(s.cfg.SelectorsPerEntry, 1) {
		entry.Selectors = append(entry.Selectors, &common.Selector{
			Type:  "unix",
			Value: fmt.Sprintf("uid:%d:%d", i, j),
		})
	}
	for j := range s.cfg.DNSNamesPerEntry {
		entry.DnsNames = append(entry.DnsNames, fmt.Sprintf("workload-%d-%d.example", i, j))
	}
	for j := range s.cfg.FederatesWithPerEntry {
		entry.FederatesWith = append(entry.FederatesWith, fmt.Sprintf("spiffe://federated-%d.org", j))
	}
	return entry
}

func (s *DataStore) parentID(i int) string {
	if s.cfg.NumAliases > 0 {
		return fmt.Sprintf("%s/alias-%d", s.trustDomainPrefix, i%s.cfg.NumAliases)
	}
	return s.agentID(i % max(s.cfg.NumAgents, 1))
}

func (s *DataStore) node(i int, fetchSelectors bool) *common.AttestedNode {
	node := &common.AttestedNode{
		SpiffeId:            s.agentID(i),
		AttestationDataType: "test",
		CertSerialNumber:    strconv.Itoa(i),
		CertNotAfter:        s.notAfter,
	}
	if !fetchSelectors {
		return node
	}

	// Every agent carries the alias selector for one alias plus some noise, so
	// that alias resolution has real work to do.
	node.Selectors = make([]*common.Selector, 0, max(s.cfg.SelectorsPerAgent, 1))
	if s.cfg.NumAliases > 0 {
		node.Selectors = append(node.Selectors, &common.Selector{
			Type:  "alias",
			Value: strconv.Itoa(i % s.cfg.NumAliases),
		})
	}
	for j := len(node.Selectors); j < s.cfg.SelectorsPerAgent; j++ {
		node.Selectors = append(node.Selectors, &common.Selector{
			Type:  "node",
			Value: fmt.Sprintf("attr:%d:%d", i, j),
		})
	}
	return node
}

func (s *DataStore) agentID(i int) string {
	return fmt.Sprintf("%s/agent-%d", s.trustDomainPrefix, i)
}

func entryID(i int) string {
	return "entry-" + strconv.Itoa(i)
}

func indexFromID(id, prefix string) (int, bool) {
	if len(id) <= len(prefix) || id[:len(prefix)] != prefix {
		return 0, false
	}
	i, err := strconv.Atoi(id[len(prefix):])
	if err != nil || i < 0 {
		return 0, false
	}
	return i, true
}

func parseToken(token string) (int, error) {
	if token == "" {
		return 0, nil
	}
	i, err := strconv.Atoi(token)
	if err != nil || i < 0 {
		return 0, status.Errorf(codes.InvalidArgument, "could not parse token %q", token)
	}
	return i, nil
}
