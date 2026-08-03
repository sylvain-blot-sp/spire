package api_test

import (
	"fmt"
	"testing"
	"unsafe"

	"github.com/spiffe/spire/pkg/server/api"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/stretchr/testify/require"
)

// benchRegistrationEntries builds a page-sized corpus shaped like a large
// deployment: many entries per parent, and selector types drawn from a small
// vocabulary.
func benchRegistrationEntries(count, entriesPerParent int) []*common.RegistrationEntry {
	selectorTypes := []string{"k8s", "unix", "docker"}

	entries := make([]*common.RegistrationEntry, 0, count)
	for i := range count {
		entries = append(entries, &common.RegistrationEntry{
			EntryId:  fmt.Sprintf("entry-%d", i),
			ParentId: fmt.Sprintf("spiffe://example.org/spire/agent/node/%d", i/entriesPerParent),
			SpiffeId: fmt.Sprintf("spiffe://example.org/workload/%d", i),
			Selectors: []*common.Selector{
				{Type: selectorTypes[i%len(selectorTypes)], Value: fmt.Sprintf("ns:ns-%d", i%100)},
				{Type: selectorTypes[(i+1)%len(selectorTypes)], Value: fmt.Sprintf("sa:sa-%d", i%100)},
			},
			FederatesWith:  []string{"spiffe://federated.org"},
			DnsNames:       []string{fmt.Sprintf("workload-%d.example.org", i)},
			X509SvidTtl:    3600,
			RevisionNumber: 1,
		})
	}
	return entries
}

func BenchmarkRegistrationEntriesToProto(b *testing.B) {
	const pageSize = 10000

	for _, entriesPerParent := range []int{1, 100} {
		entries := benchRegistrationEntries(pageSize, entriesPerParent)

		b.Run(fmt.Sprintf("entries_per_parent=%d", entriesPerParent), func(b *testing.B) {
			b.Run("plain", func(b *testing.B) {
				b.ReportAllocs()
				for b.Loop() {
					if _, err := api.RegistrationEntriesToProto(entries); err != nil {
						b.Fatal(err)
					}
				}
			})

			b.Run("interned", func(b *testing.B) {
				b.ReportAllocs()
				for b.Loop() {
					// One interner per page, as the cache loader uses it.
					if _, err := api.RegistrationEntriesToProtoInterned(entries, api.NewStringInterner()); err != nil {
						b.Fatal(err)
					}
				}
			})
		})
	}
}

func TestRegistrationEntriesToProtoInternedMatchesPlain(t *testing.T) {
	entries := benchRegistrationEntries(100, 10)

	plain, err := api.RegistrationEntriesToProto(entries)
	require.NoError(t, err)

	interner := api.NewStringInterner()
	interned, err := api.RegistrationEntriesToProtoInterned(entries, interner)
	require.NoError(t, err)

	spiretest.AssertProtoListEqual(t, plain, interned)

	// The repeated strings really are shared, not merely equal.
	require.Same(t, unsafe.StringData(interned[0].ParentId.Path), unsafe.StringData(interned[1].ParentId.Path))
	require.Same(t, unsafe.StringData(interned[0].SpiffeId.TrustDomain), unsafe.StringData(interned[1].SpiffeId.TrustDomain))
}
