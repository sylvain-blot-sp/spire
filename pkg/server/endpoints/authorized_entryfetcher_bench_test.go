package endpoints

import (
	"context"
	"fmt"
	"runtime"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/spire/pkg/server/authorizedentries"
	"github.com/spiffe/spire/pkg/server/cache/nodecache"
	"github.com/spiffe/spire/pkg/server/datastore"
	"github.com/spiffe/spire/test/clock"
	"github.com/spiffe/spire/test/fakes/fakeentrydatastore"
	"github.com/spiffe/spire/test/fakes/fakemetrics"
)

const benchTrustDomain = "example.org"

// benchScales are the populations the cache load path is measured at. The
// larger scales need several GB of heap; run them individually, for example:
//
//	go test ./pkg/server/endpoints -run '^$' -bench 'BenchmarkLoadCache/1000000' -benchtime 1x -benchmem
var benchScales = []int{100_000, 1_000_000, 5_000_000}

func benchDataStoreConfig(numEntries int) fakeentrydatastore.Config {
	return fakeentrydatastore.Config{
		TrustDomain: benchTrustDomain,
		NumEntries:  numEntries,
		// Roughly one alias per thousand entries, which is representative of
		// installations that fan workloads out through node aliases.
		NumAliases:            max(numEntries/1000, 1),
		NumAgents:             max(numEntries/100, 1),
		SelectorsPerEntry:     2,
		DNSNamesPerEntry:      1,
		FederatesWithPerEntry: 1,
		SelectorsPerAgent:     3,
	}
}

// BenchmarkLoadCache measures the full cold registration entry load: page
// fetch, proto conversion, and cache insertion. It measures both sinks: the
// live cache, which is the pre-existing behavior, and the builder, which is
// what a cold start now uses.
func BenchmarkLoadCache(b *testing.B) {
	for _, numEntries := range benchScales {
		b.Run(fmt.Sprintf("%d", numEntries), func(b *testing.B) {
			ctx := context.Background()
			log, _ := test.NewNullLogger()
			clk := clock.NewMock(b)
			ds := fakeentrydatastore.New(benchDataStoreConfig(numEntries))

			entries := &registrationEntries{
				clk:      clk,
				ds:       ds,
				log:      log,
				metrics:  fakemetrics.New(),
				pageSize: defaultPageSize,
			}

			run := func(b *testing.B, newSink func() authorizedentries.CacheSink) {
				b.ReportAllocs()
				for range b.N {
					if err := entries.loadCache(ctx, newSink()); err != nil {
						b.Fatal(err)
					}
					b.StopTimer()
					reportPeakHeap(b)
					b.StartTimer()
				}
			}

			b.Run("cache", func(b *testing.B) {
				run(b, func() authorizedentries.CacheSink {
					return authorizedentries.NewCache(clk, benchTrustDomain)
				})
			})
			b.Run("builder", func(b *testing.B) {
				run(b, func() authorizedentries.CacheSink {
					return authorizedentries.NewCacheBuilder(clk, benchTrustDomain, authorizedentries.CacheSizeHint{})
				})
			})
		})
	}
}

// BenchmarkLoadNodeCache measures the cold attested node load.
func BenchmarkLoadNodeCache(b *testing.B) {
	for _, numEntries := range benchScales {
		cfg := benchDataStoreConfig(numEntries)
		b.Run(fmt.Sprintf("%d", cfg.NumAgents), func(b *testing.B) {
			ctx := context.Background()
			log, _ := test.NewNullLogger()
			clk := clock.NewMock(b)
			ds := fakeentrydatastore.New(cfg)

			nodes := &attestedNodes{
				cache:     authorizedentries.NewCache(clk, benchTrustDomain),
				nodeCache: benchNodeCache(b, ds, clk, log),
				clk:       clk,
				ds:        ds,
				log:       log,
				metrics:   fakemetrics.New(),
				pageSize:  defaultPageSize,
			}

			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				cache := authorizedentries.NewCache(clk, benchTrustDomain)
				if err := nodes.loadCache(ctx, cache); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// benchNodeCache builds a node cache with automatic refresh disabled so that
// the benchmark measures only the entry fetcher's own load.
func benchNodeCache(b *testing.B, ds datastore.DataStore, clk clock.Clock, log logrus.FieldLogger) *nodecache.Cache {
	nodeCache, err := nodecache.New(context.Background(), log, ds, clk, false, true)
	if err != nil {
		b.Fatal(err)
	}
	return nodeCache
}

// reportPeakHeap records the live heap after the load, which is the figure
// that matters for sizing a server that must hold the whole cache.
func reportPeakHeap(b *testing.B) {
	var stats runtime.MemStats
	runtime.ReadMemStats(&stats)
	b.ReportMetric(float64(stats.HeapInuse)/(1<<20), "heapMB")
}
