//go:build !darwin && !windows

package codesign

import "time"

type trustCache struct{}

func newTrustCache(func() time.Time) *trustCache {
	return nil
}

func attestPID(_ *Plugin, _ int32) []string {
	return nil
}
