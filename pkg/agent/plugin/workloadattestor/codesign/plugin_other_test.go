//go:build !darwin && !windows

package codesign

import (
	"context"
	"testing"

	workloadattestorv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/agent/workloadattestor/v1"
)

func TestOtherOSEmitsNothing(t *testing.T) {
	resp, err := New().Attest(context.Background(), &workloadattestorv1.AttestRequest{Pid: 1})
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.SelectorValues) != 0 {
		t.Fatalf("selectors: %v", resp.SelectorValues)
	}
}
