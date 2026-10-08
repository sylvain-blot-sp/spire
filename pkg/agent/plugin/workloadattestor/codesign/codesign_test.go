package codesign

import (
	"context"
	"testing"

	workloadattestorv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/agent/workloadattestor/v1"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
)

func TestConfigureAcceptsEmptyPluginData(t *testing.T) {
	p := New()
	if _, err := p.Configure(context.Background(), &configv1.ConfigureRequest{}); err != nil {
		t.Fatal(err)
	}
	resp, err := p.Validate(context.Background(), &configv1.ValidateRequest{HclConfiguration: "\n"})
	if err != nil {
		t.Fatal(err)
	}
	if !resp.Valid {
		t.Fatalf("notes: %v", resp.Notes)
	}
}

func TestConfigureRejectsBrokenHCL(t *testing.T) {
	p := New()
	_, err := p.Configure(context.Background(), &configv1.ConfigureRequest{
		HclConfiguration: "plugin_data {",
	})
	if err == nil {
		t.Fatal("expected invalid HCL to fail configure")
	}
}

func TestSelectorPairRequiresBoth(t *testing.T) {
	if got := selectorPair("teamid", "ABC", "identifier", ""); got != nil {
		t.Fatalf("partial pair published: %v", got)
	}
	got := selectorPair("teamid", "ABC", "identifier", "com.example.app")
	if len(got) != 2 || got[0] != "teamid:ABC" || got[1] != "identifier:com.example.app" {
		t.Fatalf("selectors: %v", got)
	}
}

func TestAttestNilRequest(t *testing.T) {
	resp, err := New().Attest(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.SelectorValues) != 0 {
		t.Fatalf("selectors: %v", resp.SelectorValues)
	}
}

func TestAttestUnknownPID(t *testing.T) {
	resp, err := New().Attest(context.Background(), &workloadattestorv1.AttestRequest{Pid: -1})
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.SelectorValues) != 0 {
		t.Fatalf("selectors: %v", resp.SelectorValues)
	}
}
