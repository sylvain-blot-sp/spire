// Package codesign is a SPIRE Agent WorkloadAttestor built into the
// spire-agent binary Sentinel ships. Stock SPIRE does not include it.
//
// Selector values are the value only (teamid:…, not codesign:teamid:…).
// SPIRE prefixes the plugin name when it publishes the selector.
package codesign

import (
	"context"
	"time"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/hcl"
	workloadattestorv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/agent/workloadattestor/v1"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	"github.com/spiffe/spire/pkg/common/catalog"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const pluginName = "codesign"

func BuiltIn() catalog.BuiltIn {
	return builtin(New())
}

func builtin(p *Plugin) catalog.BuiltIn {
	return catalog.MakeBuiltIn(pluginName,
		workloadattestorv1.WorkloadAttestorPluginServer(p),
		configv1.ConfigServiceServer(p),
	)
}

// Plugin has no configuration. Team IDs and publisher DNs are an allowlist
// on the SPIRE server registration entry, not inputs here.
type Plugin struct {
	workloadattestorv1.UnsafeWorkloadAttestorServer
	configv1.UnsafeConfigServer

	log   hclog.Logger
	trust *trustCache
}

func New() *Plugin {
	return newWithClock(time.Now)
}

func newWithClock(now func() time.Time) *Plugin {
	return &Plugin{trust: newTrustCache(now)}
}

func (p *Plugin) SetLogger(log hclog.Logger) {
	p.log = log
}

// Attest returns an empty selector list instead of an error when the process
// cannot be attested. A plugin error suppresses every attestor for that PID,
// including path selectors.
func (p *Plugin) Attest(_ context.Context, req *workloadattestorv1.AttestRequest) (*workloadattestorv1.AttestResponse, error) {
	var pid int32
	if req != nil {
		pid = req.Pid
	}
	return &workloadattestorv1.AttestResponse{
		SelectorValues: attestPID(p, pid),
	}, nil
}

// AttestReference returns Unimplemented. This plugin does not handle
// reference-based workload attestation; the host falls back to PID-based
// Attest when the reference is a WorkloadPIDReference.
func (p *Plugin) AttestReference(_ context.Context, _ *workloadattestorv1.AttestReferenceRequest) (*workloadattestorv1.AttestReferenceResponse, error) {
	return nil, status.Error(codes.Unimplemented, "AttestReference not implemented")
}

func (p *Plugin) Configure(_ context.Context, req *configv1.ConfigureRequest) (*configv1.ConfigureResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "missing configure request")
	}
	if err := decodeConfig(req.HclConfiguration); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "failed to decode configuration: %v", err)
	}
	return &configv1.ConfigureResponse{}, nil
}

func (p *Plugin) Validate(_ context.Context, req *configv1.ValidateRequest) (*configv1.ValidateResponse, error) {
	hclText := ""
	if req != nil {
		hclText = req.HclConfiguration
	}
	if err := decodeConfig(hclText); err != nil {
		return &configv1.ValidateResponse{
			Valid: false,
			Notes: []string{err.Error()},
		}, nil
	}
	return &configv1.ValidateResponse{Valid: true}, nil
}

func decodeConfig(hclText string) error {
	var cfg struct{}
	return hcl.Decode(&cfg, hclText)
}

// selectorPair emits both values or neither. A partial pair must not be published.
func selectorPair(kindA, a, kindB, b string) []string {
	if a == "" || b == "" {
		return nil
	}
	return []string{kindA + ":" + a, kindB + ":" + b}
}

func (p *Plugin) debug(msg string, kv ...any) {
	if p != nil && p.log != nil {
		p.log.Debug(msg, kv...)
	}
}

func (p *Plugin) warn(msg string, kv ...any) {
	if p != nil && p.log != nil {
		p.log.Warn(msg, kv...)
	}
}
