//go:build darwin

package codesign

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	workloadattestorv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/agent/workloadattestor/v1"
)

func TestAdHocAndUnsignedEmitNothing(t *testing.T) {
	adhoc := copySleep(t)
	run(t, "codesign", "--force", "--sign", "-", adhoc)
	if got := signatureSelectors(adhoc); len(got) != 0 {
		t.Fatalf("ad-hoc selectors: %v", got)
	}
	assertAttestEmpty(t, adhoc)

	unsigned := copySleep(t)
	run(t, "codesign", "--remove-signature", unsigned)
	if got := signatureSelectors(unsigned); len(got) != 0 {
		t.Fatalf("unsigned selectors: %v", got)
	}
	assertAttestEmpty(t, unsigned)
}

func TestTrustedSignatureEmitsTeamIDAndIdentifier(t *testing.T) {
	identity := trustedCodesignIdentity()
	if identity == "" {
		t.Skip("no trusted codesigning identity (set SENTINEL_CODE_CERTIFICATE)")
	}
	bin := copySleep(t)
	if err := signWithIdentity(bin, identity, ""); err != nil {
		t.Skipf("could not sign with %q: %v", identity, err)
	}
	team, ident := codesignDisplay(t, bin)
	if team == "" || team == "not set" || ident == "" {
		t.Skipf("signature for %q has no Team ID (team=%q identifier=%q)", identity, team, ident)
	}
	want := []string{"teamid:" + team, "identifier:" + ident}
	got := signatureSelectors(bin)
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("selectors\n got %v\nwant %v", got, want)
	}
	for _, value := range got {
		if strings.HasPrefix(value, "codesign:") {
			t.Fatalf("selector includes plugin name: %s", value)
		}
	}
	assertAttestMatches(t, bin, want)
}

func assertAttestEmpty(t *testing.T, bin string) {
	t.Helper()
	resp, err := attestRunning(t, bin)
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.SelectorValues) != 0 {
		t.Fatalf("attest selectors: %v", resp.SelectorValues)
	}
}

func assertAttestMatches(t *testing.T, bin string, want []string) {
	t.Helper()
	resp, err := attestRunning(t, bin)
	if err != nil {
		t.Fatal(err)
	}
	got := resp.SelectorValues
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("attest selectors\n got %v\nwant %v", got, want)
	}
}

func attestRunning(t *testing.T, bin string) (*workloadattestorv1.AttestResponse, error) {
	t.Helper()
	cmd := exec.Command(bin, "30")
	if err := cmd.Start(); err != nil {
		t.Fatalf("start %s: %v", bin, err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	})
	return New().Attest(context.Background(), &workloadattestorv1.AttestRequest{
		Pid: int32(cmd.Process.Pid),
	})
}

func copySleep(t *testing.T) string {
	t.Helper()
	src, err := os.ReadFile("/bin/sleep")
	if err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(t.TempDir(), "sleep")
	if err := os.WriteFile(dst, src, 0o755); err != nil {
		t.Fatal(err)
	}
	return dst
}

// trustedCodesignIdentity is only the identity named explicitly. Picking the
// first keychain identity would sign with whatever the build machine holds and
// can raise a keychain prompt in the middle of a build.
func trustedCodesignIdentity() string {
	return strings.TrimSpace(os.Getenv("SENTINEL_CODE_CERTIFICATE"))
}

func codesignDisplay(t *testing.T, bin string) (team, identifier string) {
	t.Helper()
	out, err := exec.Command("codesign", "-dv", "--verbose=4", bin).CombinedOutput()
	if err != nil {
		t.Fatalf("codesign -dv: %v\n%s", err, out)
	}
	for _, line := range strings.Split(string(out), "\n") {
		if v, ok := strings.CutPrefix(line, "TeamIdentifier="); ok {
			team = strings.TrimSpace(v)
		}
		if v, ok := strings.CutPrefix(line, "Identifier="); ok {
			identifier = strings.TrimSpace(v)
		}
	}
	return team, identifier
}

func signWithIdentity(bin, identity, keychain string) error {
	args := []string{"--force", "--sign", identity}
	if keychain != "" {
		args = append(args, "--keychain", keychain)
	}
	args = append(args, bin)
	out, err := exec.Command("codesign", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w\n%s", err, out)
	}
	return nil
}

func run(t *testing.T, name string, args ...string) {
	t.Helper()
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		t.Fatalf("%s %s: %v\n%s", name, strings.Join(args, " "), err, out)
	}
}
