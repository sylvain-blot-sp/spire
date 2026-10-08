//go:build windows

package codesign

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	workloadattestorv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/agent/workloadattestor/v1"
)

// helperSleepEnv makes the test binary sleep instead of running tests, so a
// test can attest a running process whose image is known to be unsigned.
const helperSleepEnv = "CODESIGN_TEST_HELPER_SLEEP"

func TestMain(m *testing.M) {
	if os.Getenv(helperSleepEnv) != "" {
		time.Sleep(30 * time.Second)
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func TestSignedSystemBinaryEmitsPublisherDER(t *testing.T) {
	path, pub := embeddedSignedSystemBinary(t)
	parsed, err := x509.ParseCertificate(pub.encoded)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(parsed.RawIssuer, pub.issuer) || !bytes.Equal(parsed.RawSubject, pub.subject) {
		t.Fatal("leaf issuer/subject DER does not match the parsed certificate")
	}
	wantIssuer := "publisher_issuer:" + hex.EncodeToString(pub.issuer)
	wantSubject := "publisher_subject:" + hex.EncodeToString(pub.subject)
	if wantIssuer != strings.ToLower(wantIssuer) || wantSubject != strings.ToLower(wantSubject) {
		t.Fatal("publisher hex is not lowercase")
	}
	got := pub.selectors()
	if len(got) != 2 || got[0] != wantIssuer || got[1] != wantSubject {
		t.Fatalf("selectors\n got %v\nwant %s %s", got, wantIssuer, wantSubject)
	}
	sum := sha256.Sum256(pub.encoded)
	thumb := hex.EncodeToString(sum[:])
	for _, value := range got {
		if strings.Contains(value, "thumbprint") || strings.Contains(value, thumb) {
			t.Fatalf("selector contains leaf thumbprint: %s", value)
		}
		if strings.HasPrefix(value, "codesign:") {
			t.Fatalf("selector includes plugin name: %s", value)
		}
	}

	// ping keeps running long enough to attest. Other candidates may exit at
	// once, so attest a running ping only when ping is the signed candidate.
	if !strings.EqualFold(filepath.Base(path), "ping.exe") {
		return
	}
	resp := attestRunning(t, exec.Command(path, "-n", "30", "127.0.0.1"))
	if len(resp.SelectorValues) != 2 || resp.SelectorValues[0] != wantIssuer || resp.SelectorValues[1] != wantSubject {
		t.Fatalf("attest selectors: %v", resp.SelectorValues)
	}
}

func TestUnsignedFileIsUnsigned(t *testing.T) {
	path := filepath.Join(t.TempDir(), "unsigned.exe")
	if err := os.WriteFile(path, []byte("MZ unsigned"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := New().trust.publisher(path); !errors.Is(err, errUnsigned) {
		t.Fatalf("want errUnsigned, got %v", err)
	}
}

func TestUnsignedRunningProcessEmitsNothing(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(self)
	cmd.Env = append(os.Environ(), helperSleepEnv+"=1")
	resp := attestRunning(t, cmd)
	if len(resp.SelectorValues) != 0 {
		t.Fatalf("unsigned process selectors: %v", resp.SelectorValues)
	}
}

func TestInvalidPIDEmitsNothing(t *testing.T) {
	resp, err := New().Attest(context.Background(), &workloadattestorv1.AttestRequest{Pid: -1})
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.SelectorValues) != 0 {
		t.Fatalf("selectors: %v", resp.SelectorValues)
	}
}

func TestTrustCacheExpires(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	c := newTrustCache(func() time.Time { return now })
	digest := sha256.Sum256([]byte("image"))
	want := publisher{issuer: []byte{1}, subject: []byte{2}}
	c.store(digest, want)

	now = now.Add(trustCacheTTL - time.Second)
	if got, ok := c.lookup(digest); !ok || !bytes.Equal(got.issuer, want.issuer) {
		t.Fatal("entry missing before TTL")
	}
	now = now.Add(time.Second)
	if _, ok := c.lookup(digest); ok {
		t.Fatal("entry served at TTL")
	}
}

func TestTrustCacheIsBounded(t *testing.T) {
	c := newTrustCache(time.Now)
	for i := range trustCacheMax + 1 {
		c.store(sha256.Sum256([]byte{byte(i), byte(i >> 8)}), publisher{})
	}
	if len(c.entries) > trustCacheMax {
		t.Fatalf("cache holds %d entries", len(c.entries))
	}
}

// embeddedSignedSystemBinary returns the first inbox binary that carries an
// embedded Authenticode signature. Many System32 images are catalog-signed
// only, which WTD_CHOICE_FILE reports as unsigned.
func embeddedSignedSystemBinary(t *testing.T) (string, publisher) {
	t.Helper()
	root := os.Getenv("SystemRoot")
	candidates := []string{
		filepath.Join(root, "System32", "ping.exe"),
		filepath.Join(root, "System32", "ntoskrnl.exe"),
		filepath.Join(root, "explorer.exe"),
		filepath.Join(root, "System32", "WindowsPowerShell", "v1.0", "powershell.exe"),
	}
	var errs []string
	for _, path := range candidates {
		pub, err := New().trust.publisher(path)
		if err == nil {
			return path, pub
		}
		errs = append(errs, path+": "+err.Error())
	}
	t.Fatalf("no embedded-signed system binary:\n%s", strings.Join(errs, "\n"))
	return "", publisher{}
}

func attestRunning(t *testing.T, cmd *exec.Cmd) *workloadattestorv1.AttestResponse {
	t.Helper()
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	})
	resp, err := New().Attest(context.Background(), &workloadattestorv1.AttestRequest{
		Pid: int32(cmd.Process.Pid),
	})
	if err != nil {
		t.Fatal(err)
	}
	return resp
}
