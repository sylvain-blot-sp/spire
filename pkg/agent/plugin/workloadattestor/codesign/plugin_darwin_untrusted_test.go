//go:build darwin && codesignfixture

package codesign

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestUntrustedSelfSignedEmitsNothing(t *testing.T) {
	bin := copySleep(t)
	run(t, "codesign", "--remove-signature", bin)
	kc := installUntrustedIdentity(t)
	if err := signUntrustedKeychain(kc, "temp", bin); err != nil {
		t.Fatalf("could not create an untrusted self-signed binary: %v", err)
	}
	out, err := exec.Command("codesign", "-dv", "--verbose=4", bin).CombinedOutput()
	if err != nil {
		t.Fatalf("codesign -dv: %v\n%s", err, out)
	}
	text := string(out)
	if strings.Contains(text, "Signature=adhoc") {
		t.Fatalf("fixture is ad-hoc, so it does not lock the trust gate:\n%s", text)
	}
	if !strings.Contains(text, "Sentinel Codesign Test") {
		t.Fatalf("fixture is not signed by the self-signed cert:\n%s", text)
	}
	// The fixture's OU is a well-formed Team ID, so the plugin gets as far as
	// the requirement check. "anchor apple generic" rejects a chain that ends
	// at this self-signed certificate. The plugin must return no selectors and
	// no error.
	if st := signatureValidityStatus(bin); st == 0 {
		t.Fatalf("self-signed binary passed trust evaluation:\n%s", text)
	}
	if got := signatureSelectors(bin); len(got) != 0 {
		t.Fatalf("untrusted signature produced selectors: %v", got)
	}
	assertAttestEmpty(t, bin)
}

func installUntrustedIdentity(t *testing.T) (keychain string) {
	t.Helper()
	dir := t.TempDir()
	cnf := filepath.Join(dir, "openssl.cnf")
	cnfText := `
[req]
distinguished_name=dn
x509_extensions=ext
prompt=no
[dn]
CN=Sentinel Codesign Test
OU=TESTTEAM01
[ext]
extendedKeyUsage=codeSigning
keyUsage=digitalSignature
`
	if err := os.WriteFile(cnf, []byte(cnfText), 0o600); err != nil {
		t.Fatal(err)
	}
	key := filepath.Join(dir, "key.pem")
	cert := filepath.Join(dir, "cert.pem")
	p12 := filepath.Join(dir, "cert.p12")
	run(t, "openssl", "req", "-x509", "-newkey", "rsa:2048", "-keyout", key, "-out", cert, "-days", "1", "-nodes", "-config", cnf)
	run(t, "openssl", "pkcs12", "-export", "-out", p12, "-inkey", key, "-in", cert, "-passout", "pass:temp")

	kc := filepath.Join(dir, "codesign.keychain-db")
	t.Cleanup(func() {
		_ = exec.Command("security", "delete-keychain", kc).Run()
	})
	run(t, "security", "create-keychain", "-p", "temp", kc)
	run(t, "security", "unlock-keychain", "-p", "temp", kc)
	// -A lets this test process use the key without a keychain UI prompt.
	// The keychain is temporary and deleted when the test ends.
	run(t, "security", "import", p12, "-k", kc, "-P", "temp", "-A", "-f", "pkcs12")
	_ = exec.Command("security", "set-key-partition-list", "-S", "apple-tool:,apple:,codesign:", "-s", "-k", "temp", kc).Run()
	return kc
}
