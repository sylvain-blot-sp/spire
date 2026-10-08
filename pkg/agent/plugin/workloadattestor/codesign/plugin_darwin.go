//go:build darwin

package codesign

/*
#cgo LDFLAGS: -framework Security -framework CoreFoundation
#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// CODESIGN_NO_IDENTITY: unsigned, ad-hoc, or no Team ID / identifier pair.
// Positive so it cannot collide with an OSStatus error.
#define CODESIGN_NO_IDENTITY 1

static char *codesign_cfstring(CFStringRef s) {
	if (!s) {
		return NULL;
	}
	CFIndex len = CFStringGetLength(s);
	CFIndex max = CFStringGetMaximumSizeForEncoding(len, kCFStringEncodingUTF8) + 1;
	if (max <= 1) {
		return NULL;
	}
	char *buf = malloc((size_t)max);
	if (!buf) {
		return NULL;
	}
	if (!CFStringGetCString(s, buf, max, kCFStringEncodingUTF8) || buf[0] == '\0') {
		free(buf);
		return NULL;
	}
	return buf;
}

// Apple Team IDs are ten upper-case alphanumerics.
static int codesign_valid_team(const char *t) {
	if (strlen(t) != 10) {
		return 0;
	}
	for (const char *c = t; *c; c++) {
		if (!((*c >= 'A' && *c <= 'Z') || (*c >= '0' && *c <= '9'))) {
			return 0;
		}
	}
	return 1;
}

// The identifier is quoted into a requirement string, so reject anything that
// could end or escape the literal.
static int codesign_valid_ident(const char *s) {
	for (const char *c = s; *c; c++) {
		unsigned char u = (unsigned char)*c;
		if (u < 0x20 || u == 0x7f || u == '"' || u == '\\') {
			return 0;
		}
	}
	return 1;
}

// codesign_unverified_info reads the Team ID and identifier claimed by the
// CodeDirectory. Nothing here is trusted: the signer chooses both values. The
// caller only uses them to build the requirement that is then verified.
static int codesign_unverified_info(SecStaticCodeRef code, char **team_out, char **ident_out) {
	CFDictionaryRef info = NULL;
	OSStatus st = SecCodeCopySigningInformation(code, kSecCSSigningInformation, &info);
	if (st != errSecSuccess || !info) {
		return st != errSecSuccess ? (int)st : CODESIGN_NO_IDENTITY;
	}

	int rc = CODESIGN_NO_IDENTITY;
	uint32_t flags = 0;
	CFTypeRef flagsValue = CFDictionaryGetValue(info, kSecCodeInfoFlags);
	if (flagsValue && CFGetTypeID(flagsValue) == CFNumberGetTypeID()) {
		CFNumberGetValue((CFNumberRef)flagsValue, kCFNumberSInt32Type, &flags);
	}
	CFTypeRef teamValue = CFDictionaryGetValue(info, kSecCodeInfoTeamIdentifier);
	CFTypeRef identValue = CFDictionaryGetValue(info, kSecCodeInfoIdentifier);
	if ((flags & kSecCodeSignatureAdhoc) == 0 &&
		teamValue && CFGetTypeID(teamValue) == CFStringGetTypeID() &&
		identValue && CFGetTypeID(identValue) == CFStringGetTypeID()) {
		*team_out = codesign_cfstring((CFStringRef)teamValue);
		*ident_out = codesign_cfstring((CFStringRef)identValue);
		if (*team_out && *ident_out && codesign_valid_team(*team_out) && codesign_valid_ident(*ident_out)) {
			rc = 0;
		}
	}
	CFRelease(info);
	if (rc != 0) {
		free(*team_out);
		free(*ident_out);
		*team_out = NULL;
		*ident_out = NULL;
	}
	return rc;
}

// codesign_verify returns 0 and fills team/ident only when the code satisfies
//
//	anchor apple generic and certificate leaf[subject.OU] = TEAM and identifier IDENT
//
// "anchor apple generic" pins the chain to Apple's root. A chain that ends at
// any other system-trusted root (a public code-signing CA) does not satisfy
// it, and the leaf OU check binds the CodeDirectory Team ID to the Apple-issued
// certificate. The identifier is sealed by the same signature.
static int codesign_verify(SecStaticCodeRef code, int dynamic, char **team_out, char **ident_out) {
	*team_out = NULL;
	*ident_out = NULL;
	char *team = NULL;
	char *ident = NULL;
	int rc = codesign_unverified_info(code, &team, &ident);
	if (rc != 0) {
		return rc;
	}

	const char *fmt = "anchor apple generic and certificate leaf[subject.OU] = \"%s\" and identifier \"%s\"";
	size_t n = strlen(fmt) + strlen(team) + strlen(ident) + 1;
	char *text = malloc(n);
	CFStringRef reqText = NULL;
	SecRequirementRef req = NULL;
	OSStatus st = errSecAllocate;
	if (text) {
		snprintf(text, n, fmt, team, ident);
		reqText = CFStringCreateWithCString(NULL, text, kCFStringEncodingUTF8);
		free(text);
	}
	if (reqText) {
		st = SecRequirementCreateWithString(reqText, kSecCSDefaultFlags, &req);
		CFRelease(reqText);
	}
	if (st == errSecSuccess && req) {
		st = dynamic
			? SecCodeCheckValidity((SecCodeRef)code, kSecCSDefaultFlags, req)
			: SecStaticCodeCheckValidity(code, kSecCSDefaultFlags, req);
		CFRelease(req);
	}
	if (st != errSecSuccess) {
		free(team);
		free(ident);
		return (int)st;
	}
	*team_out = team;
	*ident_out = ident;
	return 0;
}

// codesign_identity verifies an on-disk path. Tests use this. Attest uses the
// PID guest.
static int codesign_identity(const char *path, char **team_out, char **ident_out) {
	*team_out = NULL;
	*ident_out = NULL;
	if (!path || path[0] == '\0') {
		return CODESIGN_NO_IDENTITY;
	}
	CFURLRef url = CFURLCreateFromFileSystemRepresentation(NULL, (const UInt8 *)path, (CFIndex)strlen(path), false);
	if (!url) {
		return CODESIGN_NO_IDENTITY;
	}
	SecStaticCodeRef code = NULL;
	OSStatus st = SecStaticCodeCreateWithPath(url, kSecCSDefaultFlags, &code);
	CFRelease(url);
	if (st != errSecSuccess || !code) {
		return st != errSecSuccess ? (int)st : CODESIGN_NO_IDENTITY;
	}
	int rc = codesign_verify(code, 0, team_out, ident_out);
	CFRelease(code);
	return rc;
}

// codesign_identity_pid attests the kernel's code object for the running PID.
// A path lookup can name a different file than the one the process executed.
static int codesign_identity_pid(int pid, char **team_out, char **ident_out) {
	*team_out = NULL;
	*ident_out = NULL;
	if (pid <= 0) {
		return CODESIGN_NO_IDENTITY;
	}
	CFNumberRef pidNum = CFNumberCreate(NULL, kCFNumberIntType, &pid);
	if (!pidNum) {
		return errSecAllocate;
	}
	const void *keys[] = {kSecGuestAttributePid};
	const void *vals[] = {pidNum};
	CFDictionaryRef attrs = CFDictionaryCreate(NULL, keys, vals, 1, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
	CFRelease(pidNum);
	if (!attrs) {
		return errSecAllocate;
	}
	SecCodeRef guest = NULL;
	OSStatus st = SecCodeCopyGuestWithAttributes(NULL, attrs, kSecCSDefaultFlags, &guest);
	CFRelease(attrs);
	if (st != errSecSuccess || !guest) {
		return st != errSecSuccess ? (int)st : CODESIGN_NO_IDENTITY;
	}
	int rc = codesign_verify((SecStaticCodeRef)guest, 1, team_out, ident_out);
	CFRelease(guest);
	return rc;
}
*/
import "C"
import (
	"time"
	"unsafe"
)

// trustCache is Windows-only. macOS validates the kernel's code object for the
// PID, which needs no network round trip.
type trustCache struct{}

func newTrustCache(func() time.Time) *trustCache {
	return nil
}

// errSecCSUnsigned: the code has no signature at all. Expected for most
// processes, so it is not worth a warning.
const errSecCSUnsigned = -67062

func attestPID(p *Plugin, pid int32) []string {
	if pid <= 0 {
		p.debug("codesign attest skipped: invalid pid", "pid", pid)
		return nil
	}
	var team, ident *C.char
	rc := C.codesign_identity_pid(C.int(pid), &team, &ident)
	selectors := takeSelectors(rc, team, ident)
	switch rc {
	case 0:
	case C.CODESIGN_NO_IDENTITY, errSecCSUnsigned:
		p.debug("codesign attest: no Apple-issued identity", "pid", pid, "status", int(rc))
	default:
		// Signed but not verifiable as Apple-issued, or a Security framework
		// failure. This is what an operator needs when a workload gets no SVID.
		p.warn("codesign attest: signature rejected", "pid", pid, "osstatus", int(rc))
	}
	return selectors
}

func signatureSelectors(path string) []string {
	if path == "" {
		return nil
	}
	cpath := C.CString(path)
	defer C.free(unsafe.Pointer(cpath))
	var team, ident *C.char
	rc := C.codesign_identity(cpath, &team, &ident)
	return takeSelectors(rc, team, ident)
}

// takeSelectors frees the C strings and returns the pair only on success.
func takeSelectors(rc C.int, team, ident *C.char) []string {
	defer C.free(unsafe.Pointer(team))
	defer C.free(unsafe.Pointer(ident))
	if rc != 0 {
		return nil
	}
	return selectorPair("teamid", C.GoString(team), "identifier", C.GoString(ident))
}
