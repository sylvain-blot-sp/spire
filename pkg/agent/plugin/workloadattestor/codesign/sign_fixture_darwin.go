//go:build darwin && codesignfixture

package codesign

/*
#cgo LDFLAGS: -framework Security -framework CoreFoundation
#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#include <stdio.h>
#include <string.h>

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"

typedef struct __SecCodeSigner *SecCodeSignerRef;
extern const CFStringRef kSecCodeSignerIdentity;
extern OSStatus SecCodeSignerCreate(CFDictionaryRef parameters, SecCSFlags flags, SecCodeSignerRef *signer);
extern OSStatus SecCodeSignerAddSignatureWithErrors(SecCodeSignerRef signer, SecStaticCodeRef code, SecCSFlags flags, CFErrorRef *errors);

// codesign(1) refuses an identity that is not trusted ("no identity found").
// SecCodeSigner writes the CMS blob anyway, so the test can lock
// SecStaticCodeCheckValidity's trust evaluation. The codesignfixture tag
// keeps this file out of the spire-agent build.
static int codesign_sign_keychain(const char *kcpath, const char *password, const char *bin, char *errbuf, int errlen) {
	errbuf[0] = '\0';
	SecKeychainRef kc = NULL;
	OSStatus st = SecKeychainOpen(kcpath, &kc);
	if (st != errSecSuccess || !kc) {
		snprintf(errbuf, (size_t)errlen, "SecKeychainOpen %d", (int)st);
		return 1;
	}
	st = SecKeychainUnlock(kc, (UInt32)strlen(password), password, true);
	if (st != errSecSuccess) {
		snprintf(errbuf, (size_t)errlen, "SecKeychainUnlock %d", (int)st);
		CFRelease(kc);
		return 1;
	}

	const void *kcptr = kc;
	CFArrayRef search = CFArrayCreate(NULL, &kcptr, 1, &kCFTypeArrayCallBacks);
	const void *qkeys[] = { kSecClass, kSecMatchLimit, kSecReturnRef, kSecMatchSearchList };
	const void *qvals[] = { kSecClassIdentity, kSecMatchLimitOne, kCFBooleanTrue, search };
	CFDictionaryRef query = CFDictionaryCreate(NULL, qkeys, qvals, 4, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
	CFTypeRef ident = NULL;
	st = SecItemCopyMatching(query, &ident);
	CFRelease(query);
	CFRelease(search);
	if (st != errSecSuccess || !ident) {
		snprintf(errbuf, (size_t)errlen, "SecItemCopyMatching %d", (int)st);
		CFRelease(kc);
		return 1;
	}

	const void *skeys[] = { kSecCodeSignerIdentity };
	const void *svals[] = { ident };
	CFDictionaryRef params = CFDictionaryCreate(NULL, skeys, svals, 1, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
	SecCodeSignerRef signer = NULL;
	st = SecCodeSignerCreate(params, kSecCSDefaultFlags, &signer);
	CFRelease(params);
	if (st != errSecSuccess || !signer) {
		snprintf(errbuf, (size_t)errlen, "SecCodeSignerCreate %d", (int)st);
		CFRelease(ident);
		CFRelease(kc);
		return 1;
	}

	CFURLRef url = CFURLCreateFromFileSystemRepresentation(NULL, (const UInt8 *)bin, (CFIndex)strlen(bin), false);
	SecStaticCodeRef code = NULL;
	st = SecStaticCodeCreateWithPath(url, kSecCSDefaultFlags, &code);
	CFRelease(url);
	if (st != errSecSuccess || !code) {
		snprintf(errbuf, (size_t)errlen, "SecStaticCodeCreateWithPath %d", (int)st);
		CFRelease(signer);
		CFRelease(ident);
		CFRelease(kc);
		return 1;
	}

	CFErrorRef error = NULL;
	st = SecCodeSignerAddSignatureWithErrors(signer, code, kSecCSDefaultFlags, &error);
	if (st != errSecSuccess) {
		if (error) {
			CFStringRef desc = CFErrorCopyDescription(error);
			if (!desc || !CFStringGetCString(desc, errbuf, errlen, kCFStringEncodingUTF8)) {
				snprintf(errbuf, (size_t)errlen, "SecCodeSignerAddSignature %d", (int)st);
			}
			if (desc) {
				CFRelease(desc);
			}
			CFRelease(error);
		} else {
			snprintf(errbuf, (size_t)errlen, "SecCodeSignerAddSignature %d", (int)st);
		}
		CFRelease(code);
		CFRelease(signer);
		CFRelease(ident);
		CFRelease(kc);
		return 1;
	}

	CFRelease(code);
	CFRelease(signer);
	CFRelease(ident);
	CFRelease(kc);
	return 0;
}

static int codesign_validity_status(const char *path) {
	CFURLRef url = CFURLCreateFromFileSystemRepresentation(NULL, (const UInt8 *)path, (CFIndex)strlen(path), false);
	if (!url) {
		return -1;
	}
	SecStaticCodeRef code = NULL;
	OSStatus st = SecStaticCodeCreateWithPath(url, kSecCSDefaultFlags, &code);
	CFRelease(url);
	if (st != errSecSuccess || !code) {
		return st != errSecSuccess ? (int)st : -1;
	}
	st = SecStaticCodeCheckValidity(code, kSecCSCheckTrustedAnchors, NULL);
	CFRelease(code);
	return (int)st;
}
#pragma clang diagnostic pop
*/
import "C"

import (
	"fmt"
	"unsafe"
)

func signUntrustedKeychain(keychain, password, bin string) error {
	kc := C.CString(keychain)
	defer C.free(unsafe.Pointer(kc))
	pw := C.CString(password)
	defer C.free(unsafe.Pointer(pw))
	path := C.CString(bin)
	defer C.free(unsafe.Pointer(path))
	buf := (*C.char)(C.malloc(512))
	if buf == nil {
		return fmt.Errorf("malloc")
	}
	defer C.free(unsafe.Pointer(buf))
	if C.codesign_sign_keychain(kc, pw, path, buf, 512) != 0 {
		return fmt.Errorf("%s", C.GoString(buf))
	}
	return nil
}

func signatureValidityStatus(path string) int32 {
	cpath := C.CString(path)
	defer C.free(unsafe.Pointer(cpath))
	return int32(C.codesign_validity_status(cpath))
}
