//go:build windows

package codesign

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	// CMSG_SIGNER_CERT_INFO_PARAM is wincrypt.h value 7. x/sys v0.45 does not export it.
	cmsgSignerCertInfoParam = 7
	// WSS_GET_SECONDARY_SIG_COUNT and WTD_PROV_FLAGS_MASK match wintrust.h and
	// rust/common/src/windows/wintrust/verify.rs.
	wssGetSecondarySigCount = 2
	wtdProvFlagsMask        = 0x0000FFFF
	// TRUST_E_NOSIGNATURE and TRUST_E_SUBJECT_FORM_UNKNOWN: no Authenticode
	// signature, or not a signable file. Expected for most processes.
	trustENoSignature        = 0x800B0100
	trustESubjectFormUnknown = 0x800B0003

	imageDOSSignature           = 0x5A4D
	imageNTSignature            = 0x00004550
	pe32Magic                   = 0x10B
	pe32PlusMagic               = 0x20B
	imageDirectoryEntrySecurity = 4
	winCertHeaderLen            = 8
	winCertTypePKCSSignedData   = 2
	maxCertTableBytes           = 16 * 1024 * 1024
	maxImageBytes               = 1 << 30

	// trustCacheTTL bounds how long a revoked publisher keeps attesting.
	// WinVerifyTrust checks revocation online for the whole chain; without a
	// cache every Workload API connection pays a CRL/OCSP round trip.
	trustCacheTTL = time.Hour
	// trustCacheMax bounds memory. Few distinct signed images talk to the
	// agent, so clearing on overflow is enough.
	trustCacheMax = 64
)

var (
	crypt32              = windows.NewLazySystemDLL("crypt32.dll")
	procCryptMsgGetParam = crypt32.NewProc("CryptMsgGetParam")
	procCryptMsgClose    = crypt32.NewProc("CryptMsgClose")

	errUnsigned = errors.New("no Authenticode signature")
	// Catalog-signed images can pass WinVerifyTrust with no PE certificate
	// table. That is trusted-but-unreadable, not unsigned.
	errLeafUnavailable = errors.New("trusted, but the leaf certificate could not be read")
)

// publisher is the leaf certificate identity, read only after WinVerifyTrust
// succeeds. encoded is for tests that check the bytes against crypto/x509.
type publisher struct {
	issuer, subject, encoded []byte
}

func (pub publisher) selectors() []string {
	return selectorPair(
		"publisher_issuer", hex.EncodeToString(pub.issuer),
		"publisher_subject", hex.EncodeToString(pub.subject),
	)
}

// attestPID resolves the image by path. The process name is fixed at process
// creation, and a running image can be renamed and replaced, so the bytes
// checked here are not guaranteed to be the bytes that are running. Windows
// registration entries must therefore also pin a `windows:path` selector in a
// directory only administrators can write (see docs/spire-architecture.md).
func attestPID(p *Plugin, pid int32) []string {
	path, err := executablePath(pid)
	if err != nil {
		p.debug("codesign path lookup failed", "pid", pid, "error", err)
		return nil
	}
	pub, err := p.trust.publisher(path)
	switch {
	case err == nil:
		return pub.selectors()
	case errors.Is(err, errUnsigned):
		p.debug("codesign attest: unsigned image", "pid", pid, "path", path)
	default:
		p.warn("codesign attest: signature rejected", "pid", pid, "path", path, "error", err)
	}
	return nil
}

func executablePath(pid int32) (string, error) {
	if pid <= 0 {
		return "", errors.New("invalid pid")
	}
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		return "", err
	}
	defer windows.CloseHandle(h)

	buf := make([]uint16, windows.MAX_LONG_PATH)
	size := uint32(len(buf))
	if err := windows.QueryFullProcessImageName(h, 0, &buf[0], &size); err != nil {
		return "", err
	}
	return windows.UTF16ToString(buf[:size]), nil
}

// trustCache remembers successful verifications by SHA-256 of the image
// bytes. Only success is cached: the agent starts before the network is
// reliably up, and caching a revocation timeout would deny the workload until
// the TTL ran out. The clock is injected for tests.
type trustCache struct {
	now     func() time.Time
	mu      sync.Mutex
	entries map[[sha256.Size]byte]cachedPublisher
}

type cachedPublisher struct {
	pub     publisher
	expires time.Time
}

func newTrustCache(now func() time.Time) *trustCache {
	return &trustCache{now: now, entries: make(map[[sha256.Size]byte]cachedPublisher)}
}

// publisher verifies path, or returns the cached result for identical bytes.
// The handle denies write sharing, so the digest, WinVerifyTrust, and the
// certificate table all see the same content.
func (c *trustCache) publisher(path string) (publisher, error) {
	file, err := openImage(path)
	if err != nil {
		return publisher{}, fmt.Errorf("open image: %w", err)
	}
	defer windows.CloseHandle(file)
	digest, err := fileDigest(file)
	if err != nil {
		return publisher{}, err
	}
	if pub, ok := c.lookup(digest); ok {
		return pub, nil
	}
	pub, err := verifiedPublisher(path, file)
	if err != nil {
		return publisher{}, err
	}
	c.store(digest, pub)
	return pub, nil
}

func (c *trustCache) lookup(digest [sha256.Size]byte) (publisher, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	entry, ok := c.entries[digest]
	if !ok {
		return publisher{}, false
	}
	if !c.now().Before(entry.expires) {
		delete(c.entries, digest)
		return publisher{}, false
	}
	return entry.pub, true
}

func (c *trustCache) store(digest [sha256.Size]byte, pub publisher) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.entries) >= trustCacheMax {
		clear(c.entries)
	}
	c.entries[digest] = cachedPublisher{pub: pub, expires: c.now().Add(trustCacheTTL)}
}

func verifiedPublisher(path string, file windows.Handle) (publisher, error) {
	if err := winVerifyTrust(path, file); err != nil {
		return publisher{}, err
	}
	pkcs7, ok := embeddedPKCS7(file)
	if !ok {
		return publisher{}, errLeafUnavailable
	}
	pub, ok := leafFromPKCS7(pkcs7)
	if !ok {
		return publisher{}, errLeafUnavailable
	}
	return pub, nil
}

func openImage(path string) (windows.Handle, error) {
	pathPtr, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return 0, err
	}
	// No FILE_SHARE_WRITE: nobody can change the bytes while this handle is
	// open, and an existing writer makes the open fail closed. A mapped
	// executable has no write opens, so it still opens.
	return windows.CreateFile(
		pathPtr,
		windows.GENERIC_READ,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_DELETE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_ATTRIBUTE_NORMAL,
		0,
	)
}

func fileDigest(file windows.Handle) ([sha256.Size]byte, error) {
	var sum [sha256.Size]byte
	high := int32(0)
	if _, err := windows.SetFilePointer(file, 0, &high, windows.FILE_BEGIN); err != nil {
		return sum, fmt.Errorf("seek image: %w", err)
	}
	h := sha256.New()
	buf := make([]byte, 1<<20)
	total := 0
	for {
		var n uint32
		if err := windows.ReadFile(file, buf, &n, nil); err != nil {
			return sum, fmt.Errorf("read image: %w", err)
		}
		if n == 0 {
			break
		}
		total += int(n)
		if total > maxImageBytes {
			return sum, errors.New("image larger than 1 GiB")
		}
		h.Write(buf[:n])
	}
	copy(sum[:], h.Sum(nil))
	return sum, nil
}

func winVerifyTrust(path string, file windows.Handle) error {
	pathPtr, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	fileInfo := windows.WinTrustFileInfo{
		Size:     uint32(unsafe.Sizeof(windows.WinTrustFileInfo{})),
		FilePath: pathPtr,
		File:     file,
	}
	sigSettings := windows.WinTrustSignatureSettings{
		Size:  uint32(unsafe.Sizeof(windows.WinTrustSignatureSettings{})),
		Flags: wssGetSecondarySigCount,
	}
	action := windows.WINTRUST_ACTION_GENERIC_VERIFY_V2
	data := windows.WinTrustData{
		Size:                            uint32(unsafe.Sizeof(windows.WinTrustData{})),
		UIChoice:                        windows.WTD_UI_NONE,
		RevocationChecks:                windows.WTD_REVOKE_WHOLECHAIN,
		UnionChoice:                     windows.WTD_CHOICE_FILE,
		FileOrCatalogOrBlobOrSgnrOrCert: unsafe.Pointer(&fileInfo),
		StateAction:                     windows.WTD_STATEACTION_VERIFY,
		ProvFlags:                       (windows.WTD_REVOCATION_CHECK_CHAIN | windows.WTD_DISABLE_MD2_MD4) & wtdProvFlagsMask,
		UIContext:                       windows.WTD_UICONTEXT_EXECUTE,
		SignatureSettings:               &sigSettings,
	}
	verifyErr := windows.WinVerifyTrustEx(windows.InvalidHWND, &action, &data)
	data.StateAction = windows.WTD_STATEACTION_CLOSE
	_ = windows.WinVerifyTrustEx(windows.InvalidHWND, &action, &data)
	if verifyErr == nil {
		return nil
	}
	var errno windows.Errno
	if errors.As(verifyErr, &errno) && (uint32(errno) == trustENoSignature || uint32(errno) == trustESubjectFormUnknown) {
		return errUnsigned
	}
	return fmt.Errorf("WinVerifyTrust: %w", verifyErr)
}

func leafFromPKCS7(der []byte) (publisher, bool) {
	if len(der) == 0 || len(der) > int(^uint32(0)) {
		return publisher{}, false
	}
	blob := windows.CryptIntegerBlob{
		Size: uint32(len(der)),
		Data: &der[0],
	}
	var store windows.Handle
	var msg windows.Handle
	err := windows.CryptQueryObject(
		windows.CERT_QUERY_OBJECT_BLOB,
		unsafe.Pointer(&blob),
		windows.CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED,
		windows.CERT_QUERY_FORMAT_FLAG_BINARY,
		0,
		nil,
		nil,
		nil,
		&store,
		&msg,
		nil,
	)
	if err != nil {
		return publisher{}, false
	}
	defer windows.CertCloseStore(store, 0)
	defer cryptMsgClose(msg)
	if msg == 0 || store == 0 {
		return publisher{}, false
	}

	infoBuf, ok := cryptMsgGetParam(msg, cmsgSignerCertInfoParam)
	if !ok || len(infoBuf) < int(unsafe.Sizeof(windows.CertInfo{})) {
		return publisher{}, false
	}
	info := (*windows.CertInfo)(unsafe.Pointer(&infoBuf[0]))
	encoding := uint32(windows.X509_ASN_ENCODING | windows.PKCS_7_ASN_ENCODING)
	cert, err := windows.CertFindCertificateInStore(
		store,
		encoding,
		0,
		windows.CERT_FIND_SUBJECT_CERT,
		unsafe.Pointer(info),
		nil,
	)
	if err != nil || cert == nil || cert.CertInfo == nil {
		return publisher{}, false
	}
	defer windows.CertFreeCertificateContext(cert)

	pub := publisher{
		issuer:  nameBytes(cert.CertInfo.Issuer),
		subject: nameBytes(cert.CertInfo.Subject),
	}
	if cert.EncodedCert != nil && cert.Length > 0 {
		pub.encoded = append([]byte(nil), unsafe.Slice(cert.EncodedCert, cert.Length)...)
	}
	if len(pub.issuer) == 0 || len(pub.subject) == 0 {
		return publisher{}, false
	}
	return pub, true
}

// embeddedPKCS7 reads the first PKCS #7 from the PE certificate table of file.
// The security directory's virtual address is a file offset.
func embeddedPKCS7(file windows.Handle) ([]byte, bool) {
	off, size, ok := peSecurityDirectory(file)
	if !ok || size == 0 || size > maxCertTableBytes {
		return nil, false
	}
	table, ok := readAt(file, int64(off), int(size))
	if !ok {
		return nil, false
	}
	return firstPKCS7(table)
}

func peSecurityDirectory(file windows.Handle) (offset, size uint32, ok bool) {
	dos, ok := readAt(file, 0, 64)
	if !ok || binary.LittleEndian.Uint16(dos[0:2]) != imageDOSSignature {
		return 0, 0, false
	}
	eLfanew := int64(binary.LittleEndian.Uint32(dos[0x3C:0x40]))
	nt, ok := readAt(file, eLfanew, 24)
	if !ok || binary.LittleEndian.Uint32(nt[0:4]) != imageNTSignature {
		return 0, 0, false
	}
	optSize := int(binary.LittleEndian.Uint16(nt[20:22]))
	if optSize < 2 {
		return 0, 0, false
	}
	optional, ok := readAt(file, eLfanew+24, optSize)
	if !ok {
		return 0, 0, false
	}
	magic := binary.LittleEndian.Uint16(optional[0:2])
	var dirOff, numOff int
	switch magic {
	case pe32Magic:
		dirOff, numOff = 96, 92
	case pe32PlusMagic:
		dirOff, numOff = 112, 108
	default:
		return 0, 0, false
	}
	if len(optional) < numOff+4 {
		return 0, 0, false
	}
	nRva := binary.LittleEndian.Uint32(optional[numOff : numOff+4])
	if nRva <= imageDirectoryEntrySecurity {
		return 0, 0, false
	}
	entry := dirOff + imageDirectoryEntrySecurity*8
	if len(optional) < entry+8 {
		return 0, 0, false
	}
	virtualAddress := binary.LittleEndian.Uint32(optional[entry : entry+4])
	dirSize := binary.LittleEndian.Uint32(optional[entry+4 : entry+8])
	if virtualAddress == 0 || dirSize == 0 {
		return 0, 0, false
	}
	return virtualAddress, dirSize, true
}

func firstPKCS7(table []byte) ([]byte, bool) {
	if len(table) < winCertHeaderLen {
		return nil, false
	}
	dwLength := int(binary.LittleEndian.Uint32(table[0:4]))
	if dwLength < winCertHeaderLen || dwLength > len(table) {
		return nil, false
	}
	if binary.LittleEndian.Uint16(table[6:8]) != winCertTypePKCSSignedData {
		return nil, false
	}
	blob := table[winCertHeaderLen:dwLength]
	n := pkcs7DERLen(blob)
	if n <= 0 || n > len(blob) {
		return nil, false
	}
	return append([]byte(nil), blob[:n]...), true
}

func pkcs7DERLen(blob []byte) int {
	if len(blob) < 2 || blob[0] != 0x30 {
		return 0
	}
	b := blob[1]
	if b < 0x80 {
		return 2 + int(b)
	}
	n := int(b & 0x7f)
	if n == 0 || n > 3 || len(blob) < 2+n {
		return 0
	}
	length := 0
	for i := 0; i < n; i++ {
		length = length<<8 | int(blob[2+i])
	}
	return 2 + n + length
}

func readAt(file windows.Handle, off int64, n int) ([]byte, bool) {
	if n <= 0 || n > maxCertTableBytes || off < 0 {
		return nil, false
	}
	high := int32(uint64(off) >> 32)
	if _, err := windows.SetFilePointer(file, int32(off), &high, windows.FILE_BEGIN); err != nil {
		return nil, false
	}
	buf := make([]byte, n)
	var done uint32
	if err := windows.ReadFile(file, buf, &done, nil); err != nil || int(done) != n {
		return nil, false
	}
	return buf, true
}

func nameBytes(b windows.CertNameBlob) []byte {
	if b.Data == nil || b.Size == 0 {
		return nil
	}
	return append([]byte(nil), unsafe.Slice(b.Data, b.Size)...)
}

func cryptMsgGetParam(msg windows.Handle, param uint32) ([]byte, bool) {
	var needed uint32
	r, _, _ := procCryptMsgGetParam.Call(
		uintptr(msg),
		uintptr(param),
		0,
		0,
		uintptr(unsafe.Pointer(&needed)),
	)
	if r == 0 || needed == 0 {
		return nil, false
	}
	buf := make([]byte, needed)
	r, _, _ = procCryptMsgGetParam.Call(
		uintptr(msg),
		uintptr(param),
		0,
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&needed)),
	)
	if r == 0 || needed == 0 || int(needed) > len(buf) {
		return nil, false
	}
	return buf[:needed], true
}

func cryptMsgClose(msg windows.Handle) {
	if msg == 0 {
		return
	}
	_, _, _ = procCryptMsgClose.Call(uintptr(msg))
}
