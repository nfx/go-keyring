//go:build windows

package keyring

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"strings"
	"sync"
	"syscall"
	"testing"
	"unicode/utf16"
	"unsafe"
)

// newWindowsBackendFake returns an FFI-free backend with successful default operations.
func newWindowsBackendFake() *windowsBackend {
	return &windowsBackend{
		closeDLL: func() error { return nil },
		credWrite: func(*windowsCredential) (bool, error) {
			return true, syscall.Errno(0)
		},
		credRead: func(_ *uint16, credential **windowsCredential) (bool, error) {
			*credential = &windowsCredential{}
			return true, syscall.Errno(0)
		},
		credDelete: func(*uint16) (bool, error) {
			return true, syscall.Errno(0)
		},
		credFree: func(*windowsCredential) {},
	}
}

func TestWindowsCredentialLayout(t *testing.T) {
	credential := windowsCredential{}
	if size := unsafe.Sizeof(credential); size != 80 {
		t.Fatalf("windowsCredential size = %d, want 80", size)
	}
	if offset := unsafe.Offsetof(credential.targetName); offset != 8 {
		t.Fatalf("targetName offset = %d, want 8", offset)
	}
	if offset := unsafe.Offsetof(credential.credentialBlob); offset != 40 {
		t.Fatalf("credentialBlob offset = %d, want 40", offset)
	}
	if offset := unsafe.Offsetof(credential.userName); offset != 72 {
		t.Fatalf("userName offset = %d, want 72", offset)
	}
}

func TestWindowsTarget_preservesCaseSensitiveLogicalKeys(t *testing.T) {
	backend := newWindowsBackendFake()
	target, err := backend.target("Service", "Account")
	if err != nil {
		t.Fatalf("target() error = %v", err)
	}
	differentService, err := backend.target("service", "Account")
	if err != nil {
		t.Fatalf("target() error = %v", err)
	}
	differentAccount, err := backend.target("Service", "account")
	if err != nil {
		t.Fatalf("target() error = %v", err)
	}
	if target == differentService || target == differentAccount {
		t.Fatalf("target() collapsed case-sensitive logical keys")
	}
	if !strings.HasPrefix(target, "github.com/nfx/go-keyring/") {
		t.Fatalf("target() = %q, missing namespace prefix", target)
	}
}

func TestWindowsCallError_mapsWin32Errors(t *testing.T) {
	backend := newWindowsBackendFake()
	cases := []struct {
		name string
		err  syscall.Errno
		want error
	}{
		{name: "not found", err: winErrorNotFound, want: ErrNotFound},
		{name: "denied", err: winErrorAccessDenied, want: ErrDenied},
		{name: "canceled", err: winErrorCanceled, want: ErrCanceled},
		{name: "invalid", err: winErrorInvalidParameter, want: ErrInvalid},
		{name: "unavailable", err: winErrorNoLogonSession, want: ErrUnavailable},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			err := backend.callError("get", test.err)
			if !errors.Is(err, test.want) {
				t.Fatalf("callError(%d) = %v, want %v", test.err, err, test.want)
			}
		})
	}
}

func TestWindowsSet_writesGenericCredential(t *testing.T) {
	backend := newWindowsBackendFake()
	var captured windowsCredential
	var capturedBlob []byte
	backend.credWrite = func(credential *windowsCredential) (bool, error) {
		captured = *credential
		capturedBlob = append(capturedBlob, unsafe.Slice(credential.credentialBlob, int(credential.credentialBlobSize))...)
		return true, syscall.Errno(0)
	}
	secret := []byte{0, 1, 255}

	err := backend.set(context.Background(), "service", "account", secret)
	if err != nil {
		t.Fatalf("set() error = %v", err)
	}
	if captured.typeValue != credTypeGeneric {
		t.Fatalf("set() type = %d, want %d", captured.typeValue, credTypeGeneric)
	}
	if captured.persist != credPersistLocalMachine {
		t.Fatalf("set() persist = %d, want %d", captured.persist, credPersistLocalMachine)
	}
	if !bytes.Equal(capturedBlob, secret) {
		t.Fatalf("set() blob = %v, want %v", capturedBlob, secret)
	}
}

func TestWindowsGet_copiesAndWipesNativeBlob(t *testing.T) {
	backend := newWindowsBackendFake()
	nativeBlob := []byte{1, 2, 3}
	nativeCredential := &windowsCredential{
		credentialBlobSize: uint32(len(nativeBlob)),
		credentialBlob:     unsafe.SliceData(nativeBlob),
	}
	freed := false
	backend.credRead = func(_ *uint16, credential **windowsCredential) (bool, error) {
		*credential = nativeCredential
		return true, syscall.Errno(0)
	}
	backend.credFree = func(credential *windowsCredential) {
		if credential != nativeCredential {
			t.Fatalf("CredFree() credential = %p, want %p", credential, nativeCredential)
		}
		freed = true
	}

	secret, err := backend.get(context.Background(), "service", "account")
	if err != nil {
		t.Fatalf("get() error = %v", err)
	}
	if !bytes.Equal(secret, []byte{1, 2, 3}) {
		t.Fatalf("get() secret = %v, want [1 2 3]", secret)
	}
	if !bytes.Equal(nativeBlob, []byte{0, 0, 0}) {
		t.Fatalf("get() did not wipe native blob: %v", nativeBlob)
	}
	if !freed {
		t.Fatalf("get() did not call CredFree")
	}
}

func TestWindowsDelete_missingCredentialSucceeds(t *testing.T) {
	backend := newWindowsBackendFake()
	backend.credDelete = func(*uint16) (bool, error) {
		return false, winErrorNotFound
	}

	err := backend.delete(context.Background(), "service", "account")
	if err != nil {
		t.Fatalf("delete() error = %v, want nil", err)
	}
}

// windowsFakeStore is a stateful, target-keyed native Credential Manager double, letting
// multipart tests observe exactly which credentials a call wrote, read, or removed.
type windowsFakeStore struct {
	mu    sync.Mutex
	items map[string][]byte
}

func newWindowsFakeStore() *windowsFakeStore {
	return &windowsFakeStore{items: map[string][]byte{}}
}

// backend returns a windowsBackend whose native calls are backed by this store.
func (s *windowsFakeStore) backend() *windowsBackend {
	return &windowsBackend{
		closeDLL: func() error { return nil },
		credWrite: func(credential *windowsCredential) (bool, error) {
			target := utf16PtrToString(credential.targetName)
			var blob []byte
			if credential.credentialBlobSize > 0 {
				blob = append([]byte(nil), unsafe.Slice(credential.credentialBlob, int(credential.credentialBlobSize))...)
			}
			s.mu.Lock()
			s.items[target] = blob
			s.mu.Unlock()
			return true, syscall.Errno(0)
		},
		credRead: func(targetName *uint16, out **windowsCredential) (bool, error) {
			target := utf16PtrToString(targetName)
			s.mu.Lock()
			blob, ok := s.items[target]
			s.mu.Unlock()
			if !ok {
				return false, winErrorNotFound
			}
			credential := &windowsCredential{credentialBlobSize: uint32(len(blob))}
			if len(blob) > 0 {
				credential.credentialBlob = unsafe.SliceData(append([]byte(nil), blob...))
			}
			*out = credential
			return true, syscall.Errno(0)
		},
		credDelete: func(targetName *uint16) (bool, error) {
			target := utf16PtrToString(targetName)
			s.mu.Lock()
			_, ok := s.items[target]
			delete(s.items, target)
			s.mu.Unlock()
			if !ok {
				return false, winErrorNotFound
			}
			return true, syscall.Errno(0)
		},
		credFree: func(*windowsCredential) {},
	}
}

// utf16PtrToString decodes a NUL-terminated native string, mirroring what CredWriteW receives.
func utf16PtrToString(ptr *uint16) string {
	if ptr == nil {
		return ""
	}
	length := 0
	for unsafe.Slice(ptr, length+1)[length] != 0 {
		length++
	}
	return string(utf16.Decode(unsafe.Slice(ptr, length)))
}

// deterministicSecret returns anonymized, reproducible filler bytes of the requested size.
func deterministicSecret(size int) []byte {
	secret := make([]byte, size)
	for i := range secret {
		secret[i] = byte(i % 256)
	}
	return secret
}

func TestWindowsSetGet_roundTripsSecretLargerThanChunkSize(t *testing.T) {
	store := newWindowsFakeStore()
	backend := store.backend()
	secret := deterministicSecret(windowsMaxChunkSize*3 + 17)

	err := backend.set(t.Context(), "service", "account", secret)
	if err != nil {
		t.Fatalf("set() error = %v", err)
	}
	target, err := backend.target("service", "account")
	if err != nil {
		t.Fatalf("target() error = %v", err)
	}
	wantItems := 1 + 4 // header + 4 parts (3 full chunks plus a 17-byte remainder)
	if len(store.items) != wantItems {
		t.Fatalf("set() wrote %d credentials, want %d", len(store.items), wantItems)
	}
	if _, ok := store.items[target]; !ok {
		t.Fatalf("set() did not write header credential %q", target)
	}

	got, err := backend.get(t.Context(), "service", "account")
	if err != nil {
		t.Fatalf("get() error = %v", err)
	}
	if !bytes.Equal(got, secret) {
		t.Fatalf("get() secret mismatch")
	}
}

func TestWindowsSetGet_secretAtChunkSizeStaysSingleCredential(t *testing.T) {
	store := newWindowsFakeStore()
	backend := store.backend()
	secret := deterministicSecret(windowsMaxChunkSize)

	err := backend.set(t.Context(), "service", "account", secret)
	if err != nil {
		t.Fatalf("set() error = %v", err)
	}
	if len(store.items) != 1 {
		t.Fatalf("set() wrote %d credentials, want 1", len(store.items))
	}

	got, err := backend.get(t.Context(), "service", "account")
	if err != nil {
		t.Fatalf("get() error = %v", err)
	}
	if !bytes.Equal(got, secret) {
		t.Fatalf("get() secret mismatch")
	}
}

func TestWindowsSet_removesStalePartsWhenNewSecretIsSmaller(t *testing.T) {
	store := newWindowsFakeStore()
	backend := store.backend()
	large := deterministicSecret(windowsMaxChunkSize*3 + 1)
	small := deterministicSecret(16)

	err := backend.set(t.Context(), "service", "account", large)
	if err != nil {
		t.Fatalf("set(large) error = %v", err)
	}
	err = backend.set(t.Context(), "service", "account", small)
	if err != nil {
		t.Fatalf("set(small) error = %v", err)
	}
	if len(store.items) != 1 {
		t.Fatalf("set(small) left %d credentials behind, want 1", len(store.items))
	}

	got, err := backend.get(t.Context(), "service", "account")
	if err != nil {
		t.Fatalf("get() error = %v", err)
	}
	if !bytes.Equal(got, small) {
		t.Fatalf("get() secret mismatch")
	}
}

func TestWindowsDelete_removesAllParts(t *testing.T) {
	store := newWindowsFakeStore()
	backend := store.backend()
	secret := deterministicSecret(windowsMaxChunkSize*2 + 1)

	err := backend.set(t.Context(), "service", "account", secret)
	if err != nil {
		t.Fatalf("set() error = %v", err)
	}
	if len(store.items) <= 1 {
		t.Fatalf("set() wrote %d credentials, want more than 1", len(store.items))
	}

	err = backend.delete(t.Context(), "service", "account")
	if err != nil {
		t.Fatalf("delete() error = %v", err)
	}
	if len(store.items) != 0 {
		t.Fatalf("delete() left %d credentials behind, want 0", len(store.items))
	}
	_, err = backend.get(t.Context(), "service", "account")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("get() after delete() error = %v, want ErrNotFound", err)
	}
}

func TestWindowsGet_detectsTruncatedPart(t *testing.T) {
	store := newWindowsFakeStore()
	backend := store.backend()
	secret := deterministicSecret(windowsMaxChunkSize + 10)

	err := backend.set(t.Context(), "service", "account", secret)
	if err != nil {
		t.Fatalf("set() error = %v", err)
	}
	target, err := backend.target("service", "account")
	if err != nil {
		t.Fatalf("target() error = %v", err)
	}
	partTarget := backend.partTarget(target, 1)
	store.mu.Lock()
	store.items[partTarget] = store.items[partTarget][:1]
	store.mu.Unlock()

	_, err = backend.get(t.Context(), "service", "account")
	if !errors.Is(err, ErrTooLarge) {
		t.Fatalf("get() error = %v, want ErrTooLarge", err)
	}
}

func TestParseWindowsMultipartHeader(t *testing.T) {
	backend := newWindowsBackendFake()
	validHeader := func() []byte {
		header := make([]byte, 0, multipartHeaderLength)
		header = append(header, windowsMultipartMagic[:]...)
		header = binary.BigEndian.AppendUint32(header, 2)
		header = binary.BigEndian.AppendUint32(header, windowsMaxChunkSize+1)
		return header
	}
	tests := []struct {
		name string
		blob []byte
		ok   bool
	}{
		{name: "valid header", blob: validHeader(), ok: true},
		{name: "too short", blob: validHeader()[:multipartHeaderLength-1], ok: false},
		{name: "too long", blob: append(validHeader(), 0), ok: false},
		{name: "wrong magic", blob: append([]byte(strings.Repeat("x", multipartMagicLength)), validHeader()[multipartMagicLength:]...), ok: false},
		{name: "totalLen exceeds MaxSecretSize", blob: func() []byte {
			header := make([]byte, 0, multipartHeaderLength)
			header = append(header, windowsMultipartMagic[:]...)
			header = binary.BigEndian.AppendUint32(header, 1)
			header = binary.BigEndian.AppendUint32(header, MaxSecretSize+1)
			return header
		}(), ok: false},
		{name: "partCount exceeds windowsMaxParts", blob: func() []byte {
			header := make([]byte, 0, multipartHeaderLength)
			header = append(header, windowsMultipartMagic[:]...)
			header = binary.BigEndian.AppendUint32(header, windowsMaxParts+1)
			header = binary.BigEndian.AppendUint32(header, windowsMaxChunkSize+1)
			return header
		}(), ok: false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, ok := backend.parseMultipartHeader(test.blob)
			if ok != test.ok {
				t.Fatalf("parseWindowsMultipartHeader() ok = %v, want %v", ok, test.ok)
			}
		})
	}
}
