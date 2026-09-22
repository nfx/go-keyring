//go:build windows

package keyring

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"syscall"
	"testing"
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
