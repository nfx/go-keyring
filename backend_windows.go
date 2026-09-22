//go:build windows

package keyring

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"runtime"
	"syscall"
	"unsafe"
)

const (
	credTypeGeneric          uint32 = 1
	credPersistLocalMachine  uint32 = 2
	winErrorAccessDenied            = syscall.Errno(5)
	winErrorInvalidParameter        = syscall.Errno(87)
	winErrorNotFound                = syscall.Errno(1168)
	winErrorCanceled                = syscall.Errno(1223)
	winErrorNoLogonSession          = syscall.Errno(1312)
)

type windowsCredential struct {
	flags              uint32
	typeValue          uint32
	targetName         *uint16
	comment            *uint16
	lastWritten        windowsFiletime
	credentialBlobSize uint32
	credentialBlob     *byte
	persist            uint32
	attributeCount     uint32
	attributes         unsafe.Pointer
	targetAlias        *uint16
	userName           *uint16
}

type windowsFiletime struct {
	lowDateTime  uint32
	highDateTime uint32
}

type windowsBackend struct {
	closeDLL   func() error
	credWrite  func(*windowsCredential) (bool, error)
	credRead   func(*uint16, **windowsCredential) (bool, error)
	credDelete func(*uint16) (bool, error)
	credFree   func(*windowsCredential)
}

// newBackend securely loads Credential Manager entry points from System32.
func newBackend() (backend, error) {
	// syscall registers advapi32.dll as a System32-only DLL before LoadDLL runs.
	advapi, err := syscall.LoadDLL("advapi32.dll")
	if err != nil {
		return nil, fmt.Errorf("%w: open failed", ErrUnavailable)
	}
	store := &windowsBackend{
		closeDLL: advapi.Release,
	}
	err = store.bindProcedures(advapi)
	if err != nil {
		_ = advapi.Release()
		return nil, fmt.Errorf("%w: open failed", ErrUnavailable)
	}
	return store, nil
}

// bindProcedures validates every native API before Open succeeds.
func (w *windowsBackend) bindProcedures(advapi *syscall.DLL) error {
	credWrite, err := advapi.FindProc("CredWriteW")
	if err != nil {
		return err
	}
	credRead, err := advapi.FindProc("CredReadW")
	if err != nil {
		return err
	}
	credDelete, err := advapi.FindProc("CredDeleteW")
	if err != nil {
		return err
	}
	credFree, err := advapi.FindProc("CredFree")
	if err != nil {
		return err
	}
	w.credWrite = func(credential *windowsCredential) (bool, error) {
		result, _, callErr := credWrite.Call(uintptr(unsafe.Pointer(credential)), 0)
		return result != 0, callErr
	}
	w.credRead = func(targetName *uint16, credential **windowsCredential) (bool, error) {
		result, _, callErr := credRead.Call(
			uintptr(unsafe.Pointer(targetName)),
			uintptr(credTypeGeneric),
			0,
			uintptr(unsafe.Pointer(credential)),
		)
		return result != 0, callErr
	}
	w.credDelete = func(targetName *uint16) (bool, error) {
		result, _, callErr := credDelete.Call(uintptr(unsafe.Pointer(targetName)), uintptr(credTypeGeneric), 0)
		return result != 0, callErr
	}
	w.credFree = func(credential *windowsCredential) {
		_, _, _ = credFree.Call(uintptr(unsafe.Pointer(credential)))
	}
	return nil
}

// set writes a generic credential whose target is a case-sensitive logical-key digest.
func (w *windowsBackend) set(_ context.Context, service string, account string, secret []byte) error {
	target, err := w.target(service, account)
	if err != nil {
		return err
	}
	targetName, err := syscall.UTF16PtrFromString(target)
	if err != nil {
		return ErrInvalid
	}
	comment, err := syscall.UTF16PtrFromString(service)
	if err != nil {
		return ErrInvalid
	}
	userName, err := syscall.UTF16PtrFromString(account)
	if err != nil {
		return ErrInvalid
	}

	credential := windowsCredential{
		typeValue:          credTypeGeneric,
		targetName:         targetName,
		comment:            comment,
		credentialBlobSize: uint32(len(secret)),
		persist:            credPersistLocalMachine,
		userName:           userName,
	}
	if len(secret) > 0 {
		credential.credentialBlob = unsafe.SliceData(secret)
	}
	succeeded, callErr := w.credWrite(&credential)
	runtime.KeepAlive(secret)
	runtime.KeepAlive(credential)
	if succeeded {
		return nil
	}
	return w.callError("set", callErr)
}

// get copies the native credential blob before wiping it and freeing its one allocation.
func (w *windowsBackend) get(_ context.Context, service string, account string) ([]byte, error) {
	target, err := w.target(service, account)
	if err != nil {
		return nil, err
	}
	targetName, err := syscall.UTF16PtrFromString(target)
	if err != nil {
		return nil, ErrInvalid
	}

	var credential *windowsCredential
	succeeded, callErr := w.credRead(targetName, &credential)
	runtime.KeepAlive(targetName)
	if !succeeded {
		return nil, w.callError("get", callErr)
	}
	defer w.freeCredential(credential)
	if credential.credentialBlobSize > MaxSecretSize {
		return nil, ErrTooLarge
	}

	secret := make([]byte, int(credential.credentialBlobSize))
	if credential.credentialBlobSize == 0 {
		return secret, nil
	}
	copy(secret, unsafe.Slice(credential.credentialBlob, int(credential.credentialBlobSize)))
	return secret, nil
}

// delete removes one generic credential and treats a missing target as already deleted.
func (w *windowsBackend) delete(_ context.Context, service string, account string) error {
	target, err := w.target(service, account)
	if err != nil {
		return err
	}
	targetName, err := syscall.UTF16PtrFromString(target)
	if err != nil {
		return ErrInvalid
	}
	succeeded, callErr := w.credDelete(targetName)
	runtime.KeepAlive(targetName)
	if succeeded {
		return nil
	}
	if errors.Is(callErr, winErrorNotFound) {
		return nil
	}
	return w.callError("delete", callErr)
}

// close releases the eagerly loaded Credential Manager DLL.
func (w *windowsBackend) close() error {
	err := w.closeDLL()
	if err != nil {
		return fmt.Errorf("%w: close failed", ErrUnavailable)
	}
	return nil
}

// target derives a target name that preserves case-sensitive logical namespaces.
func (w *windowsBackend) target(service string, account string) (string, error) {
	if validateIdentifier(service) != nil || validateIdentifier(account) != nil {
		return "", ErrInvalid
	}

	hash := sha256.New()
	w.writeIdentifier(hash, service)
	w.writeIdentifier(hash, account)
	return "github.com/nfx/go-keyring/" + hex.EncodeToString(hash.Sum(nil)), nil
}

// writeIdentifier adds a length-prefixed identifier so tuple boundaries are unambiguous.
func (w *windowsBackend) writeIdentifier(hash interface{ Write([]byte) (int, error) }, identifier string) {
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(identifier)))
	_, _ = hash.Write(length[:])
	_, _ = hash.Write([]byte(identifier))
}

// freeCredential wipes a valid native blob before CredFree releases its containing allocation.
func (w *windowsBackend) freeCredential(credential *windowsCredential) {
	if credential.credentialBlobSize > 0 && credential.credentialBlobSize <= MaxSecretSize {
		Wipe(unsafe.Slice(credential.credentialBlob, int(credential.credentialBlobSize)))
	}
	w.credFree(credential)
}

// callError maps Win32 failures while retaining only a numeric platform code for diagnosis.
func (w *windowsBackend) callError(operation string, callErr error) error {
	var errno syscall.Errno
	if !errors.As(callErr, &errno) {
		return fmt.Errorf("%w: %s failed", ErrUnavailable, operation)
	}
	return fmt.Errorf("%w: %s failed (code %d)", w.sentinel(errno), operation, errno)
}

func (w *windowsBackend) sentinel(errno syscall.Errno) error {
	switch errno {
	case winErrorNotFound:
		return ErrNotFound
	case winErrorAccessDenied:
		return ErrDenied
	case winErrorCanceled:
		return ErrCanceled
	case winErrorInvalidParameter:
		return ErrInvalid
	case winErrorNoLogonSession:
		return ErrUnavailable
	default:
		return errUnrecognizedStatus
	}
}
