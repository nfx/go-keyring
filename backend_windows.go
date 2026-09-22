//go:build windows

package keyring

import (
	"bytes"
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

	// windowsMaxChunkSize bounds every individual credential this backend writes, well under
	// Credential Manager's native per-entry limit. Secrets above it are split across numbered
	// parts named target_p01, target_p02, ... behind a magic-tagged header credential.
	windowsMaxChunkSize   = 2028
	multipartMagicText    = "go-keyring://multipart"
	multipartMagicLength  = len(multipartMagicText)
	multipartHeaderLength = multipartMagicLength + 8 // magic + partCount(4) + totalLen(4)
	windowsMaxParts       = (MaxSecretSize + windowsMaxChunkSize - 1) / windowsMaxChunkSize
)

// windowsMultipartMagic tags a credential as a multipart header rather than raw secret bytes.
var windowsMultipartMagic = [multipartMagicLength]byte([]byte(multipartMagicText))

// windowsMultipartHeader records how many numbered parts follow and their combined length.
type windowsMultipartHeader struct {
	partCount uint32
	totalLen  uint32
}

// parseMultipartHeader recognizes the fixed-size, magic-tagged, bounds-checked header this
// backend writes ahead of numbered parts; any other shape is treated as a raw secret.
func (w *windowsBackend) parseMultipartHeader(blob []byte) (windowsMultipartHeader, bool) {
	if len(blob) != multipartHeaderLength {
		return windowsMultipartHeader{}, false
	}
	if !bytes.Equal(blob[:multipartMagicLength], windowsMultipartMagic[:]) {
		return windowsMultipartHeader{}, false
	}
	header := windowsMultipartHeader{
		partCount: binary.BigEndian.Uint32(blob[multipartMagicLength:]),
		totalLen:  binary.BigEndian.Uint32(blob[multipartMagicLength+4:]),
	}
	if header.totalLen > MaxSecretSize || header.partCount > windowsMaxParts {
		return windowsMultipartHeader{}, false
	}
	return header, true
}

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

// set writes secret under a case-sensitive logical-key digest, splitting it across numbered part
// credentials behind a magic-tagged header when it exceeds windowsChunkSize, and removes any
// parts a shorter earlier write left behind.
func (w *windowsBackend) set(_ context.Context, service string, account string, secret []byte) error {
	target, err := w.target(service, account)
	if err != nil {
		return err
	}
	previousParts := w.previousPartCount(target)
	newParts, err := w.writeSecret(target, service, account, secret)
	if err != nil {
		return err
	}
	return w.deleteStaleParts(target, newParts, previousParts)
}

// writeSecret writes secret as one credential when it fits in a chunk, otherwise as a header
// credential plus numbered parts, and reports how many parts it wrote.
func (w *windowsBackend) writeSecret(target string, service string, account string, secret []byte) (int, error) {
	if len(secret) <= windowsMaxChunkSize {
		return 0, w.writeCredential(target, service, account, secret)
	}
	partCount := (len(secret) + windowsMaxChunkSize - 1) / windowsMaxChunkSize
	return partCount, w.writeParts(target, service, account, secret, partCount)
}

// writeParts writes the magic-tagged header followed by fixed-size chunks under numbered target
// suffixes so the read path can recognize and reassemble them.
func (w *windowsBackend) writeParts(target string, service string, account string, secret []byte, partCount int) error {
	header := make([]byte, 0, multipartHeaderLength)
	header = append(header, windowsMultipartMagic[:]...)
	header = binary.BigEndian.AppendUint32(header, uint32(partCount))
	header = binary.BigEndian.AppendUint32(header, uint32(len(secret)))
	err := w.writeCredential(target, service, account, header)
	if err != nil {
		return err
	}
	for part := 1; part <= partCount; part++ {
		start := (part - 1) * windowsMaxChunkSize
		end := min(start+windowsMaxChunkSize, len(secret))
		err = w.writeCredential(w.partTarget(target, part), service, account, secret[start:end])
		if err != nil {
			return err
		}
	}
	return nil
}

// previousPartCount reports how many numbered parts an earlier write left behind, or 0 if target
// does not exist or does not hold a multipart header.
func (w *windowsBackend) previousPartCount(target string) int {
	header, ok := w.readHeader(target)
	if !ok {
		return 0
	}
	return int(header.partCount)
}

// deleteStaleParts removes numbered parts a previous, larger write left behind when the current
// write needs fewer of them.
func (w *windowsBackend) deleteStaleParts(target string, newParts int, previousParts int) error {
	for part := newParts + 1; part <= previousParts; part++ {
		err := w.deleteOne(w.partTarget(target, part))
		if err != nil {
			return err
		}
	}
	return nil
}

// writeCredential upserts one native generic credential holding blob.
func (w *windowsBackend) writeCredential(target string, service string, account string, blob []byte) error {
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
		credentialBlobSize: uint32(len(blob)),
		persist:            credPersistLocalMachine,
		userName:           userName,
	}
	if len(blob) > 0 {
		credential.credentialBlob = unsafe.SliceData(blob)
	}
	succeeded, callErr := w.credWrite(&credential)
	runtime.KeepAlive(blob)
	runtime.KeepAlive(credential)
	if succeeded {
		return nil
	}
	return w.callError("set", callErr)
}

// get returns a raw single credential, or reassembles one split across numbered parts behind a
// magic-tagged header.
func (w *windowsBackend) get(_ context.Context, service string, account string) ([]byte, error) {
	target, err := w.target(service, account)
	if err != nil {
		return nil, err
	}
	blob, err := w.readCredential(target)
	if err != nil {
		return nil, err
	}
	header, ok := w.parseMultipartHeader(blob)
	if !ok {
		return blob, nil
	}
	Wipe(blob)
	return w.readParts(target, header)
}

// readParts reassembles a secret from its numbered part credentials and checks the length the
// header recorded.
func (w *windowsBackend) readParts(target string, header windowsMultipartHeader) ([]byte, error) {
	secret := make([]byte, 0, header.totalLen)
	for part := 1; part <= int(header.partCount); part++ {
		chunk, err := w.readCredential(w.partTarget(target, part))
		if err != nil {
			return nil, err
		}
		secret = append(secret, chunk...)
		Wipe(chunk)
	}
	if uint32(len(secret)) != header.totalLen {
		Wipe(secret)
		return nil, ErrTooLarge
	}
	return secret, nil
}

// readHeader reads target's credential and reports whether it holds a valid multipart header.
func (w *windowsBackend) readHeader(target string) (windowsMultipartHeader, bool) {
	blob, err := w.readCredential(target)
	if err != nil {
		return windowsMultipartHeader{}, false
	}
	defer Wipe(blob)
	return w.parseMultipartHeader(blob)
}

// readCredential returns a caller-owned copy of one native credential blob, wiping the native
// copy before CredFree releases its allocation.
func (w *windowsBackend) readCredential(target string) ([]byte, error) {
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
	blob := make([]byte, int(credential.credentialBlobSize))
	if credential.credentialBlobSize == 0 {
		return blob, nil
	}
	copy(blob, unsafe.Slice(credential.credentialBlob, int(credential.credentialBlobSize)))
	return blob, nil
}

// delete removes a credential and, if it held a multipart header, its numbered parts too, and
// treats a missing target as already deleted.
func (w *windowsBackend) delete(_ context.Context, service string, account string) error {
	target, err := w.target(service, account)
	if err != nil {
		return err
	}
	header, ok := w.readHeader(target)
	if ok {
		err = w.deleteParts(target, header)
		if err != nil {
			return err
		}
	}
	return w.deleteOne(target)
}

// deleteParts removes every numbered part credential a header describes.
func (w *windowsBackend) deleteParts(target string, header windowsMultipartHeader) error {
	for part := 1; part <= int(header.partCount); part++ {
		err := w.deleteOne(w.partTarget(target, part))
		if err != nil {
			return err
		}
	}
	return nil
}

// deleteOne removes one native credential and treats a missing target as already deleted.
func (w *windowsBackend) deleteOne(target string) error {
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

// partTarget derives the target name of one numbered part credential.
func (w *windowsBackend) partTarget(target string, part int) string {
	return fmt.Sprintf("%s_p%02d", target, part)
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
