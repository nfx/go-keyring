//go:build linux

package keyring

import (
	"context"
	"errors"
	"testing"
	"unsafe"
)

type linuxTestTokens struct {
	service     byte
	hashTable   byte
	cancellable byte
	item        byte
	secondItem  byte
	value       byte
}

func TestLinuxBackendGet_copiesBinarySecret(t *testing.T) {
	secret := []byte{0, 255, 1}
	tokens := linuxTestTokens{}
	itemsReleased := 0
	valuesReleased := 0
	backend := newLinuxTestBackend(&tokens, &linuxGList{data: unsafe.Pointer(&tokens.item)}, secret)
	backend.api.gObjectUnref = func(pointer unsafe.Pointer) {
		if pointer == unsafe.Pointer(&tokens.item) {
			itemsReleased++
		}
	}
	backend.api.secretValueUnref = func(unsafe.Pointer) { valuesReleased++ }

	result, err := backend.get(context.Background(), "service", "account")
	if err != nil {
		t.Fatalf("get() error = %v", err)
	}
	if string(result) != string(secret) {
		t.Fatalf("get() = %v, want %v", result, secret)
	}
	result[0] = 9
	if secret[0] != 0 {
		t.Fatalf("get() returned native storage")
	}
	if itemsReleased != 1 || valuesReleased != 1 {
		t.Fatalf("releases = items %d, values %d; want 1, 1", itemsReleased, valuesReleased)
	}
}

func TestLinuxBackendGet_rejectsDuplicateMatches(t *testing.T) {
	tokens := linuxTestTokens{}
	list := &linuxGList{data: unsafe.Pointer(&tokens.item)}
	list.next = &linuxGList{data: unsafe.Pointer(&tokens.secondItem)}
	backend := newLinuxTestBackend(&tokens, list, []byte("secret"))

	_, err := backend.get(context.Background(), "service", "account")
	if !errors.Is(err, errUnrecognizedStatus) {
		t.Fatalf("get() error = %v, want errUnrecognizedStatus", err)
	}
}

func TestLinuxBackendDelete_releasesEveryCancellableAndItem(t *testing.T) {
	tokens := linuxTestTokens{}
	list := &linuxGList{data: unsafe.Pointer(&tokens.item)}
	list.next = &linuxGList{data: unsafe.Pointer(&tokens.secondItem)}
	backend := newLinuxTestBackend(&tokens, list, []byte("secret"))
	deleted := 0
	unrefs := 0
	backend.api.secretItemDeleteSync = func(unsafe.Pointer, unsafe.Pointer, *unsafe.Pointer) int32 {
		deleted++
		return 1
	}
	backend.api.gObjectUnref = func(unsafe.Pointer) { unrefs++ }

	err := backend.delete(context.Background(), "service", "account")
	if err != nil {
		t.Fatalf("delete() error = %v", err)
	}
	if deleted != 2 {
		t.Fatalf("delete calls = %d, want 2", deleted)
	}
	if unrefs != 4 {
		t.Fatalf("g_object_unref calls = %d, want 4", unrefs)
	}
}

func TestLinuxAPI_nativeErrorMapsStableCodes(t *testing.T) {
	api := &linuxAPI{
		gIOErrorQuark:    func() uint32 { return 1 },
		secretErrorQuark: func() uint32 { return 2 },
	}
	cases := []struct {
		domain uint32
		code   int32
		want   error
	}{
		{1, linuxIOErrorNotFound, ErrNotFound},
		{1, linuxIOErrorPermissionDenied, ErrDenied},
		{1, linuxIOErrorCancelled, ErrCanceled},
		{2, linuxSecretErrorIsLocked, ErrDenied},
		{2, linuxSecretErrorNoSuchObject, ErrNotFound},
	}
	for _, testCase := range cases {
		err := api.nativeError("test", testCase.domain, testCase.code)
		if !errors.Is(err, testCase.want) {
			t.Fatalf("nativeError(%d, %d) = %v, want %v", testCase.domain, testCase.code, err, testCase.want)
		}
	}
}

// newLinuxTestBackend returns a complete fake ABI table for orchestration tests without libsecret.
func newLinuxTestBackend(tokens *linuxTestTokens, list *linuxGList, secret []byte) *linuxBackend {
	api := &linuxAPI{}
	api.gHashTableNewFull = func(unsafe.Pointer, unsafe.Pointer, unsafe.Pointer, unsafe.Pointer) unsafe.Pointer {
		return unsafe.Pointer(&tokens.hashTable)
	}
	api.gHashTableInsert = func(unsafe.Pointer, unsafe.Pointer, unsafe.Pointer) int32 { return 1 }
	api.gHashTableDestroy = func(unsafe.Pointer) {}
	api.gStrdup = func(*byte) unsafe.Pointer { return unsafe.Pointer(&tokens.hashTable) }
	api.gFree = func(unsafe.Pointer) {}
	api.gListFree = func(*linuxGList) {}
	api.gObjectUnref = func(unsafe.Pointer) {}
	api.gCancellableNew = func() unsafe.Pointer { return unsafe.Pointer(&tokens.cancellable) }
	api.gCancellableCancel = func(unsafe.Pointer) {}
	api.secretServiceSearchSync = func(unsafe.Pointer, unsafe.Pointer, unsafe.Pointer, uint32, unsafe.Pointer, *unsafe.Pointer) *linuxGList {
		return list
	}
	api.secretItemGetLocked = func(unsafe.Pointer) int32 { return 0 }
	api.secretItemGetSecret = func(unsafe.Pointer) unsafe.Pointer { return unsafe.Pointer(&tokens.value) }
	api.secretValueGet = func(_ unsafe.Pointer, length *uintptr) *byte {
		*length = uintptr(len(secret))
		return unsafe.SliceData(secret)
	}
	api.secretValueUnref = func(unsafe.Pointer) {}
	api.secretItemDeleteSync = func(unsafe.Pointer, unsafe.Pointer, *unsafe.Pointer) int32 { return 1 }
	return &linuxBackend{api: api, service: unsafe.Pointer(&tokens.service)}
}
