//go:build darwin

package keyring

import (
	"context"
	"errors"
	"testing"
	"unsafe"
)

type darwinBackendFake struct {
	next           uintptr
	dictionaries   map[uintptr]map[uintptr]uintptr
	released       []uintptr
	updateStatuses []int32
	addStatuses    []int32
	updateCalls    int
	addCalls       int
	copyStatus     int32
	copyResult     uintptr
	deleteStatus   int32
	data           []byte
}

// newDarwinBackendFake returns an FFI-free backend whose calls and CF ownership are observable.
func newDarwinBackendFake() (*darwinBackend, *darwinBackendFake) {
	fake := &darwinBackendFake{next: 100, dictionaries: make(map[uintptr]map[uintptr]uintptr)}
	backend := &darwinBackend{
		class:                    1,
		classGenericPassword:     2,
		attrAccount:              3,
		attrService:              4,
		returnData:               5,
		valueData:                6,
		booleanTrue:              7,
		dictionaryKeyCallbacks:   8,
		dictionaryValueCallbacks: 9,
	}
	backend.cfDictionaryCreateMutable = fake.newDictionary
	backend.cfDictionarySetValue = fake.setDictionaryValue
	backend.cfStringCreateWithBytes = fake.newString
	backend.cfDataCreate = fake.newData
	backend.cfDataGetLength = fake.dataLength
	backend.cfDataGetBytePtr = fake.dataPointer
	backend.cfRelease = fake.release
	backend.secItemUpdate = fake.update
	backend.secItemAdd = fake.add
	backend.secItemCopyMatching = fake.copyMatching
	backend.secItemDelete = fake.delete
	return backend, fake
}

func (f *darwinBackendFake) newDictionary(_ uintptr, _ int64, _ uintptr, _ uintptr) uintptr {
	handle := f.newHandle()
	f.dictionaries[handle] = make(map[uintptr]uintptr)
	return handle
}

func (f *darwinBackendFake) setDictionaryValue(dictionary uintptr, key uintptr, value uintptr) {
	f.dictionaries[dictionary][key] = value
}

func (f *darwinBackendFake) newString(_ uintptr, _ *byte, _ int64, _ uint32, _ uint8) uintptr {
	return f.newHandle()
}

func (f *darwinBackendFake) newData(_ uintptr, data *byte, length int64) uintptr {
	if length > 0 {
		f.data = append(f.data[:0], unsafe.Slice(data, int(length))...)
	}
	return f.newHandle()
}

func (f *darwinBackendFake) dataLength(_ uintptr) int64 {
	return int64(len(f.data))
}

func (f *darwinBackendFake) dataPointer(_ uintptr) *byte {
	return unsafe.SliceData(f.data)
}

func (f *darwinBackendFake) release(value uintptr) {
	f.released = append(f.released, value)
}

func (f *darwinBackendFake) update(_ uintptr, _ uintptr) int32 {
	status := f.updateStatuses[f.updateCalls]
	f.updateCalls++
	return status
}

func (f *darwinBackendFake) add(_ uintptr, _ *uintptr) int32 {
	status := f.addStatuses[f.addCalls]
	f.addCalls++
	return status
}

func (f *darwinBackendFake) copyMatching(_ uintptr, result *uintptr) int32 {
	*result = f.copyResult
	return f.copyStatus
}

func (f *darwinBackendFake) delete(_ uintptr) int32 {
	return f.deleteStatus
}

func (f *darwinBackendFake) newHandle() uintptr {
	handle := f.next
	f.next++
	return handle
}

func TestDarwinStatusError_mapsNativeStatus(t *testing.T) {
	backend, _ := newDarwinBackendFake()
	cases := []struct {
		name   string
		status int32
		want   error
	}{
		{name: "missing", status: errSecItemNotFound, want: ErrNotFound},
		{name: "invalid", status: errSecParam, want: ErrInvalid},
		{name: "denied", status: errSecAuthFailed, want: ErrDenied},
		{name: "canceled", status: errSecUserCanceled, want: ErrCanceled},
		{name: "unavailable", status: errSecNotAvailable, want: ErrUnavailable},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			err := backend.statusError("get", test.status)
			if !errors.Is(err, test.want) {
				t.Fatalf("statusError(%d) = %v, want %v", test.status, err, test.want)
			}
		})
	}
}

func TestDarwinStatusError_unknownStatusIsNotUnavailable(t *testing.T) {
	backend, _ := newDarwinBackendFake()
	err := backend.statusError("get", -1)
	if errors.Is(err, ErrUnavailable) {
		t.Fatalf("statusError(-1) = %v, unexpectedly matches ErrUnavailable", err)
	}
}

func TestDarwinSet_updatesExistingItem(t *testing.T) {
	backend, fake := newDarwinBackendFake()
	fake.updateStatuses = []int32{errSecSuccess}
	secret := []byte{1, 2, 3}

	err := backend.set(context.Background(), "service", "account", secret)
	if err != nil {
		t.Fatalf("set() error = %v", err)
	}
	if fake.updateCalls != 1 || fake.addCalls != 0 {
		t.Fatalf("set() calls = update %d, add %d; want update 1, add 0", fake.updateCalls, fake.addCalls)
	}
	if string(fake.data) != string(secret) {
		t.Fatalf("set() data = %v, want %v", fake.data, secret)
	}
	if len(fake.released) != 5 {
		t.Fatalf("set() releases = %d, want 5", len(fake.released))
	}
}

func TestDarwinSet_retriesUpdateAfterDuplicateAdd(t *testing.T) {
	backend, fake := newDarwinBackendFake()
	fake.updateStatuses = []int32{errSecItemNotFound, errSecSuccess}
	fake.addStatuses = []int32{errSecDuplicateItem}

	err := backend.set(context.Background(), "service", "account", []byte("secret"))
	if err != nil {
		t.Fatalf("set() error = %v", err)
	}
	if fake.updateCalls != 2 || fake.addCalls != 1 {
		t.Fatalf("set() calls = update %d, add %d; want update 2, add 1", fake.updateCalls, fake.addCalls)
	}
	if len(fake.released) != 9 {
		t.Fatalf("set() releases = %d, want 9", len(fake.released))
	}
}

func TestDarwinGet_copiesNativeDataAndReleasesObjects(t *testing.T) {
	backend, fake := newDarwinBackendFake()
	fake.copyStatus = errSecSuccess
	fake.copyResult = 99
	fake.data = []byte{1, 2, 3}

	secret, err := backend.get(context.Background(), "service", "account")
	if err != nil {
		t.Fatalf("get() error = %v", err)
	}
	fake.data[0] = 9
	if string(secret) != string([]byte{1, 2, 3}) {
		t.Fatalf("get() returned aliased data: %v", secret)
	}
	if len(fake.released) != 4 {
		t.Fatalf("get() releases = %d, want 4", len(fake.released))
	}
}

func TestDarwinDelete_missingItemSucceeds(t *testing.T) {
	backend, fake := newDarwinBackendFake()
	fake.deleteStatus = errSecItemNotFound

	err := backend.delete(context.Background(), "service", "account")
	if err != nil {
		t.Fatalf("delete() error = %v, want nil", err)
	}
	if len(fake.released) != 3 {
		t.Fatalf("delete() releases = %d, want 3", len(fake.released))
	}
}
