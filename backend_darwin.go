//go:build darwin

package keyring

import (
	"context"
	"fmt"
	"runtime"
	"unsafe"

	"github.com/ebitengine/purego"
)

const (
	errSecSuccess        int32  = 0
	errSecParam          int32  = -50
	errSecUserCanceled   int32  = -128
	errSecDuplicateItem  int32  = -25299
	errSecItemNotFound   int32  = -25300
	errSecAuthFailed     int32  = -25293
	errSecNotAvailable   int32  = -25291
	errSecInteractionNot int32  = -25308
	cfStringEncodingUTF8 uint32 = 0x08000100
)

type darwinBackend struct {
	security                  uintptr
	core                      uintptr
	cfDataCreate              func(uintptr, *byte, int64) uintptr
	cfDataGetBytePtr          func(uintptr) *byte
	cfDataGetLength           func(uintptr) int64
	cfDictionaryCreateMutable func(uintptr, int64, uintptr, uintptr) uintptr
	cfDictionarySetValue      func(uintptr, uintptr, uintptr)
	cfRelease                 func(uintptr)
	cfStringCreateWithBytes   func(uintptr, *byte, int64, uint32, uint8) uintptr
	secItemAdd                func(uintptr, *uintptr) int32
	secItemCopyMatching       func(uintptr, *uintptr) int32
	secItemDelete             func(uintptr) int32
	secItemUpdate             func(uintptr, uintptr) int32
	class                     uintptr
	classGenericPassword      uintptr
	attrAccount               uintptr
	attrService               uintptr
	returnData                uintptr
	valueData                 uintptr
	booleanTrue               uintptr
	dictionaryKeyCallbacks    uintptr
	dictionaryValueCallbacks  uintptr
}

type darwinDictionary struct {
	backend    *darwinBackend
	value      uintptr
	references []uintptr
}

// newBackend eagerly validates the dynamic frameworks and every symbol it uses.
func newBackend() (backend, error) {
	security, err := purego.Dlopen(
		"/System/Library/Frameworks/Security.framework/Security",
		purego.RTLD_NOW|purego.RTLD_LOCAL)
	if err != nil {
		return nil, fmt.Errorf("%w: open failed", ErrUnavailable)
	}
	core, err := purego.Dlopen(
		"/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation",
		purego.RTLD_NOW|purego.RTLD_LOCAL)
	if err != nil {
		closeErr := purego.Dlclose(security)
		_ = closeErr
		return nil, fmt.Errorf("%w: open failed", ErrUnavailable)
	}
	store := &darwinBackend{security: security, core: core}
	err = store.bind()
	if err != nil {
		_ = store.close()
		return nil, err
	}
	return store, nil
}

type binding struct {
	library uintptr
	symbol  string
	target  any
	bind    func(uintptr, string, any) error
}

// bind resolves functions and data symbols before exposing a partially initialized backend.
func (d *darwinBackend) bind() error {
	bindings := []binding{
		{d.core, "CFDataCreate", &d.cfDataCreate, d.bindFunction},
		{d.core, "CFDataGetBytePtr", &d.cfDataGetBytePtr, d.bindFunction},
		{d.core, "CFDataGetLength", &d.cfDataGetLength, d.bindFunction},
		{d.core, "CFDictionaryCreateMutable", &d.cfDictionaryCreateMutable, d.bindFunction},
		{d.core, "CFDictionarySetValue", &d.cfDictionarySetValue, d.bindFunction},
		{d.core, "CFRelease", &d.cfRelease, d.bindFunction},
		{d.core, "CFStringCreateWithBytes", &d.cfStringCreateWithBytes, d.bindFunction},
		{d.security, "SecItemAdd", &d.secItemAdd, d.bindFunction},
		{d.security, "SecItemCopyMatching", &d.secItemCopyMatching, d.bindFunction},
		{d.security, "SecItemDelete", &d.secItemDelete, d.bindFunction},
		{d.security, "SecItemUpdate", &d.secItemUpdate, d.bindFunction},
		{d.security, "kSecClass", &d.class, d.bindData},
		{d.security, "kSecClassGenericPassword", &d.classGenericPassword, d.bindData},
		{d.security, "kSecAttrAccount", &d.attrAccount, d.bindData},
		{d.security, "kSecAttrService", &d.attrService, d.bindData},
		{d.security, "kSecReturnData", &d.returnData, d.bindData},
		{d.security, "kSecValueData", &d.valueData, d.bindData},
		{d.core, "kCFBooleanTrue", &d.booleanTrue, d.bindData},
		{d.core, "kCFTypeDictionaryKeyCallBacks", &d.dictionaryKeyCallbacks, d.bindAddress},
		{d.core, "kCFTypeDictionaryValueCallBacks", &d.dictionaryValueCallbacks, d.bindAddress},
	}
	for _, b := range bindings {
		if err := b.bind(b.library, b.symbol, b.target); err != nil {
			return fmt.Errorf("%s: %w", b.symbol, err)
		}
	}
	return nil
}

// bindFunction resolves one C function and registers its Go call signature.
func (d *darwinBackend) bindFunction(library uintptr, symbol string, target any) error {
	pointer, err := purego.Dlsym(library, symbol)
	if err != nil {
		return fmt.Errorf("%w: open failed", ErrUnavailable)
	}
	purego.RegisterFunc(target, pointer)
	return nil
}

// bindData loads the CFTypeRef stored in an exported constant data symbol.
func (d *darwinBackend) bindData(library uintptr, symbol string, target any) error {
	pointer, err := purego.Dlsym(library, symbol)
	if err != nil {
		return fmt.Errorf("%w: open failed", ErrUnavailable)
	}
	*target.(*uintptr) = *(*uintptr)(unsafe.Pointer(pointer))
	return nil
}

// bindAddress stores an exported Core Foundation callback-structure address.
func (d *darwinBackend) bindAddress(library uintptr, symbol string, target any) error {
	pointer, err := purego.Dlsym(library, symbol)
	if err != nil {
		return fmt.Errorf("%w: open failed", ErrUnavailable)
	}
	*target.(*uintptr) = pointer
	return nil
}

// set updates an item, adding it only when its lookup key is absent.
func (d *darwinBackend) set(_ context.Context, service string, account string, secret []byte) error {
	query := d.newDictionary(service, account, nil, false)
	defer query.release()
	attributes := d.newDictionary("", "", secret, false)
	defer attributes.release()
	status := d.secItemUpdate(query.value, attributes.value)
	if status == errSecSuccess {
		return nil
	}
	if status != errSecItemNotFound {
		return d.statusError("set", status)
	}
	item := d.newDictionary(service, account, secret, false)
	defer item.release()
	status = d.secItemAdd(item.value, nil)
	if status == errSecDuplicateItem {
		status = d.secItemUpdate(query.value, attributes.value)
	}
	return d.statusError("set", status)
}

// get copies the immutable CFData result into caller-owned Go memory.
func (d *darwinBackend) get(_ context.Context, service string, account string) ([]byte, error) {
	query := d.newDictionary(service, account, nil, true)
	defer query.release()
	var result uintptr
	status := d.secItemCopyMatching(query.value, &result)
	if status != errSecSuccess {
		return nil, d.statusError("get", status)
	}
	defer d.cfRelease(result)
	length := d.cfDataGetLength(result)
	if length < 0 || length > MaxSecretSize {
		return nil, ErrTooLarge
	}
	secret := make([]byte, int(length))
	if length == 0 {
		return secret, nil
	}
	copy(secret, unsafe.Slice(d.cfDataGetBytePtr(result), int(length)))
	return secret, nil
}

// delete removes the exact generic-password item and normalizes absence to success.
func (d *darwinBackend) delete(_ context.Context, service string, account string) error {
	query := d.newDictionary(service, account, nil, false)
	defer query.release()
	status := d.secItemDelete(query.value)
	if status == errSecItemNotFound {
		return nil
	}
	return d.statusError("delete", status)
}

// close balances the two framework loads performed during Open.
func (d *darwinBackend) close() error {
	coreErr := purego.Dlclose(d.core)
	securityErr := purego.Dlclose(d.security)
	if coreErr != nil || securityErr != nil {
		return fmt.Errorf("%w: close failed", ErrUnavailable)
	}
	return nil
}

// newDictionary builds the Core Foundation dictionary required by Security.framework.
func (d *darwinBackend) newDictionary(service string, account string, secret []byte, returnData bool) darwinDictionary {
	result := darwinDictionary{backend: d}
	result.value = d.cfDictionaryCreateMutable(0, 0, d.dictionaryKeyCallbacks, d.dictionaryValueCallbacks)
	if service != "" {
		result.set(d.class, d.classGenericPassword)
		result.setString(d.attrService, service)
	}
	if account != "" {
		result.setString(d.attrAccount, account)
	}
	if secret != nil {
		result.setData(d.valueData, secret)
	}
	if returnData {
		result.set(d.returnData, d.booleanTrue)
	}
	return result
}

// set adds an existing Core Foundation object to a temporary dictionary.
func (d *darwinDictionary) set(key uintptr, value uintptr) {
	d.backend.cfDictionarySetValue(d.value, key, value)
}

// setString creates and retains a CFString until its temporary dictionary is released.
func (d *darwinDictionary) setString(key uintptr, value string) {
	stringValue := d.backend.cfStringCreateWithBytes(0, unsafe.StringData(value), int64(len(value)), cfStringEncodingUTF8, 0)
	d.references = append(d.references, stringValue)
	d.set(key, stringValue)
	runtime.KeepAlive(value)
}

// setData creates a Core Foundation copy so Security never retains Go-backed secret memory.
func (d *darwinDictionary) setData(key uintptr, secret []byte) {
	data := d.backend.cfDataCreate(0, unsafe.SliceData(secret), int64(len(secret)))
	d.references = append(d.references, data)
	d.set(key, data)
	runtime.KeepAlive(secret)
}

// release balances all Core Foundation objects created for this dictionary.
func (d *darwinDictionary) release() {
	for _, reference := range d.references {
		d.backend.cfRelease(reference)
	}
	if d.value != 0 {
		d.backend.cfRelease(d.value)
	}
}

// statusError maps Security.framework status values without surfacing native text.
func (d *darwinBackend) statusError(operation string, status int32) error {
	if status == errSecSuccess {
		return nil
	}
	return fmt.Errorf("%w: %s failed (code %d)", d.sentinel(status), operation, status)
}

func (d *darwinBackend) sentinel(status int32) error {
	switch status {
	case errSecItemNotFound:
		return ErrNotFound
	case errSecParam:
		return ErrInvalid
	case errSecAuthFailed, errSecInteractionNot:
		return ErrDenied
	case errSecUserCanceled:
		return ErrCanceled
	case errSecNotAvailable:
		return ErrUnavailable
	default:
		return errUnrecognizedStatus
	}
}
