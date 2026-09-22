//go:build linux

package keyring

import (
	"context"
	"errors"
	"fmt"
	"os"
	"runtime"
	"strings"
	"unsafe"

	"github.com/ebitengine/purego"
)

const (
	linuxServiceOpenSession      uint32 = 2
	linuxSearchAll               uint32 = 2
	linuxSearchUnlock            uint32 = 4
	linuxSearchLoadSecrets       uint32 = 8
	linuxIOErrorNotFound                = 1
	linuxIOErrorPermissionDenied        = 14
	linuxIOErrorCancelled               = 19
	linuxSecretErrorIsLocked            = 2
	linuxSecretErrorNoSuchObject        = 3

	linuxLibsecret  = "libsecret-1.so.0"
	linuxLibGLib    = "libglib-2.0.so.0"
	linuxLibGIO     = "libgio-2.0.so.0"
	linuxLibGObject = "libgobject-2.0.so.0"

	linuxDefaultCollection = "default"
	linuxContentType       = "application/octet-stream"
	linuxLabel             = "go-keyring"
)

type linuxGError struct {
	domain  uint32
	code    int32
	message *byte
}

type linuxGList struct {
	data unsafe.Pointer
	next *linuxGList
	prev *linuxGList
}

type linuxAPI struct {
	secretPtr                          uintptr
	glibPtr                            uintptr
	gioPtr                             uintptr
	gobjectPtr                         uintptr
	secretServiceGetType               func() uintptr
	secretServiceOpenSync              func(uintptr, *byte, uint32, unsafe.Pointer, *unsafe.Pointer) unsafe.Pointer
	secretServiceReadAliasDBusPathSync func(unsafe.Pointer, *byte, unsafe.Pointer, *unsafe.Pointer) *byte
	secretServiceStoreSync             func(unsafe.Pointer, unsafe.Pointer, unsafe.Pointer, *byte, *byte, unsafe.Pointer, unsafe.Pointer, *unsafe.Pointer) int32
	secretServiceSearchSync            func(unsafe.Pointer, unsafe.Pointer, unsafe.Pointer, uint32, unsafe.Pointer, *unsafe.Pointer) *linuxGList
	secretItemGetLocked                func(unsafe.Pointer) int32
	secretItemGetSecret                func(unsafe.Pointer) unsafe.Pointer
	secretItemDeleteSync               func(unsafe.Pointer, unsafe.Pointer, *unsafe.Pointer) int32
	secretValueNew                     func(*byte, int64, *byte) unsafe.Pointer
	secretValueGet                     func(unsafe.Pointer, *uintptr) *byte
	secretValueUnref                   func(unsafe.Pointer)
	gHashTableNewFull                  func(unsafe.Pointer, unsafe.Pointer, unsafe.Pointer, unsafe.Pointer) unsafe.Pointer
	gHashTableInsert                   func(unsafe.Pointer, unsafe.Pointer, unsafe.Pointer) int32
	gHashTableDestroy                  func(unsafe.Pointer)
	gStrdup                            func(*byte) unsafe.Pointer
	gFree                              func(unsafe.Pointer)
	gErrorFree                         func(unsafe.Pointer)
	gListFree                          func(*linuxGList)
	gObjectUnref                       func(unsafe.Pointer)
	gCancellableNew                    func() unsafe.Pointer
	gCancellableCancel                 func(unsafe.Pointer)
	gIOErrorQuark                      func() uint32
	secretErrorQuark                   func() uint32
	gFreePointer                       unsafe.Pointer
}

type linuxCString struct {
	api   *linuxAPI
	value unsafe.Pointer
}

// release returns ownership of a GLib-allocated string to its allocator.
func (s linuxCString) release() {
	if s.value != nil {
		s.api.gFree(s.value)
	}
}

type linuxAttributes struct {
	api   *linuxAPI
	value unsafe.Pointer
}

// release destroys the table and its GLib-owned keys and values.
func (a linuxAttributes) release() {
	if a.value != nil {
		a.api.gHashTableDestroy(a.value)
	}
}

type linuxCancellable struct {
	api   *linuxAPI
	value unsafe.Pointer
	stop  chan struct{}
	done  chan struct{}
}

// release stops cancellation before releasing the GObject it could otherwise race.
func (c linuxCancellable) release() {
	if c.stop != nil {
		close(c.stop)
		<-c.done
	}
	if c.value != nil {
		c.api.gObjectUnref(c.value)
	}
}

type linuxBinding struct {
	library uintptr
	symbol  string
	target  any
}

// newLinuxAPI opens versioned runtime libraries and resolves the complete ABI used by the backend.
func newLinuxAPI() (*linuxAPI, error) {
	api := &linuxAPI{}
	err := api.openLibraries()
	if err != nil {
		return nil, err
	}
	err = api.bind()
	if err != nil {
		_ = api.closeLibraries()
		return nil, err
	}
	return api, nil
}

// openLibraries loads only runtime SONAMEs so building needs neither headers nor link-time libraries.
func (a *linuxAPI) openLibraries() error {
	libraries := []struct {
		pointer *uintptr
		name    string
	}{
		{&a.secretPtr, linuxLibsecret},
		{&a.glibPtr, linuxLibGLib},
		{&a.gioPtr, linuxLibGIO},
		{&a.gobjectPtr, linuxLibGObject},
	}
	for _, library := range libraries {
		pointer, err := purego.Dlopen(library.name, purego.RTLD_NOW|purego.RTLD_LOCAL)
		if err != nil {
			_ = a.closeLibraries()
			return fmt.Errorf("%w: open failed", ErrUnavailable)
		}
		*library.pointer = pointer
	}
	return nil
}

// closeLibraries balances a complete or partial library load in reverse dependency order.
func (a *linuxAPI) closeLibraries() error {
	failed := false
	for _, library := range []uintptr{a.gobjectPtr, a.gioPtr, a.glibPtr, a.secretPtr} {
		if library != 0 && purego.Dlclose(library) != nil {
			failed = true
		}
	}
	a.secretPtr = 0
	a.glibPtr = 0
	a.gioPtr = 0
	a.gobjectPtr = 0
	if failed {
		return fmt.Errorf("%w: close failed", ErrUnavailable)
	}
	return nil
}

// bind resolves every required stable libsecret and GLib symbol before Open can succeed.
func (a *linuxAPI) bind() error {
	bindings := []linuxBinding{
		{a.secretPtr, "secret_service_get_type", &a.secretServiceGetType},
		{a.secretPtr, "secret_service_open_sync", &a.secretServiceOpenSync},
		{a.secretPtr, "secret_service_read_alias_dbus_path_sync", &a.secretServiceReadAliasDBusPathSync},
		{a.secretPtr, "secret_service_store_sync", &a.secretServiceStoreSync},
		{a.secretPtr, "secret_service_search_sync", &a.secretServiceSearchSync},
		{a.secretPtr, "secret_item_get_locked", &a.secretItemGetLocked},
		{a.secretPtr, "secret_item_get_secret", &a.secretItemGetSecret},
		{a.secretPtr, "secret_item_delete_sync", &a.secretItemDeleteSync},
		{a.secretPtr, "secret_value_new", &a.secretValueNew},
		{a.secretPtr, "secret_value_get", &a.secretValueGet},
		{a.secretPtr, "secret_value_unref", &a.secretValueUnref},
		{a.secretPtr, "secret_error_get_quark", &a.secretErrorQuark},
		{a.glibPtr, "g_hash_table_new_full", &a.gHashTableNewFull},
		{a.glibPtr, "g_hash_table_insert", &a.gHashTableInsert},
		{a.glibPtr, "g_hash_table_destroy", &a.gHashTableDestroy},
		{a.glibPtr, "g_strdup", &a.gStrdup},
		{a.glibPtr, "g_free", &a.gFree},
		{a.glibPtr, "g_error_free", &a.gErrorFree},
		{a.glibPtr, "g_list_free", &a.gListFree},
		{a.gioPtr, "g_cancellable_new", &a.gCancellableNew},
		{a.gioPtr, "g_cancellable_cancel", &a.gCancellableCancel},
		{a.gioPtr, "g_io_error_quark", &a.gIOErrorQuark},
		{a.gobjectPtr, "g_object_unref", &a.gObjectUnref},
	}
	for _, binding := range bindings {
		err := a.bindFunction(binding)
		if err != nil {
			return err
		}
	}
	pointer, err := purego.Dlsym(a.glibPtr, "g_free")
	if err != nil {
		return fmt.Errorf("%w: g_free unavailable", ErrUnavailable)
	}
	a.gFreePointer = unsafe.Pointer(pointer)
	return nil
}

// bindFunction registers one native call signature without retaining Go pointers in native code.
func (a *linuxAPI) bindFunction(binding linuxBinding) error {
	pointer, err := purego.Dlsym(binding.library, binding.symbol)
	if err != nil {
		return fmt.Errorf("%w: %s unavailable", ErrUnavailable, binding.symbol)
	}
	purego.RegisterFunc(binding.target, pointer)
	return nil
}

type linuxBackend struct {
	api     *linuxAPI
	service unsafe.Pointer
}

// newBackend opens an independent Secret Service session after validating Linux runtime prerequisites.
func newBackend() (backend, error) {
	err := validateLinuxSessionBus()
	if err != nil {
		return nil, err
	}
	api, err := newLinuxAPI()
	if err != nil {
		return nil, err
	}
	store, err := newLinuxBackend(api)
	if err != nil {
		_ = api.closeLibraries()
		return nil, err
	}
	return store, nil
}

// newLinuxBackend opens and verifies the default collection without creating one.
func newLinuxBackend(api *linuxAPI) (*linuxBackend, error) {
	var nativeError unsafe.Pointer
	service := api.secretServiceOpenSync(api.secretServiceGetType(), nil, linuxServiceOpenSession, nil, &nativeError)
	if service == nil {
		return nil, api.operationError("open", context.Background(), nativeError)
	}
	store := &linuxBackend{api: api, service: service}
	err := store.verifyDefaultCollection()
	if err != nil {
		store.releaseService()
		return nil, err
	}
	return store, nil
}

// validateLinuxSessionBus rejects explicitly configured non-local D-Bus transports.
func validateLinuxSessionBus() error {
	address, configured := os.LookupEnv("DBUS_SESSION_BUS_ADDRESS")
	if !configured {
		return nil
	}
	for _, entry := range strings.Split(address, ";") {
		if !strings.HasPrefix(entry, "unix:") {
			return ErrUnavailable
		}
	}
	return nil
}

// verifyDefaultCollection confirms the provider exposes the default alias without creating state.
func (l *linuxBackend) verifyDefaultCollection() error {
	alias := l.newCString(linuxDefaultCollection)
	defer alias.release()
	var nativeError unsafe.Pointer
	path := l.api.secretServiceReadAliasDBusPathSync(l.service, (*byte)(alias.value), nil, &nativeError)
	if path != nil {
		l.api.gFree(unsafe.Pointer(path))
		return nil
	}
	return l.api.operationError("open", context.Background(), nativeError)
}

// set stores a binary SecretValue, replacing an item with equal service and account attributes.
func (l *linuxBackend) set(ctx context.Context, service string, account string, secret []byte) error {
	attributes := l.newAttributes(service, account)
	defer attributes.release()
	value := l.newSecretValue(secret)
	if value == nil {
		return fmt.Errorf("%w: set failed", ErrUnavailable)
	}
	defer l.api.secretValueUnref(value)
	collection := l.newCString(linuxDefaultCollection)
	defer collection.release()
	label := l.newCString(linuxLabel)
	defer label.release()
	cancellable := l.newCancellable(ctx)
	defer cancellable.release()
	var nativeError unsafe.Pointer
	success := l.api.secretServiceStoreSync(l.service, nil, attributes.value, (*byte)(collection.value), (*byte)(label.value), value, cancellable.value, &nativeError)
	runtime.KeepAlive(secret)
	if success != 0 {
		return nil
	}
	return l.api.operationError("set", ctx, nativeError)
}

// get loads one exact matching item, rejecting duplicate or still-locked matches.
func (l *linuxBackend) get(ctx context.Context, service string, account string) ([]byte, error) {
	list, err := l.search(ctx, service, account, linuxSearchAll|linuxSearchUnlock|linuxSearchLoadSecrets)
	if err != nil {
		return nil, err
	}
	defer l.releaseItems(list)
	item, err := l.singleItem(list)
	if err != nil {
		return nil, err
	}
	if l.api.secretItemGetLocked(item) != 0 {
		return nil, ErrDenied
	}
	value := l.api.secretItemGetSecret(item)
	if value == nil {
		return nil, fmt.Errorf("%w: get failed", ErrUnavailable)
	}
	defer l.api.secretValueUnref(value)
	return l.copySecretValue(value)
}

// delete removes every exact matching item so successful deletion cannot retain a known duplicate.
func (l *linuxBackend) delete(ctx context.Context, service string, account string) error {
	list, err := l.search(ctx, service, account, linuxSearchAll|linuxSearchUnlock)
	if err != nil {
		return err
	}
	defer l.releaseItems(list)
	for current := list; current != nil; current = current.next {
		if l.api.secretItemGetLocked(current.data) != 0 {
			return ErrDenied
		}
		cancellable := l.newCancellable(ctx)
		var nativeError unsafe.Pointer
		success := l.api.secretItemDeleteSync(current.data, cancellable.value, &nativeError)
		cancellable.release()
		if success == 0 {
			return l.api.operationError("delete", ctx, nativeError)
		}
	}
	return nil
}

// search finds every item with both exact non-secret attributes.
func (l *linuxBackend) search(ctx context.Context, service string, account string, flags uint32) (*linuxGList, error) {
	attributes := l.newAttributes(service, account)
	defer attributes.release()
	cancellable := l.newCancellable(ctx)
	defer cancellable.release()
	var nativeError unsafe.Pointer
	list := l.api.secretServiceSearchSync(l.service, nil, attributes.value, flags, cancellable.value, &nativeError)
	if nativeError == nil {
		return list, nil
	}
	return nil, l.api.operationError("search", ctx, nativeError)
}

// singleItem validates that a logical key has exactly one stored item.
func (l *linuxBackend) singleItem(list *linuxGList) (unsafe.Pointer, error) {
	if list == nil {
		return nil, ErrNotFound
	}
	if list.next != nil {
		return nil, fmt.Errorf("%w: get failed", errUnrecognizedStatus)
	}
	return list.data, nil
}

// copySecretValue copies a bounded native binary value into caller-owned storage.
func (l *linuxBackend) copySecretValue(value unsafe.Pointer) ([]byte, error) {
	var length uintptr
	pointer := l.api.secretValueGet(value, &length)
	if length > MaxSecretSize {
		return nil, ErrTooLarge
	}
	secret := make([]byte, int(length))
	if length == 0 {
		return secret, nil
	}
	if pointer == nil {
		return nil, fmt.Errorf("%w: get failed", ErrUnavailable)
	}
	copy(secret, unsafe.Slice(pointer, int(length)))
	return secret, nil
}

// newSecretValue creates a binary native copy without handing libsecret a retained Go pointer.
func (l *linuxBackend) newSecretValue(secret []byte) unsafe.Pointer {
	contentType := l.newCString(linuxContentType)
	defer contentType.release()
	value := l.api.secretValueNew(unsafe.SliceData(secret), int64(len(secret)), (*byte)(contentType.value))
	runtime.KeepAlive(secret)
	return value
}

// newAttributes allocates the exact lookup attributes entirely in GLib-owned memory.
func (l *linuxBackend) newAttributes(service string, account string) linuxAttributes {
	value := l.api.gHashTableNewFull(nil, nil, l.api.gFreePointer, l.api.gFreePointer)
	attributes := linuxAttributes{api: l.api, value: value}
	l.insertAttribute(value, "service", service)
	l.insertAttribute(value, "account", account)
	return attributes
}

// insertAttribute transfers its allocated key and value into the GLib hash table.
func (l *linuxBackend) insertAttribute(attributes unsafe.Pointer, key string, value string) {
	keyValue := l.newCString(key)
	attributeValue := l.newCString(value)
	l.api.gHashTableInsert(attributes, keyValue.value, attributeValue.value)
}

// newCString copies a Go string through a NUL-terminated temporary into GLib-owned storage.
func (l *linuxBackend) newCString(value string) linuxCString {
	buffer := append([]byte(value), 0)
	pointer := l.api.gStrdup(unsafe.SliceData(buffer))
	runtime.KeepAlive(buffer)
	return linuxCString{api: l.api, value: pointer}
}

// newCancellable connects a context to a GCancellable and joins its goroutine before unref.
func (l *linuxBackend) newCancellable(ctx context.Context) linuxCancellable {
	cancellable := linuxCancellable{api: l.api, value: l.api.gCancellableNew()}
	if ctx.Done() == nil {
		return cancellable
	}
	cancellable.stop = make(chan struct{})
	cancellable.done = make(chan struct{})
	go func() {
		defer close(cancellable.done)
		select {
		case <-ctx.Done():
			l.api.gCancellableCancel(cancellable.value)
		case <-cancellable.stop:
		}
	}()
	return cancellable
}

// releaseItems releases every item reference and then its containing GLib list.
func (l *linuxBackend) releaseItems(list *linuxGList) {
	for current := list; current != nil; current = current.next {
		l.api.gObjectUnref(current.data)
	}
	if list != nil {
		l.api.gListFree(list)
	}
}

// releaseService drops the independent proxy while retaining libraries until Close finishes.
func (l *linuxBackend) releaseService() {
	if l.service != nil {
		l.api.gObjectUnref(l.service)
		l.service = nil
	}
}

// close releases the service before its dynamically loaded libraries in reverse order.
func (l *linuxBackend) close() error {
	l.releaseService()
	err := l.api.closeLibraries()
	return err
}

// operationError maps stable GLib domains and codes without exposing native localized messages.
func (a *linuxAPI) operationError(operation string, ctx context.Context, nativeError unsafe.Pointer) error {
	if nativeError == nil {
		return fmt.Errorf("%w: %s failed", ErrUnavailable, operation)
	}
	errorValue := (*linuxGError)(nativeError)
	domain := errorValue.domain
	code := errorValue.code
	a.gErrorFree(nativeError)
	err := ctx.Err()
	if err != nil {
		return err
	}
	mapped := a.nativeError(operation, domain, code)
	if operation == "open" && errors.Is(mapped, errUnrecognizedStatus) {
		return fmt.Errorf("%w: open failed", ErrUnavailable)
	}
	return mapped
}

// nativeError normalizes known GIO and libsecret failures while retaining only a numeric code.
func (a *linuxAPI) nativeError(operation string, domain uint32, code int32) error {
	sentinel := errUnrecognizedStatus
	if domain == a.gIOErrorQuark() {
		sentinel = a.gIOSentinel(code)
	}
	if domain == a.secretErrorQuark() {
		sentinel = a.secretSentinel(code)
	}
	return fmt.Errorf("%w: %s failed (code %d)", sentinel, operation, code)
}

// gIOSentinel classifies stable GIO error codes relevant to Secret Service calls.
func (a *linuxAPI) gIOSentinel(code int32) error {
	switch code {
	case linuxIOErrorNotFound:
		return ErrNotFound
	case linuxIOErrorPermissionDenied:
		return ErrDenied
	case linuxIOErrorCancelled:
		return ErrCanceled
	default:
		return errUnrecognizedStatus
	}
}

// secretSentinel classifies stable libsecret errors relevant to item operations.
func (a *linuxAPI) secretSentinel(code int32) error {
	switch code {
	case linuxSecretErrorIsLocked:
		return ErrDenied
	case linuxSecretErrorNoSuchObject:
		return ErrNotFound
	default:
		return errUnrecognizedStatus
	}
}

var _ backend = (*linuxBackend)(nil)
