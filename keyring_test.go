package keyring

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"strings"
	"sync"
	"testing"
)

type fakeBackend struct {
	mu        sync.Mutex
	secret    []byte
	setErr    error
	getErr    error
	deleteErr error
	started   chan struct{}
	release   chan struct{}
	startOnce sync.Once
}

// set copies the owned buffer so tests can observe caller isolation after return.
func (f *fakeBackend) set(_ context.Context, _ string, _ string, secret []byte) error {
	if f.started != nil {
		f.startOnce.Do(func() { close(f.started) })
		<-f.release
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.secret = copySecret(secret)
	return f.setErr
}

// get returns a fresh backend buffer, matching the private backend contract.
func (f *fakeBackend) get(_ context.Context, _ string, _ string) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.getErr != nil {
		return nil, f.getErr
	}
	return copySecret(f.secret), nil
}

// delete clears the in-memory fake just as an idempotent native delete would.
func (f *fakeBackend) delete(_ context.Context, _ string, _ string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.secret = nil
	return f.deleteErr
}

func (f *fakeBackend) close() error {
	return nil
}

func TestKeyringSet_doesNotModifyCallerSecret(t *testing.T) {
	store := &fakeBackend{}
	ring := newKeyring("service", store)
	secret := []byte{1, 2, 3}

	err := ring.Set(context.Background(), "account", secret)
	if err != nil {
		t.Fatalf("Set() error = %v", err)
	}
	if string(secret) != string([]byte{1, 2, 3}) {
		t.Fatalf("Set() modified caller secret: %v", secret)
	}
}

func TestKeyringGet_returnsIndependentStorage(t *testing.T) {
	store := &fakeBackend{secret: []byte{1, 2, 3}}
	ring := newKeyring("service", store)

	secret, err := ring.Get(context.Background(), "account")
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	secret[0] = 9
	second, err := ring.Get(context.Background(), "account")
	if err != nil {
		t.Fatalf("second Get() error = %v", err)
	}
	if second[0] != 1 {
		t.Fatalf("Get() returned shared storage: %v", second)
	}
}

func TestKeyringSet_rejectsTooLargeSecret(t *testing.T) {
	ring := newKeyring("service", &fakeBackend{})
	secret := make([]byte, MaxSecretSize+1)

	err := ring.Set(context.Background(), "account", secret)
	if !errors.Is(err, ErrTooLarge) {
		t.Fatalf("Set() error = %v, want ErrTooLarge", err)
	}
}

func TestKeyringSet_rejectsCanceledContextBeforeBackendCall(t *testing.T) {
	ring := newKeyring("service", &fakeBackend{})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := ring.Set(ctx, "account", []byte("secret"))
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Set() error = %v, want context.Canceled", err)
	}
}

func TestKeyringClose_rejectsNewCallsWhileWaitingForActiveCall(t *testing.T) {
	store := &fakeBackend{started: make(chan struct{}), release: make(chan struct{})}
	ring := newKeyring("service", store)
	setDone := make(chan error, 1)
	go func() {
		setDone <- ring.Set(context.Background(), "account", []byte("secret"))
	}()
	<-store.started

	closeDone := make(chan error, 1)
	go func() {
		closeDone <- ring.Close()
	}()
	for {
		ring.mu.Lock()
		closed := ring.closed
		ring.mu.Unlock()
		if closed {
			break
		}
		runtime.Gosched()
	}
	err := ring.Delete(context.Background(), "account")
	if !errors.Is(err, ErrClosed) {
		t.Fatalf("Delete() error = %v, want ErrClosed", err)
	}
	close(store.release)
	setErr := <-setDone
	if setErr != nil {
		t.Fatalf("Set() error = %v", setErr)
	}
	closeErr := <-closeDone
	if closeErr != nil {
		t.Fatalf("Close() error = %v", closeErr)
	}
}

func TestValidateIdentifier_rejectsInvalidInput(t *testing.T) {
	cases := []string{"", "has\x00nul", string([]byte{0xff}), strings.Repeat("a", maxIdentifierSize+1)}
	for _, identifier := range cases {
		err := validateIdentifier(identifier)
		if !errors.Is(err, ErrInvalid) {
			t.Fatalf("validateIdentifier(%q) error = %v, want ErrInvalid", identifier, err)
		}
	}
}

func TestOperationError_redactsCredentialData(t *testing.T) {
	err := fmt.Errorf("%w: set failed (code %d)", ErrDenied, 5)
	message := err.Error()
	if !errors.Is(err, ErrDenied) {
		t.Fatalf("errors.Is() = false, want true")
	}
	for _, forbidden := range []string{"service-name", "account-name", "secret-value"} {
		if strings.Contains(message, forbidden) {
			t.Fatalf("Error() exposed %q: %q", forbidden, message)
		}
	}
}
