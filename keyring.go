package keyring

import (
	"context"
	"sync"
	"unicode/utf8"
)

const (
	// MaxSecretSize is the largest secret supported by every native backend. macOS Keychain and
	// Linux Secret Service accept 16MB+ items natively; Windows Credential Manager's per-entry
	// limit is far smaller, so the Windows backend transparently splits larger secrets across
	// multiple credentials.
	MaxSecretSize     = 1024 * 1024
	maxIdentifierSize = 255
)

// Store provides access to credentials in a service namespace.
type Store interface {
	Set(ctx context.Context, account string, secret []byte) error
	Get(ctx context.Context, account string) ([]byte, error)
	Delete(ctx context.Context, account string) error
	Close() error
}

// keyring stores credentials in one service namespace.
type keyring struct {
	service   string
	backend   backend
	mu        sync.Mutex
	active    int
	closed    bool
	closing   bool
	idle      chan struct{}
	closeDone chan struct{}
}

// Open initializes the credential store for service using the native backend.
func Open(service string) (Store, error) {
	err := validateIdentifier(service)
	if err != nil {
		return nil, err
	}
	store, err := newBackend()
	if err != nil {
		return nil, err
	}
	return newKeyring(service, store), nil
}

// newKeyring constructs a keyring around a private test seam.
func newKeyring(service string, store backend) *keyring {
	return &keyring{
		service:   service,
		backend:   store,
		idle:      make(chan struct{}),
		closeDone: make(chan struct{}),
	}
}

// Set upserts secret for account without mutating the caller's slice.
func (k *keyring) Set(ctx context.Context, account string, secret []byte) error {
	err := validateIdentifier(account)
	if err != nil {
		return err
	}
	if len(secret) > MaxSecretSize {
		return ErrTooLarge
	}
	store, err := k.begin(ctx)
	if err != nil {
		return err
	}
	defer k.finish()
	owned := copySecret(secret)
	defer Wipe(owned)
	return store.set(ctx, k.service, account, owned)
}

// Get returns a fresh caller-owned copy of account's secret.
func (k *keyring) Get(ctx context.Context, account string) ([]byte, error) {
	err := validateIdentifier(account)
	if err != nil {
		return nil, err
	}
	store, err := k.begin(ctx)
	if err != nil {
		return nil, err
	}
	defer k.finish()
	secret, err := store.get(ctx, k.service, account)
	if err != nil {
		return nil, err
	}
	defer Wipe(secret)
	if len(secret) > MaxSecretSize {
		return nil, ErrTooLarge
	}
	return copySecret(secret), nil
}

// Delete removes account's credential and succeeds if it is already absent.
func (k *keyring) Delete(ctx context.Context, account string) error {
	err := validateIdentifier(account)
	if err != nil {
		return err
	}
	store, err := k.begin(ctx)
	if err != nil {
		return err
	}
	defer k.finish()
	return store.delete(ctx, k.service, account)
}

// Close waits for active calls then releases native backend resources.
func (k *keyring) Close() error {
	k.mu.Lock()
	if k.closed {
		done := k.closeDone
		k.mu.Unlock()
		<-done
		return nil
	}
	k.closed = true
	k.closing = true
	wait := k.active > 0
	store := k.backend
	k.mu.Unlock()
	if wait {
		<-k.idle
	}
	err := store.close()
	k.mu.Lock()
	k.closing = false
	close(k.closeDone)
	k.mu.Unlock()
	return err
}

// begin reserves a native call after checking lifecycle and cancellation.
func (k *keyring) begin(ctx context.Context) (backend, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.closed {
		return nil, ErrClosed
	}
	err := ctx.Err()
	if err != nil {
		return nil, err
	}
	k.active++
	return k.backend, nil
}

// finish releases one native call and wakes Close when it is the final call.
func (k *keyring) finish() {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.active--
	if k.closed && k.active == 0 {
		close(k.idle)
	}
}

// validateIdentifier accepts portable metadata that is safe to pass to native APIs.
func validateIdentifier(identifier string) error {
	if identifier == "" || len(identifier) > maxIdentifierSize || !utf8.ValidString(identifier) {
		return ErrInvalid
	}
	for _, character := range identifier {
		if character == 0 {
			return ErrInvalid
		}
	}
	return nil
}
