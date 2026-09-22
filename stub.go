package keyring

import (
	"context"
)

// Stub is an in-memory backend suitable for unit testing.
// It stores secrets as []byte values keyed by "service:account".
type Stub map[string][]byte

var _ Store = Stub{}

// Set implements the Store interface for in-memory testing.
func (s Stub) Set(_ context.Context, account string, secret []byte) error {
	s[account] = copySecret(secret)
	return nil
}

// Get implements the Store interface for in-memory testing.
func (s Stub) Get(_ context.Context, account string) ([]byte, error) {
	if secret, ok := s[account]; ok {
		return copySecret(secret), nil
	}
	return nil, nil
}

// Delete implements the Store interface for in-memory testing.
func (s Stub) Delete(_ context.Context, account string) error {
	delete(s, account)
	return nil
}

// Close implements the Store interface for in-memory testing.
func (s Stub) Close() error {
	return nil
}
