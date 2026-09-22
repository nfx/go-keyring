//go:build darwin

package keyring_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"

	"github.com/nfx/go-keyring"
)

const runTests = true

// Example_darwinIntegration runs an opt-in Keychain round trip with isolated metadata.
func Example_darwinIntegration() {
	if !runTests {
		return
	}

	service := "go-keyring-integration-" + randomID()
	account := "account-" + randomID()
	store, err := keyring.Open(service)
	if err != nil {
		panic(err)
	}

	ctx := context.Background()
	defer func() {
		cleanupErr := store.Delete(ctx, account)
		if cleanupErr != nil {
			panic(cleanupErr)
		}
		closeErr := store.Close()
		if closeErr != nil {
			panic(closeErr)
		}
	}()

	first := []byte{0, 1, 255, 2}
	err = store.Set(ctx, account, first)
	if err != nil {
		panic(err)
	}
	second := []byte{3, 4, 5}
	err = store.Set(ctx, account, second)
	if err != nil {
		panic(err)
	}
	secret, err := store.Get(ctx, account)
	if err != nil {
		panic(err)
	}
	if !bytes.Equal(secret, second) {
		panic("Keychain returned an unexpected secret")
	}
	err = store.Delete(ctx, account)
	if err != nil {
		panic(err)
	}
	_, err = store.Get(ctx, account)
	if !errors.Is(err, keyring.ErrNotFound) {
		panic(err)
	}

	// Output:
}

// randomID returns opaque example metadata that cannot collide with a parallel run.
func randomID() string {
	var value [12]byte
	_, err := rand.Read(value[:])
	if err != nil {
		panic(err)
	}
	return hex.EncodeToString(value[:])
}
