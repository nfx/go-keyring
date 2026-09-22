# go-keyring

`go-keyring` stores opaque secrets in the current user's native credential store 
without CGo and just `purego` as a single dependency.

This implementation supports macOS Keychain, Windows Credential Manager, and Linux Secret
Service. `Open` returns `ErrUnavailable` on unsupported platforms; it never falls back to
plaintext storage.

```go
import "github.com/nfx/go-keyring"

// ...

store, err := keyring.Open("com.example.app")
if err != nil {
	return err
}
defer store.Close()

err = store.Set(ctx, "api-token", token)
```

Payloads are artificially limited to 2kb and secret keys are limited to 255 bytes.
`store.Set` does not mutate its input; `store.Get` returns a fresh caller-owned byte slice. 
`keyring.Wipe` overwrites a slice on a best-effort basis but cannot erase runtime,
operating-system, or credential-provider copies. 
Native calls on macOS and Windows are synchronous, so cancellation prevents a call from
starting but cannot reliably interrupt one already in progress.
On Linux, running the backend requires the distribution's `libsecret-1.so.0`, GLib/GIO/GObject,
a local D-Bus session, and a Secret Service provider such as GNOME Keyring, KeePassXC, or KWallet.
These are runtime prerequisites, not bundled dependencies.
When they are missing or unusable, `Open` returns `ErrUnavailable`; the package never writes a
plaintext fallback. Linux operations pass context cancellation to libsecret cooperatively. A
canceled `Set` or `Delete` can have an indeterminate postcondition if the provider committed just
before observing cancellation.
