//go:build !darwin && !windows && !linux

package keyring

func newBackend() (backend, error) {
	return nil, ErrUnavailable
}
