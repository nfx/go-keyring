package keyring

import "runtime"

// Wipe overwrites b in place on a best-effort basis.
func Wipe(b []byte) {
	for index := range b {
		b[index] = 0
	}
	runtime.KeepAlive(b)
}

// copySecret returns a caller-independent buffer.
func copySecret(secret []byte) []byte {
	return append([]byte(nil), secret...)
}
