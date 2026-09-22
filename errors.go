package keyring

import "errors"

var (
	// ErrNotFound reports that a requested credential does not exist.
	ErrNotFound = errors.New("keyring: item not found")
	// ErrUnavailable reports that the platform credential store cannot be used.
	ErrUnavailable = errors.New("keyring: native store unavailable")
	// ErrDenied reports that the credential store denied access.
	ErrDenied = errors.New("keyring: access denied")
	// ErrCanceled reports that the user canceled a credential-store prompt.
	ErrCanceled = errors.New("keyring: user canceled")
	// ErrClosed reports use after Close has started.
	ErrClosed = errors.New("keyring: store closed")
	// ErrInvalid reports an invalid service or account identifier.
	ErrInvalid = errors.New("keyring: invalid input")
	// ErrTooLarge reports a secret larger than MaxSecretSize.
	ErrTooLarge = errors.New("keyring: secret too large")
	// errUnrecognizedStatus reports a platform status code this package does not classify.
	errUnrecognizedStatus = errors.New("keyring: unrecognized status")
)
