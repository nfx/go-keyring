package keyring

import "context"

type backend interface {
	set(context.Context, string, string, []byte) error
	get(context.Context, string, string) ([]byte, error)
	delete(context.Context, string, string) error
	close() error
}
