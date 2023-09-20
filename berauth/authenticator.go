package berauth

import (
	"context"
	"errors"
)

var (
	ErrUnauthorized = errors.New("не авторизован")
)

type ctxKey string

type Authenticator interface {
	Auth(ctx context.Context, credentials string) (context.Context, error)
}
