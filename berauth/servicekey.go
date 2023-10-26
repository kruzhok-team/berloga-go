package berauth

import (
	"context"
	"errors"
)

var (
	ErrMissingServiceKey = errors.New("не установлен сервисный ключ")

	AuthServiceKey AuthType = "ServiceKey"

	ctxServiceKey ctxKey = "ServiceKey"
)

// SetServiceKey создает контекст авторизованный аутентификатором ServiceKey.
func SetServiceKey(ctx context.Context) context.Context {
	return context.WithValue(ctx, ctxServiceKey, struct{}{})
}

// HasServiceKey сообщает имеется ли успешная аутентификация сервисным ключом в контексте.
func HasServiceKey(ctx context.Context) bool {
	return ctx.Value(ctxServiceKey) != nil
}

// ServiceKey создает аутентификатор по сервисному ключу Берлоги.
func ServiceKey(key string) Authenticator {
	return &serviceKey{key: key}
}

type serviceKey struct {
	key string
}

// Auth implements Authenticator
func (s *serviceKey) Auth(ctx context.Context, credentials string) (context.Context, error) {
	if credentials == "" {
		return ctx, ErrUnauthorized
	}
	if s.key == "" {
		return ctx, ErrMissingServiceKey
	}
	if credentials != s.key {
		return ctx, ErrUnauthorized
	}
	return SetServiceKey(ctx), nil
}
