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

// GetServiceKey возвращает сервисный ключ из контекста или ошибку ErrMissingServiceKey.
func GetServiceKey(ctx context.Context) (string, error) {
	if raw := ctx.Value(ctxServiceKey); raw != nil {
		return raw.(string), nil
	}
	return "", ErrMissingServiceKey
}

// SetServiceKey создает контекст авторизованный аутентификатором ServiceKey.
func SetServiceKey(ctx context.Context, key string) context.Context {
	ctx = context.WithValue(ctx, ctxAuthType, AuthServiceKey)
	return context.WithValue(ctx, ctxServiceKey, key)
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
		return ctx, &CredentialsAuthError{ErrUnauthorized}
	}
	if s.key == "" {
		return ctx, ErrMissingServiceKey
	}
	if credentials != s.key {
		return ctx, &CredentialsAuthError{ErrUnauthorized}
	}
	return SetServiceKey(ctx, credentials), nil
}
