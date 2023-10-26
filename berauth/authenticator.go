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

type authType string

var Unauthenticated authType = ""

var ctxAuthType ctxKey = "AuthType"

// AuthType возвращает текущий тип аутентификации.
// Возможные значения:
//	- Unauthenticated
//	- AuthTalentOAuth
//	- AuthBerlogaJWT
//	- AuthServiceKey
func AuthType(ctx context.Context) authType {
	if v := ctx.Value(ctxAuthType); v != nil {
		return v.(authType)
	}
	return Unauthenticated
}
