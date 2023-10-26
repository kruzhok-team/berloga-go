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

type AuthType string

var Unauthenticated AuthType = ""

var ctxAuthType ctxKey = "AuthType"

// AuthType возвращает текущий тип аутентификации.
// Возможные значения:
//	- Unauthenticated
//	- AuthTalentOAuth
//	- AuthBerlogaJWT
//	- AuthServiceKey
func GetAuthType(ctx context.Context) AuthType {
	if v := ctx.Value(ctxAuthType); v != nil {
		return v.(AuthType)
	}
	return Unauthenticated
}
