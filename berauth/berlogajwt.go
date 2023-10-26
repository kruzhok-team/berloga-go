package berauth

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

var (
	ErrMissingBerlogaJWT = errors.New("отсутствуют учетные данные BerlogaJWT")

	AuthBerlogaJWT AuthType = "BerlogaJWT"

	ctxBerlogaJWT ctxKey = "BerlogaJWT"
)

type Player struct {
	Token         string
	JWT           jwt.Token
	ApplicationID uuid.UUID
	PlayerID      uuid.UUID
}

// GetPlayer возвращает учетные данные игрока из контекста или ошибку ErrMissingBerlogaJWT.
func GetPlayer(ctx context.Context) (Player, error) {
	if raw := ctx.Value(ctxBerlogaJWT); raw != nil {
		return raw.(Player), nil
	}
	return Player{}, ErrMissingBerlogaJWT
}

// SetPlayer создает контекст с учетными данными игрока.
func SetPlayer(ctx context.Context, player Player) context.Context {
	return context.WithValue(ctx, ctxBerlogaJWT, player)
}

// HasBerlogaJWT сообщает имеется ли успешная аутентификация BerlogaJWT в контексте.
func HasBerlogaJWT(ctx context.Context) bool {
	return ctx.Value(ctxBerlogaJWT) != nil
}

// BerlogaJWT создает JWT аутентификатор на основе JWKSet.
func BerlogaJWT(jwkset jwk.Set) Authenticator {
	return &berlogaJWT{jwks: jwkset}
}

type berlogaJWT struct {
	jwks jwk.Set
}

// Auth implements Authenticator
func (self *berlogaJWT) Auth(ctx context.Context, credentials string) (context.Context, error) {
	if credentials == "" {
		return ctx, ErrUnauthorized
	}
	var err error
	p := Player{Token: credentials}
	p.JWT, err = jwt.Parse([]byte(credentials), jwt.WithKeySet(self.jwks))
	if err != nil {
		return ctx, err
	}
	p.ApplicationID, err = uuid.Parse(p.JWT.Issuer())
	if err != nil {
		return ctx, err
	}
	p.PlayerID, err = uuid.Parse(p.JWT.Subject())
	if err != nil {
		return ctx, err
	}
	return SetPlayer(ctx, p), nil
}
