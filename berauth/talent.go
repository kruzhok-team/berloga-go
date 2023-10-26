package berauth

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strconv"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

var (
	ErrMissingTalentOAuth = errors.New("отсутствуют учетные данные TalentOAuth")

	AuthTalentOAuth AuthType = "TalentOAuth"

	ctxTalentOAuth ctxKey = "Talent"

	jwtClaimSub = regexp.MustCompile(`^(?P<userid>\d+)@user$`)
)

type User struct {
	Token string
	JWT   jwt.Token
	ID    int
}

func GetUser(ctx context.Context) (User, error) {
	if raw := ctx.Value(ctxTalentOAuth); raw != nil {
		return raw.(User), nil
	}
	return User{}, ErrMissingTalentOAuth
}

func SetUser(ctx context.Context, user User) context.Context {
	ctx = context.WithValue(ctx, ctxAuthType, AuthTalentOAuth)
	return context.WithValue(ctx, ctxTalentOAuth, user)
}

func HasTalentOAuth(ctx context.Context) bool {
	return ctx.Value(ctxTalentOAuth) != nil
}

func TalentOAuth(jwkset jwk.Set) Authenticator {
	return &talentOAuth{jwks: jwkset}
}

type talentOAuth struct {
	jwks jwk.Set
}

// Auth implements Authenticator
func (self *talentOAuth) Auth(ctx context.Context, credentials string) (context.Context, error) {
	if credentials == "" {
		return ctx, ErrUnauthorized
	}
	var err error
	u := User{Token: credentials}
	u.JWT, err = jwt.Parse([]byte(credentials), jwt.WithKeySet(self.jwks))
	if err != nil {
		return ctx, err
	}
	names := jwtClaimSub.SubexpNames()
	for i, m := range jwtClaimSub.FindStringSubmatch(u.JWT.Subject()) {
		if names[i] == "userid" {
			u.ID, err = strconv.Atoi(m)
			if err != nil {
				return ctx, fmt.Errorf("приведение jwt.Subject к int: %w", err)
			}
		}
	}
	return SetUser(ctx, u), nil
}
