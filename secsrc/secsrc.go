package secsrc

import (
	"context"

	"github.com/go-faster/errors"
	"github.com/ogen-go/ogen/ogenerrors"

	"github.com/kruzhok-team/berloga-go/berauth"
)

type SecuritySource interface {
	TalentOAuth(ctx context.Context, operationName string) (string, error)
	BerlogaJWT(ctx context.Context, operationName string) (string, error)
	ServiceKey(ctx context.Context, operationName string) (string, error)
}

// Context выполняет аутентификацию токеном и методом, взятыми из контекста выполняемого запроса.
func Context() SecuritySource {
	return &contextSource{}
}

type contextSource struct{}

// TalentOAuth implements SecuritySource.
func (*contextSource) TalentOAuth(ctx context.Context, operationName string) (string, error) {
	if berauth.GetAuthType(ctx) != berauth.AuthTalentOAuth {
		return "", ogenerrors.ErrSkipClientSecurity
	}
	usr, err := berauth.GetUser(ctx)
	if err != nil {
		return "", errors.Wrap(err, "get user")
	}
	return usr.Token, nil
}

// BerlogaJWT implements SecuritySource.
func (*contextSource) BerlogaJWT(ctx context.Context, operationName string) (string, error) {
	if berauth.GetAuthType(ctx) != berauth.AuthBerlogaJWT {
		return "", ogenerrors.ErrSkipClientSecurity
	}
	player, err := berauth.GetPlayer(ctx)
	if err != nil {
		return "", errors.Wrap(err, "get player")
	}
	return player.Token, nil
}

// ServiceKey implements SecuritySource.
func (*contextSource) ServiceKey(ctx context.Context, operationName string) (string, error) {
	if berauth.GetAuthType(ctx) != berauth.AuthServiceKey {
		return "", ogenerrors.ErrSkipClientSecurity
	}
	key, err := berauth.GetServiceKey(ctx)
	if err != nil {
		return "", errors.Wrap(err, "get service key")
	}
	return key, nil
}

var _ SecuritySource = (*contextSource)(nil)

// BerlogaJWT выполняет аутентификацию указанным токеном методом BerlogaJWT.
func BerlogaJWT(token string) SecuritySource {
	return &tokenSource{authType: berauth.AuthBerlogaJWT, token: token}
}

// ServiceKey выполняет аутентификацию указанным токеном методом ServiceKey.
func ServiceKey(key string) SecuritySource {
	return &tokenSource{authType: berauth.AuthServiceKey, token: key}
}

type tokenSource struct {
	authType berauth.AuthType
	token    string
}

// TalentOAuth implements SecuritySource.
func (src *tokenSource) TalentOAuth(ctx context.Context, operationName string) (string, error) {
	if src.authType != berauth.AuthTalentOAuth {
		return "", ogenerrors.ErrSkipClientSecurity
	}
	return src.token, nil
}

// BerlogaJWT implements SecuritySource.
func (src *tokenSource) BerlogaJWT(ctx context.Context, operationName string) (string, error) {
	if src.authType != berauth.AuthBerlogaJWT {
		return "", ogenerrors.ErrSkipClientSecurity
	}
	return src.token, nil
}

// ServiceKey implements SecuritySource.
func (src *tokenSource) ServiceKey(ctx context.Context, operationName string) (string, error) {
	if src.authType != berauth.AuthServiceKey {
		return "", ogenerrors.ErrSkipClientSecurity
	}
	return src.token, nil
}

var _ SecuritySource = (*tokenSource)(nil)
