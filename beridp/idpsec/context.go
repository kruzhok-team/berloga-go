package idpsec

import (
	"context"

	"github.com/go-faster/errors"
	"github.com/kruzhok-team/berloga-go/berauth"
	"github.com/kruzhok-team/berloga-go/beridp"
	"github.com/ogen-go/ogen/ogenerrors"
)

type FromContext struct{}

// BerlogaJWT implements beridp.SecuritySource.
func (*FromContext) BerlogaJWT(ctx context.Context, operationName string) (beridp.BerlogaJWT, error) {
	if berauth.GetAuthType(ctx) != berauth.AuthBerlogaJWT {
		return beridp.BerlogaJWT{}, ogenerrors.ErrSkipClientSecurity
	}
	player, err := berauth.GetPlayer(ctx)
	if err != nil {
		return beridp.BerlogaJWT{}, errors.Wrap(err, "get player")
	}
	return beridp.BerlogaJWT{APIKey: player.Token}, nil
}

// ServiceKey implements beridp.SecuritySource.
func (*FromContext) ServiceKey(ctx context.Context, operationName string) (beridp.ServiceKey, error) {
	if berauth.GetAuthType(ctx) != berauth.AuthServiceKey {
		return beridp.ServiceKey{}, ogenerrors.ErrSkipClientSecurity
	}
	key, err := berauth.GetServiceKey(ctx)
	if err != nil {
		return beridp.ServiceKey{}, errors.Wrap(err, "get service key")
	}
	return beridp.ServiceKey{APIKey: key}, nil
}

var _ beridp.SecuritySource = (*FromContext)(nil)
