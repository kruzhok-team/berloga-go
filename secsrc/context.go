package secsrc

import (
	"context"

	"github.com/go-faster/errors"
	"github.com/ogen-go/ogen/ogenerrors"

	"github.com/kruzhok-team/berloga-go/berauth"
)

type FromContext struct{}

func (*FromContext) GetBerlogaJWT(ctx context.Context, operationName string) (string, error) {
	if berauth.GetAuthType(ctx) != berauth.AuthBerlogaJWT {
		return "", ogenerrors.ErrSkipClientSecurity
	}
	player, err := berauth.GetPlayer(ctx)
	if err != nil {
		return "", errors.Wrap(err, "get player")
	}
	return player.Token, nil
}

func (*FromContext) GetServiceKey(ctx context.Context, operationName string) (string, error) {
	if berauth.GetAuthType(ctx) != berauth.AuthServiceKey {
		return "", ogenerrors.ErrSkipClientSecurity
	}
	key, err := berauth.GetServiceKey(ctx)
	if err != nil {
		return "", errors.Wrap(err, "get service key")
	}
	return key, nil
}
