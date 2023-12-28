package secsrc

import (
	"context"

	"github.com/ogen-go/ogen/ogenerrors"

	"github.com/kruzhok-team/berloga-go/berauth"
)

// Аутентификатор реализующий только схему BerlogaJWT.
type BerlogaJWTSrc struct{}

func (s *BerlogaJWTSrc) GetBerlogaJWT(ctx context.Context, operationName string) (string, error) {
	player, err := berauth.GetPlayer(ctx)
	if err != nil {
		return "", err
	}
	return player.Token, nil
}

func (s *BerlogaJWTSrc) GetServiceKey(ctx context.Context, operationName string) (string, error) {
	return "", ogenerrors.ErrSkipClientSecurity
}
