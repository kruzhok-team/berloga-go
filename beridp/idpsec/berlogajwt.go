package idpsec

import (
	"context"

	"github.com/ogen-go/ogen/ogenerrors"

	"github.com/kruzhok-team/berloga-go/berauth"
	"github.com/kruzhok-team/berloga-go/beridp"
)

// Аутентификатор реализующий только схему BerlogaJWT.
type BerlogaJWT struct{}

// BerlogaJWT implements beridp.SecuritySource
func (s *BerlogaJWT) BerlogaJWT(ctx context.Context, operationName string) (beridp.BerlogaJWT, error) {
	player, err := berauth.GetPlayer(ctx)
	if err != nil {
		return beridp.BerlogaJWT{}, err
	}
	return beridp.BerlogaJWT{APIKey: player.Token}, nil
}

// ServiceKey implements beridp.SecuritySource
func (s *BerlogaJWT) ServiceKey(ctx context.Context, operationName string) (beridp.ServiceKey, error) {
	return beridp.ServiceKey{}, ogenerrors.ErrSkipClientSecurity
}

var _ beridp.SecuritySource = (*BerlogaJWT)(nil)
