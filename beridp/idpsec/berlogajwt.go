package idpsec

import (
	"context"

	"github.com/kruzhok-team/berloga-go/beridp"
	"github.com/kruzhok-team/berloga-go/secsrc"
)

// Аутентификатор реализующий только схему BerlogaJWT.
type BerlogaJWT struct{
	secsrc.BerlogaJWTSrc
}

// BerlogaJWT implements beridp.SecuritySource
func (s *BerlogaJWT) BerlogaJWT(ctx context.Context, operationName string) (beridp.BerlogaJWT, error) {
	tok, err := s.GetBerlogaJWT(ctx, operationName)
	if err != nil {
		return beridp.BerlogaJWT{}, err
	}
	return beridp.BerlogaJWT{APIKey: tok}, nil
}

// ServiceKey implements beridp.SecuritySource
func (s *BerlogaJWT) ServiceKey(ctx context.Context, operationName string) (beridp.ServiceKey, error) {
	tok, err := s.GetServiceKey(ctx, operationName)
	if err != nil {
		return beridp.ServiceKey{}, err
	}
	return beridp.ServiceKey{APIKey: tok}, nil
}

var _ beridp.SecuritySource = (*BerlogaJWT)(nil)
