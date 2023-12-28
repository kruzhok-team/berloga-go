package actsec

import (
	"context"

	"github.com/kruzhok-team/berloga-go/beract"
	"github.com/kruzhok-team/berloga-go/secsrc"
)

// Аутентификатор реализующий только схему BerlogaJWT.
type BerlogaJWT struct{
	secsrc.BerlogaJWTSrc
}

// BerlogaJWT implements beract.SecuritySource
func (s *BerlogaJWT) BerlogaJWT(ctx context.Context, operationName string) (beract.BerlogaJWT, error) {
	tok, err := s.GetBerlogaJWT(ctx, operationName)
	return beract.BerlogaJWT{APIKey: tok}, err
}

// ServiceKey implements beract.SecuritySource
func (s *BerlogaJWT) ServiceKey(ctx context.Context, operationName string) (beract.ServiceKey, error) {
	tok, err := s.GetServiceKey(ctx, operationName)
	return beract.ServiceKey{APIKey: tok}, err
}

var _ beract.SecuritySource = (*BerlogaJWT)(nil)
