package actsec

import (
	"context"

	"github.com/kruzhok-team/berloga-go/beract"
	"github.com/kruzhok-team/berloga-go/secsrc"
)

// Аутентификатор реализующий только схему ServiceKey.
type ServiceKey struct {
	secsrc.BerlogaJWTSrc
}

// BerlogaJWT implements beract.SecuritySource
func (s *ServiceKey) BerlogaJWT(ctx context.Context, operationName string) (beract.BerlogaJWT, error) {
	tok, err := s.GetBerlogaJWT(ctx, operationName)
	if err != nil {
		return beract.BerlogaJWT{}, err
	}
	return beract.BerlogaJWT{APIKey: tok}, nil
}

// ServiceKey implements beract.SecuritySource
func (s *ServiceKey) ServiceKey(ctx context.Context, operationName string) (beract.ServiceKey, error) {
	tok, err := s.GetServiceKey(ctx, operationName)
	if err != nil {
		return beract.ServiceKey{}, err
	}
	return beract.ServiceKey{APIKey: tok}, nil
}

var _ beract.SecuritySource = (*ServiceKey)(nil)
