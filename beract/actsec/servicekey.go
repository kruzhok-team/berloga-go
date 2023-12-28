package actsec

import (
	"context"

	"github.com/kruzhok-team/berloga-go/beract"
	"github.com/kruzhok-team/berloga-go/secsrc"
)

// Аутентификатор реализующий только схему ServiceKey.
type ServiceKey struct {
	secsrc.SvcKey
}

// BerlogaJWT implements beract.SecuritySource
func (s *ServiceKey) BerlogaJWT(ctx context.Context, operationName string) (beract.BerlogaJWT, error) {
	tok, err := s.GetBerlogaJWT(ctx, operationName)
	return beract.BerlogaJWT{APIKey: tok}, err
}

// ServiceKey implements beract.SecuritySource
func (s *ServiceKey) ServiceKey(ctx context.Context, operationName string) (beract.ServiceKey, error) {
	tok, err := s.GetServiceKey(ctx, operationName)
	return beract.ServiceKey{APIKey: tok}, err
}

var _ beract.SecuritySource = (*ServiceKey)(nil)
