package idpsec

import (
	"context"

	"github.com/ogen-go/ogen/ogenerrors"

	"github.com/kruzhok-team/berloga-go/beridp"
)

// Аутентификатор реализующий только схему ServiceKey.
type ServiceKey struct {
	SvcKey string
}

// BerlogaJWT implements beridp.SecuritySource
func (s *ServiceKey) BerlogaJWT(ctx context.Context, operationName string) (beridp.BerlogaJWT, error) {
	return beridp.BerlogaJWT{}, ogenerrors.ErrSkipClientSecurity
}

// ServiceKey implements beridp.SecuritySource
func (s *ServiceKey) ServiceKey(ctx context.Context, operationName string) (beridp.ServiceKey, error) {
	return beridp.ServiceKey{APIKey: s.SvcKey}, nil
}

var _ beridp.SecuritySource = (*ServiceKey)(nil)
