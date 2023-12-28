package secsrc

import (
	"context"

	"github.com/ogen-go/ogen/ogenerrors"
)

// Аутентификатор реализующий только схему ServiceKey.
type ServiceKey struct {
	SvcKey string
}

func (s *ServiceKey) GetBerlogaJWT(ctx context.Context, operationName string) (string, error) {
	return "", ogenerrors.ErrSkipClientSecurity
}

func (s *ServiceKey) GetServiceKey(ctx context.Context, operationName string) (string, error) {
	return s.SvcKey, nil
}
