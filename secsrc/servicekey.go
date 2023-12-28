package secsrc

import (
	"context"

	"github.com/ogen-go/ogen/ogenerrors"
)

// Аутентификатор реализующий только схему ServiceKey.
type ServiceKeySrc struct {
	SvcKey string
}

func (s *ServiceKeySrc) GetBerlogaJWT(ctx context.Context, operationName string) (string, error) {
	return "", ogenerrors.ErrSkipClientSecurity
}

func (s *ServiceKeySrc) GetServiceKey(ctx context.Context, operationName string) (string, error) {
	return s.SvcKey, nil
}
