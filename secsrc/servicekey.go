package secsrc

import (
	"context"

	"github.com/ogen-go/ogen/ogenerrors"
)

// Аутентификатор реализующий только схему ServiceKey.
type SvcKey string

func (s *SvcKey) GetBerlogaJWT(ctx context.Context, operationName string) (string, error) {
	return "", ogenerrors.ErrSkipClientSecurity
}

func (s *SvcKey) GetServiceKey(ctx context.Context, operationName string) (string, error) {
	return string(*s), nil
}
