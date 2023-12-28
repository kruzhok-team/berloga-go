package actsec

import (
	"context"

	"github.com/kruzhok-team/berloga-go/beract"
	"github.com/kruzhok-team/berloga-go/secsrc"
)

// Аутентификатор использующий учетные данные из контекста.
type FromContext struct{
	secsrc.FromContext
}

// BerlogaJWT implements beract.SecuritySource.
func (s *FromContext) BerlogaJWT(ctx context.Context, operationName string) (beract.BerlogaJWT, error) {
	tok, err := s.GetBerlogaJWT(ctx, operationName)
	return beract.BerlogaJWT{APIKey: tok}, err
}

// ServiceKey implements beract.SecuritySource.
func (s *FromContext) ServiceKey(ctx context.Context, operationName string) (beract.ServiceKey, error) {
	tok, err := s.GetServiceKey(ctx, operationName)
	return beract.ServiceKey{APIKey: tok}, err
}

var _ beract.SecuritySource = (*FromContext)(nil)
