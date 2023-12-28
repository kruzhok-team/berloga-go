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
	if err != nil {
		return beract.BerlogaJWT{}, err
	}
	return beract.BerlogaJWT{APIKey: tok}, nil
}

// ServiceKey implements beract.SecuritySource.
func (s *FromContext) ServiceKey(ctx context.Context, operationName string) (beract.ServiceKey, error) {
	tok, err := s.GetServiceKey(ctx, operationName)
	if err != nil {
		return beract.ServiceKey{}, err
	}
	return beract.ServiceKey{APIKey: tok}, nil
}

var _ beract.SecuritySource = (*FromContext)(nil)
