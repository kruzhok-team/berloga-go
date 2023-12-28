package idpsec

import (
	"context"

	"github.com/kruzhok-team/berloga-go/beridp"
	"github.com/kruzhok-team/berloga-go/secsrc"
)

// Аутентификатор использующий учетные данные из контекста.
type FromContext struct{
	secsrc.BerlogaJWTSrc
}

// BerlogaJWT implements beridp.SecuritySource.
func (s *FromContext) BerlogaJWT(ctx context.Context, operationName string) (beridp.BerlogaJWT, error) {
	tok, err := s.GetBerlogaJWT(ctx, operationName)
	return beridp.BerlogaJWT{APIKey: tok}, err
}

// ServiceKey implements beridp.SecuritySource.
func (s *FromContext) ServiceKey(ctx context.Context, operationName string) (beridp.ServiceKey, error) {
	tok, err := s.GetServiceKey(ctx, operationName)
	return beridp.ServiceKey{APIKey: tok}, err
}

var _ beridp.SecuritySource = (*FromContext)(nil)
