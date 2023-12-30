package idpsec

import (
	"context"

	"github.com/kruzhok-team/berloga-go/beridp"
	"github.com/kruzhok-team/berloga-go/secsrc"
)

// Реализация beridp.SecuritySource являющаяся враппером для secsrc.SecuritySource.
type SecuritySource struct {
	Src secsrc.SecuritySource
}

// BerlogaJWT implements beridp.SecuritySource
func (s *SecuritySource) BerlogaJWT(ctx context.Context, operationName string) (beridp.BerlogaJWT, error) {
	tok, err := s.Src.BerlogaJWT(ctx, operationName)
	return beridp.BerlogaJWT{APIKey: tok}, err
}

// ServiceKey implements beridp.SecuritySource
func (s *SecuritySource) ServiceKey(ctx context.Context, operationName string) (beridp.ServiceKey, error) {
	tok, err := s.Src.ServiceKey(ctx, operationName)
	return beridp.ServiceKey{APIKey: tok}, err
}

var _ beridp.SecuritySource = (*SecuritySource)(nil)
