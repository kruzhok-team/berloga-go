package idpsec

import (
	"context"

	"github.com/kruzhok-team/berloga-go/beridp"
	"github.com/kruzhok-team/berloga-go/secsrc"
)

func New(src secsrc.SecuritySource) *SecuritySource {
	return &SecuritySource{Src: src}
}

// Реализация beridp.SecuritySource являющаяся враппером для secsrc.SecuritySource.
type SecuritySource struct {
	Src secsrc.SecuritySource
}

// TalentOAuth implements beridp.SecuritySource.
func (s *SecuritySource) TalentOAuth(ctx context.Context, operationName string) (beridp.TalentOAuth, error) {
	tok, err := s.Src.TalentOAuth(ctx, operationName)
	return beridp.TalentOAuth{Token: tok}, err
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
