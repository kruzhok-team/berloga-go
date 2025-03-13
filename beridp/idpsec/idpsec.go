package idpsec

import (
	"context"

	"github.com/kruzhok-team/berloga-go/beridp"
	"github.com/kruzhok-team/berloga-go/secsrc"
)

func New(src secsrc.SecuritySource) *securitySource {
	return &securitySource{src: src}
}

// Реализация beridp.SecuritySource являющаяся враппером для secsrc.SecuritySource.
type securitySource struct {
	src secsrc.SecuritySource
}

// TalentOAuth implements beridp.SecuritySource.
func (s *securitySource) TalentOAuth(ctx context.Context, operationName string) (beridp.TalentOAuth, error) {
	tok, err := s.src.TalentOAuth(ctx, operationName)
	return beridp.TalentOAuth{Token: tok}, err
}

// BerlogaJWT implements beridp.SecuritySource
func (s *securitySource) BerlogaJWT(ctx context.Context, operationName string) (beridp.BerlogaJWT, error) {
	tok, err := s.src.BerlogaJWT(ctx, operationName)
	return beridp.BerlogaJWT{APIKey: tok}, err
}

// ServiceKey implements beridp.SecuritySource
func (s *securitySource) ServiceKey(ctx context.Context, operationName string) (beridp.ServiceKey, error) {
	tok, err := s.src.ServiceKey(ctx, operationName)
	return beridp.ServiceKey{APIKey: tok}, err
}

var _ beridp.SecuritySource = (*securitySource)(nil)
