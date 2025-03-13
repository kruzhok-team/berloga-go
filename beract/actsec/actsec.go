package actsec

import (
	"context"

	"github.com/kruzhok-team/berloga-go/beract"
	"github.com/kruzhok-team/berloga-go/secsrc"
)

func New(src secsrc.SecuritySource) *securitySource {
	return &securitySource{src: src}
}

// Реализация beract.SecuritySource являющаяся враппером для secsrc.SecuritySource.
type securitySource struct {
	src secsrc.SecuritySource
}

// TalentOAuth implements beract.SecuritySource.
func (s *securitySource) TalentOAuth(ctx context.Context, operationName string) (beract.TalentOAuth, error) {
	tok, err := s.src.TalentOAuth(ctx, operationName)
	return beract.TalentOAuth{Token: tok}, err
}

// BerlogaJWT implements beract.SecuritySource
func (s *securitySource) BerlogaJWT(ctx context.Context, operationName string) (beract.BerlogaJWT, error) {
	tok, err := s.src.BerlogaJWT(ctx, operationName)
	return beract.BerlogaJWT{APIKey: tok}, err
}

// ServiceKey implements beract.SecuritySource
func (s *securitySource) ServiceKey(ctx context.Context, operationName string) (beract.ServiceKey, error) {
	tok, err := s.src.ServiceKey(ctx, operationName)
	return beract.ServiceKey{APIKey: tok}, err
}

var _ beract.SecuritySource = (*securitySource)(nil)
