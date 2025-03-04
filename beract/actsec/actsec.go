package actsec

import (
	"context"

	"github.com/kruzhok-team/berloga-go/beract"
	"github.com/kruzhok-team/berloga-go/secsrc"
)

func New(src secsrc.SecuritySource) *SecuritySource {
	return &SecuritySource{Src: src}
}

// Реализация beract.SecuritySource являющаяся враппером для secsrc.SecuritySource.
type SecuritySource struct {
	Src secsrc.SecuritySource
}

// TalentOAuth implements beract.SecuritySource.
func (s *SecuritySource) TalentOAuth(ctx context.Context, operationName string) (beract.TalentOAuth, error) {
	tok, err := s.Src.TalentOAuth(ctx, operationName)
	return beract.TalentOAuth{Token: tok}, err
}

// BerlogaJWT implements beract.SecuritySource
func (s *SecuritySource) BerlogaJWT(ctx context.Context, operationName string) (beract.BerlogaJWT, error) {
	tok, err := s.Src.BerlogaJWT(ctx, operationName)
	return beract.BerlogaJWT{APIKey: tok}, err
}

// ServiceKey implements beract.SecuritySource
func (s *SecuritySource) ServiceKey(ctx context.Context, operationName string) (beract.ServiceKey, error) {
	tok, err := s.Src.ServiceKey(ctx, operationName)
	return beract.ServiceKey{APIKey: tok}, err
}

var _ beract.SecuritySource = (*SecuritySource)(nil)
