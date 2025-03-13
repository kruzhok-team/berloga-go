package awardsec

import (
	"context"

	"github.com/kruzhok-team/berloga-go/bawards"
	"github.com/kruzhok-team/berloga-go/secsrc"
)

func New(src secsrc.SecuritySource) *SecuritySource {
	return &SecuritySource{Src: src}
}

// Реализация bawards.SecuritySource являющаяся враппером для secsrc.SecuritySource.
type SecuritySource struct {
	Src secsrc.SecuritySource
}

// TalentOAuth implements bawards.SecuritySource.
func (s *SecuritySource) TalentOAuth(ctx context.Context, operationName string) (bawards.TalentOAuth, error) {
	tok, err := s.Src.TalentOAuth(ctx, operationName)
	return bawards.TalentOAuth{Token: tok}, err
}

// BerlogaJWT implements bawards.SecuritySource
func (s *SecuritySource) BerlogaJWT(ctx context.Context, operationName string) (bawards.BerlogaJWT, error) {
	tok, err := s.Src.BerlogaJWT(ctx, operationName)
	return bawards.BerlogaJWT{APIKey: tok}, err
}

var _ bawards.SecuritySource = (*SecuritySource)(nil)
