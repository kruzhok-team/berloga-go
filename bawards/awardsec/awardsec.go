package awardsec

import (
	"context"

	"github.com/kruzhok-team/berloga-go/bawards"
	"github.com/kruzhok-team/berloga-go/secsrc"
)

func New(src secsrc.SecuritySource) *securitySource {
	return &securitySource{src: src}
}

// Реализация bawards.SecuritySource являющаяся враппером для secsrc.SecuritySource.
type securitySource struct {
	src secsrc.SecuritySource
}

// TalentOAuth implements bawards.SecuritySource.
func (s *securitySource) TalentOAuth(ctx context.Context, operationName string) (bawards.TalentOAuth, error) {
	tok, err := s.src.TalentOAuth(ctx, operationName)
	return bawards.TalentOAuth{Token: tok}, err
}

// BerlogaJWT implements bawards.SecuritySource
func (s *securitySource) BerlogaJWT(ctx context.Context, operationName string) (bawards.BerlogaJWT, error) {
	tok, err := s.src.BerlogaJWT(ctx, operationName)
	return bawards.BerlogaJWT{APIKey: tok}, err
}

var _ bawards.SecuritySource = (*securitySource)(nil)
