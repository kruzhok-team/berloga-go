// Code generated by ogen, DO NOT EDIT.

package bawards

import (
	"context"
	"net/http"

	"github.com/go-faster/errors"
)

// SecuritySource is provider of security values (tokens, passwords, etc.).
type SecuritySource interface {
	// BerlogaJWT provides BerlogaJWT security value.
	// JWT, полученный эндпоинтом
	// [issue-token](/berloga-idp/docs/#operation/IssueToken).
	BerlogaJWT(ctx context.Context, operationName string) (BerlogaJWT, error)
	// TalentOAuth provides TalentOAuth security value.
	// JWT, полученный [OAuth провайдером платформы
	// Талант](/api/docs/).
	TalentOAuth(ctx context.Context, operationName string) (TalentOAuth, error)
}

func (s *Client) securityBerlogaJWT(ctx context.Context, operationName string, req *http.Request) error {
	t, err := s.sec.BerlogaJWT(ctx, operationName)
	if err != nil {
		return errors.Wrap(err, "security source \"BerlogaJWT\"")
	}
	req.Header.Set("Authorization", t.APIKey)
	return nil
}
func (s *Client) securityTalentOAuth(ctx context.Context, operationName string, req *http.Request) error {
	t, err := s.sec.TalentOAuth(ctx, operationName)
	if err != nil {
		return errors.Wrap(err, "security source \"TalentOAuth\"")
	}
	req.Header.Set("Authorization", "Bearer "+t.Token)
	return nil
}
