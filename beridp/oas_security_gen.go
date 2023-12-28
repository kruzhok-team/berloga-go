// Code generated by ogen, DO NOT EDIT.

package beridp

import (
	"context"
	"net/http"

	"github.com/go-faster/errors"
)

// SecuritySource is provider of security values (tokens, passwords, etc.).
type SecuritySource interface {
	// BerlogaJWT provides BerlogaJWT security value.
	// JWT, полученный эндпоинтом [issue-token](#operation/issueToken).
	BerlogaJWT(ctx context.Context, operationName string) (BerlogaJWT, error)
	// ServiceKey provides ServiceKey security value.
	ServiceKey(ctx context.Context, operationName string) (ServiceKey, error)
}

func (s *Client) securityBerlogaJWT(ctx context.Context, operationName string, req *http.Request) error {
	t, err := s.sec.BerlogaJWT(ctx, operationName)
	if err != nil {
		return errors.Wrap(err, "security source \"BerlogaJWT\"")
	}
	req.Header.Set("Authorization", t.APIKey)
	return nil
}
func (s *Client) securityServiceKey(ctx context.Context, operationName string, req *http.Request) error {
	t, err := s.sec.ServiceKey(ctx, operationName)
	if err != nil {
		return errors.Wrap(err, "security source \"ServiceKey\"")
	}
	req.Header.Set("X-Service-Key", t.APIKey)
	return nil
}
