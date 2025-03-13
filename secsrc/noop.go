package secsrc

import (
	"context"

	"github.com/ogen-go/ogen/ogenerrors"
)

// NoSecurity возвращает SecuritySource который не выполняет ни какой аутентификации.
// Такой SecuritySource можно использовать при обращении к публичным операциям API.
func NoSecurity() SecuritySource {
	return &noop{}
}

type noop struct {
}

// BerlogaJWT implements SecuritySource.
func (n *noop) BerlogaJWT(ctx context.Context, operationName string) (string, error) {
	return "", ogenerrors.ErrSkipClientSecurity
}

// ServiceKey implements SecuritySource.
func (n *noop) ServiceKey(ctx context.Context, operationName string) (string, error) {
	return "", ogenerrors.ErrSkipClientSecurity
}

// TalentOAuth implements SecuritySource.
func (n *noop) TalentOAuth(ctx context.Context, operationName string) (string, error) {
	return "", ogenerrors.ErrSkipClientSecurity
}
