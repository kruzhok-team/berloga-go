package secsrc

import (
	"context"
	"testing"

	"github.com/ogen-go/ogen/ogenerrors"

	"github.com/kruzhok-team/berloga-go/berauth"
)

func TestSecuritySources(t *testing.T) {
	ctx := context.Background()
	for _, tt := range []struct {
		name    string
		src     SecuritySource
		ctx     context.Context
		bjwtTok string
		bjwtErr error
		skeyTok string
		skeyErr error
	}{
		{
			name:    "UnauthCtx",
			src:     Context(),
			ctx:     ctx,
			bjwtErr: ogenerrors.ErrSkipClientSecurity,
			skeyErr: ogenerrors.ErrSkipClientSecurity,
		},
		{
			name:    "BerlogaJWT",
			src:     Context(),
			ctx:     berauth.SetPlayer(ctx, berauth.Player{Token: "playerToken"}),
			bjwtTok: "playerToken",
			skeyErr: ogenerrors.ErrSkipClientSecurity,
		},
		{
			name:    "ServiceKey",
			src:     Context(),
			ctx:     berauth.SetServiceKey(ctx, "serviceKey"),
			bjwtErr: ogenerrors.ErrSkipClientSecurity,
			skeyTok: "serviceKey",
		},
		{
			name:    "BerlogaJWT",
			src:     BerlogaJWT("testToken"),
			bjwtTok: "testToken",
			skeyErr: ogenerrors.ErrSkipClientSecurity,
		},
		{
			name:    "ServiceKey",
			src:     ServiceKey("testToken"),
			bjwtErr: ogenerrors.ErrSkipClientSecurity,
			skeyTok: "testToken",
		},
	} {
		if tt.ctx == nil {
			tt.ctx = context.Background()
		}
		tok, err := tt.src.BerlogaJWT(tt.ctx, "testOp")
		if tok != tt.bjwtTok {
			t.Errorf("BerlogaJWT токен содержит `%s`, ожидалось `%s`", tok, tt.bjwtTok)
		}
		if err != tt.bjwtErr {
			t.Errorf("BerlogaJWT ошибка содержит `%v`, ожидалось `%v`", tok, tt.bjwtTok)
		}
		tok, err = tt.src.ServiceKey(tt.ctx, "testOp")
		if tok != tt.skeyTok {
			t.Errorf("ServiceKey токен содержит `%s`, ожидалось `%s`", tok, tt.skeyTok)
		}
		if err != tt.skeyErr {
			t.Errorf("ServiceKey ошибка содержит `%v`, ожидалось `%v`", tok, tt.skeyTok)
		}
	}
}
