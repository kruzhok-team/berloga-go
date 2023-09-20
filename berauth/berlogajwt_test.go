package berauth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

func TestGetSetPlayer(t *testing.T) {
	if _, err := GetPlayer(context.Background()); err != ErrMissingBerlogaJWT {
		t.Errorf("GetPlayer() вернула в ошибке `%v`, ожидалось `%v`", err, ErrMissingBerlogaJWT)
	}
	player := Player{Token: "test"}
	got, err := GetPlayer(SetPlayer(context.Background(), player))
	if err != nil {
		t.Fatalf("GetPlayer(SetPlayer()) вернула ошибку %v", err)
	}
	if got.Token != "test" {
		t.Errorf("Token = %v, ожидалось %v", got.Token, "test")
	}
}

func TestHasBerlogaJWT(t *testing.T) {
	if HasBerlogaJWT(context.Background()) {
		t.Errorf("HasBerlogaJWT() вернула true вместо false")
	}
	if !HasBerlogaJWT(SetPlayer(context.Background(), Player{})) {
		t.Errorf("HasBerlogaJWT() вернула false вместо true")
	}
}

func TestBerlogaJWTAuth(t *testing.T) {
	type tc struct {
		t          *testing.T
		private    jwk.Key
		credetials string
		test       func(context.Context)
	}

	for _, tt := range []struct {
		name string
		errm string
		init func(*tc)
	}{
		{
			name: "missing-credentials",
			errm: ErrUnauthorized.Error(),
		},
		{
			name: "credentials-invalid-jwt",
			errm: "invalid JWT",
			init: func(tc *tc) {
				tc.credetials = "bullshit"
			},
		},
		{
			name: "credentials-invalid-key",
			errm: "could not verify message using any of the signatures or keys",
			init: func(tc *tc) {
				token := jwt.New()
				key, err := rsa.GenerateKey(rand.Reader, 2048)
				if err != nil {
					tc.t.Fatalf("Ошибка генерации RSA ключа: %v", err)
				}
				private, err := jwk.FromRaw(key)
				if err != nil {
					tc.t.Fatalf("Ошибка создания JWK: %v", err)
				}
				private.Set(jwk.KeyIDKey, `testKey`)
				signed, err := jwt.Sign(token, jwt.WithKey(jwa.RS256, private))
				if err != nil {
					tc.t.Fatalf("Ошибка подписи токена %v", err)
				}
				tc.credetials = string(signed)
			},
		},
		{
			name: "valid-credentials",
			init: func(tc *tc) {
				token := jwt.New()
				playerID := uuid.New()
				applicationID := uuid.New()
				if err := token.Set(jwt.IssuerKey, applicationID.String()); err != nil {
					tc.t.Fatalf("token.Set(jwt.IssuerKey, applicationID) = %v", err)
				}
				if err := token.Set(jwt.SubjectKey, playerID.String()); err != nil {
					tc.t.Fatalf("token.Set(jwt.SubjectKey, playerID) = %v", err)
				}
				signed, err := jwt.Sign(token, jwt.WithKey(jwa.RS256, tc.private))
				if err != nil {
					tc.t.Fatalf("Ошибка подписи токена %v", err)
				}
				tc.credetials = string(signed)
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			key, err := rsa.GenerateKey(rand.Reader, 2048)
			if err != nil {
				t.Fatalf("Ошибка генерации RSA ключа: %v", err)
			}
			private, err := jwk.FromRaw(key)
			if err != nil {
				t.Fatalf("Ошибка создания JWK: %v", err)
			}
			private.Set(jwk.KeyIDKey, `testKey`)
			public, err := jwk.PublicKeyOf(private)
			if err != nil {
				t.Fatalf("Ошибка получения публичного ключа: %v", err)
			}
			public.Set(jwk.AlgorithmKey, jwa.RS256)
			var set = jwk.NewSet()
			set.AddKey(public)

			tc := &tc{t: t, private: private}
			if tt.init != nil {
				tt.init(tc)
			}
			ctx, err := BerlogaJWT(set).Auth(context.Background(), tc.credetials)
			var errm string
			if err != nil {
				errm = err.Error()
			}
			if errm != tt.errm {
				t.Fatalf("Auth() вернул в ошибке `%s`, ожидалось `%s`", err, tt.errm)
			}
			if err == nil {
				if tc.test != nil {
					tc.test(ctx)
				}
			}
		})
	}
}
