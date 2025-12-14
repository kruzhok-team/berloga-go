package berauth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
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
		t           *testing.T
		private     jwk.Key
		credentials string
		test        func(context.Context) error
	}

	token := func(tc *tc) jwt.Token {
		token := jwt.New()
		playerID := uuid.New()
		applicationID := uuid.New()
		if err := token.Set(jwt.IssuerKey, applicationID.String()); err != nil {
			tc.t.Fatalf("token.Set(jwt.IssuerKey, applicationID) = %v", err)
		}
		if err := token.Set(jwt.SubjectKey, playerID.String()); err != nil {
			tc.t.Fatalf("token.Set(jwt.SubjectKey, playerID) = %v", err)
		}
		return token
	}

	signToken := func(tc *tc, token jwt.Token, key jwk.Key) {
		signed, err := jwt.Sign(token, jwt.WithKey(jwa.RS256, key))
		if err != nil {
			tc.t.Fatalf("Ошибка подписи токена %v", err)
		}
		tc.credentials = string(signed)
	}

	validateClaim := func(ctx context.Context, key string, want any) error {
		player, err := GetPlayer(ctx)
		if err != nil {
			return err
		}
		v, ok := player.JWT.Get(key)
		if !ok {
			return fmt.Errorf("отсутствует ключ %q", key)
		}
		var typeMatch bool
		var valueMatch bool
		switch want := want.(type) {
		case string:
			var got string
			got, typeMatch = v.(string)
			valueMatch = want == got
		}
		if !typeMatch {
			return fmt.Errorf("claim %q содержит %q типа %T, ожидалось значение типа %T", key, v, v, want)
		}
		if !valueMatch {
			return fmt.Errorf("claim %q содержит %q, ожидалось %q", key, v, want)
		}
		return nil
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
				tc.credentials = "bullshit"
			},
		},
		{
			name: "credentials-invalid-key",
			errm: "could not verify message using any of the signatures or keys",
			init: func(tc *tc) {
				key, err := rsa.GenerateKey(rand.Reader, 2048)
				if err != nil {
					tc.t.Fatalf("Ошибка генерации RSA ключа: %v", err)
				}
				private, err := jwk.FromRaw(key)
				if err != nil {
					tc.t.Fatalf("Ошибка создания JWK: %v", err)
				}
				private.Set(jwk.KeyIDKey, `testKey`)
				signToken(tc, jwt.New(), private)
			},
		},
		{
			name: "valid-credentials",
			init: func(tc *tc) {
				signToken(tc, token(tc), tc.private)
			},
		},
		{
			name: "client_name",
			init: func(tc *tc) {
				token := token(tc)
				clientName := "example_name"
				if err := token.Set(BerlogaJWTClientName, clientName); err != nil {
					tc.t.Fatalf(`token.Set(BerlogaJWTClientName, %q) = %v`, clientName, err)
				}
				signToken(tc, token, tc.private)
				tc.test = func(ctx context.Context) error {
					return validateClaim(ctx, BerlogaJWTClientName, clientName)
				}
			},
		},
		{
			name: "client_version",
			init: func(tc *tc) {
				token := token(tc)
				clientVersion := "example_version"
				if err := token.Set(BerlogaJWTClientVersion, clientVersion); err != nil {
					tc.t.Fatalf(`token.Set(BerlogaJWTClientVersion, %q) = %v`, clientVersion, err)
				}
				signToken(tc, token, tc.private)
				tc.test = func(ctx context.Context) error {
					return validateClaim(ctx, BerlogaJWTClientVersion, clientVersion)
				}
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
			ctx, err := BerlogaJWT(set).Auth(context.Background(), tc.credentials)
			var errm string
			if err != nil {
				errm = err.Error()
			}
			if tt.errm != "" {
				tt.errm = "credentials auth: " + tt.errm
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
