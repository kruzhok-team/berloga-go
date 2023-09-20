package berauth

import (
	"context"
	"testing"
)

func TestHasSetServiceKey(t *testing.T) {
	if HasServiceKey(context.Background()) {
		t.Errorf("HasServiceKey() вернула true вместо false")
	}
	if !HasServiceKey(SetServiceKey(context.Background())) {
		t.Errorf("HasServiceKey() вернула false вместо true")
	}
}

func TestServiceKeyAuth(t *testing.T) {
	for _, tt := range []struct {
		name string
		key  string
		cred string
		errm string
		has  bool
	}{
		{
			name: "missing-service-key",
			errm: ErrMissingServiceKey.Error(),
			cred: "valid-value",
		},
		{
			name: "missing-credentials",
			errm: ErrUnauthorized.Error(),
		},
		{
			name: "invalid-credentials",
			errm: ErrUnauthorized.Error(),
			key:  "valid-value",
			cred: "other-value",
		},
		{
			name: "valid-credentials",
			key:  "valid-value",
			cred: "valid-value",
			has:  true,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			ctx, err := ServiceKey(tt.key).Auth(context.Background(), tt.cred)
			var errm string
			if err != nil {
				errm = err.Error()
			}
			if errm != tt.errm {
				t.Fatalf("В ошибке `%s`, ожидалось `%s`", err, tt.errm)
			}
			if err == nil {
				if has := HasServiceKey(ctx); has != tt.has {
					t.Errorf("HasServiceKey(ctx) = %v, ожидалось %v", has, tt.has)
				}
			}
		})
	}
}
