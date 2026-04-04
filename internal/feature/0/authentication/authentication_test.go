package authentication_test

import (
	"context"
	"net/http/httptest"
	"testing"

	"github.com/gunawanwijaya/diego/internal/feature/0/authentication"
	"github.com/gunawanwijaya/diego/pkg"
)

func TestAuthentication(t *testing.T) {
	var ctx, cancel = context.WithCancelCause(context.Background())
	defer cancel(nil)
	var cfg = authentication.Configuration{}
	var dep = authentication.Dependency{}
	var authn = pkg.Must1(authentication.New(ctx, cfg, dep))

	{
		var w = httptest.NewRecorder()
		var r = httptest.NewRequest("", "/", nil)
		authn.GET_Authenticate().ServeHTTP(w, r)
		t.Log(w.Body.String())
	}
}
