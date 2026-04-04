package httprest_test

import (
	"context"
	"html/template"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gunawanwijaya/diego/internal/service/httprest"
)

func TestHTTPREST(t *testing.T) {
	var w = httptest.NewRecorder()
	var r = httptest.NewRequest(http.MethodGet, "/", nil)
	var h = httprest.HandlerHTML(func(ctx context.Context, tmpl *template.Template, v *map[string]any, r *http.Request, wCode *int, wHeader *http.Header) (err error) {
		tmpl.Parse(`
{{define "body"}}
hello world
{{end}}`)
		return
	})

	r.Header.Set("accept-language", "de")
	h.ServeHTTP(w, r)
	t.Log(w.Body.String())
}
