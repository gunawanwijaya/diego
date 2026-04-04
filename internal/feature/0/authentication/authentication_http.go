package authentication

import (
	"context"
	"embed"
	"html/template"
	"net/http"

	"github.com/gunawanwijaya/diego/internal/service/httprest"
	"github.com/gunawanwijaya/diego/pkg"
)

var (
	_ embed.FS

	//go:embed _get.authenticate.tmpl.html
	get_authenticate_tmpl_html string
)

type AuthenticationHTTP interface {
	GET_Authenticate() http.Handler
}

func (x *authentication) GET_Authenticate() http.Handler {
	return httprest.HandlerHTML(func(ctx context.Context, t *template.Template, v *map[string]any, r *http.Request, wCode *int, wHeader *http.Header) (err error) {
		(*v)["get_authenticate_csrf"] = pkg.B64RawUrl(pkg.Nonce(64))
		(*v)["get_authenticate_submit"] = "Masuk"
		_, err = t.Parse(`{{define "body"}}` + get_authenticate_tmpl_html + `{{end}}`)
		return
	})
}
