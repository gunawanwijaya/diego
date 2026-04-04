package httprest

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"html/template"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"github.com/gunawanwijaya/diego/internal/service"
	"github.com/gunawanwijaya/diego/pkg"
)

type Configuration struct {
	ShutdownTimeout   time.Duration `json:"shutdown_timeout"`
	IdleTimeout       time.Duration `json:"idle_timeout"`
	ReadTimeout       time.Duration `json:"read_timeout"`
	WriteTimeout      time.Duration `json:"write_timeout"`
	ReadHeaderTimeout time.Duration `json:"read_header_timeout"`
	MaxHeaderBytes    int           `json:"max_header_bytes"`
}

func (x Configuration) Validate() (err error) {
	return nil
}

var (
	_ embed.FS

	//go:embed tmpl.html
	tmpl_html string

	t = template.Must(template.New("").Parse(strings.ReplaceAll(tmpl_html, "<html lang", "<html")))
)

type HandlerHTML func(ctx context.Context, t *template.Template, v *map[string]any, r *http.Request, wCode *int, wHeader *http.Header) (err error)

func (h HandlerHTML) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var wCode int
	var wHeader = w.Header()
	var cn pkg.ContentNegotiate
	_ = cn.UnmarshalText([]byte(r.Header.Get("accept-language")))
	var lang = "en"
	var cf = cn.Filter(func(c string, q float64) bool {
		return q > .8 && strings.HasPrefix(c, "id")
	})
	if len(cf) > 0 {
		lang = cf[0].Content
	}

	var v = map[string]any{
		"html_attr":       template.HTMLAttr(`lang="` + lang + `"`),
		"html_head_attr":  template.HTMLAttr(``),
		"html_body_attr":  template.HTMLAttr(``),
		"html_head_title": "diego",
		"html_head":       template.HTML(``),
	}
	var tClone = template.Must(t.Clone())
	var err = h(r.Context(), tClone, &v, r, &wCode, &wHeader)
	if err != nil {
		http.Error(w, err.Error(), wCode)
		return
	}
	if wCode > 0 && http.StatusText(wCode) != "" {
		w.WriteHeader(wCode)
	}
	w.Header().Set("content-type", "text/html")
	_ = tClone.Execute(w, v)
}

type HandlerJSON func(ctx context.Context, req service.JSONRequest, r *http.Request, wCode *int, wHeader *http.Header) (res service.JSONResponse, err error)

func (h HandlerJSON) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var err error
	var req service.JSONRequest
	var res service.JSONResponse
	var wCode int
	var wHeader = w.Header()

	if err = json.NewDecoder(r.Body).Decode(&req); err != nil && !errors.Is(err, io.EOF) {
		res.Errors = *res.Errors.Store(err)
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(res)
		return
	}
	res, err = h(r.Context(), req, r, &wCode, &wHeader)
	res.Errors = *res.Errors.Store(err)
	if wCode > 0 && http.StatusText(wCode) != "" {
		w.WriteHeader(wCode)
	}
	w.Header().Set("content-type", "application/json")
	_ = json.NewEncoder(w).Encode(res)
}

type Dependency struct {
	MapHandler     map[string]http.Handler `json:"-"`
	MapHandlerJSON map[string]HandlerJSON  `json:"-"`
}

func (x Dependency) Validate() (err error) {
	if len(x.MapHandlerJSON) < 1 {
		return pkg.ErrorStr("required to have a valid map handler")
	}
	for k, v := range x.MapHandlerJSON {
		if k == "" {
			return pkg.ErrorStr("required to have a valid map handler key")
		}
		if v == nil {
			return pkg.ErrorStr("required to have a valid map handler func")
		}
	}
	if len(x.MapHandler) < 1 {
		return pkg.ErrorStr("required to have a valid map handler")
	}
	for k, v := range x.MapHandler {
		if k == "" {
			return pkg.ErrorStr("required to have a valid map handler key")
		}
		if v == nil {
			return pkg.ErrorStr("required to have a valid map handler func")
		}
	}
	return nil
}

type HTTPREST interface{ service.Service[HTTPREST] }

type httprest struct {
	Configuration
	Dependency
	*http.Server
	flags
}

type flags struct {
	isClosing atomic.Bool
	hasClosed atomic.Bool
}

func New(ctx context.Context, cfg Configuration, dep Dependency) (_ HTTPREST, err error) {
	var handler = func() http.Handler {
		var mux = &http.ServeMux{}
		for k, h := range dep.MapHandler {
			if k != "" && h != nil {
				mux.Handle(k, h)
			}
		}
		for k, fn := range dep.MapHandlerJSON {
			if k != "" && fn != nil {
				mux.Handle(k, fn)
			}
		}
		return mux
	}()
	var srv = &http.Server{
		Addr:                         "",
		Handler:                      handler,
		DisableGeneralOptionsHandler: false,
		TLSConfig:                    nil,
		ReadTimeout:                  cfg.ReadTimeout,
		ReadHeaderTimeout:            cfg.ReadHeaderTimeout,
		WriteTimeout:                 cfg.WriteTimeout,
		IdleTimeout:                  cfg.IdleTimeout,
		MaxHeaderBytes:               cfg.MaxHeaderBytes,
		TLSNextProto:                 nil,
		ConnState:                    func(c net.Conn, cs http.ConnState) { /*.*/ },
		ErrorLog:                     nil,
		BaseContext:                  func(l net.Listener) context.Context { return ctx },
		ConnContext:                  func(ctx context.Context, c net.Conn) context.Context { return ctx },
	}
	return pkg.Validate(&httprest{cfg, dep, srv, flags{}})
}

func (x *httprest) Validate() (err error) {
	if _, err = pkg.Validate(x.Configuration); err != nil {
		return err
	}
	if _, err = pkg.Validate(x.Dependency); err != nil {
		return err
	}
	return nil
}

func (x *httprest) Serve(l net.Listener) (err error) {
	slog.Info("serve", slog.String("addr", l.Addr().String()))
	return x.Server.Serve(l)
}
