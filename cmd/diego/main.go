package main

import (
	"context"
	"log/slog"
	"net"
	"net/http"
	"os"

	"github.com/gunawanwijaya/diego/internal/repository/datastore"
	"github.com/gunawanwijaya/diego/internal/service"
	"github.com/gunawanwijaya/diego/internal/service/httprest"
	"github.com/gunawanwijaya/diego/pkg"
)

func main() {
	var (
		ctx = context.Background()
		cfg Configuration
		dep Dependency
		nop = func(...any) { /*.*/ }
	)

	slog.SetDefault(slog.New(errorLevelHandler{slog.NewJSONHandler(os.Stdout, errorLevelHandlerOptions)}))

	pkg.Must(build(ctx, &cfg, &dep))

	// slog.InfoContext(ctx, "load", slog.Any("cfg", cfg), slog.Any("dep", dep))

	repoDatastore := pkg.Must1(datastore.New(ctx, cfg.Repository.Datastore, dep.Repository.Datastore))

	// featRole := pkg.Must1(role.New(ctx, cfg.Feature.Role, dep.Feature.Role))

	// dep.Service.WebSocket = websocket.Dependency{
	// 	MapHandlerJSON: map[string]websocket.HandlerJSON{
	// 		"/v1/echo": func(ctx context.Context, wshs ws.Handshake, wshd ws.Header, req service.JSONRequest) (res service.JSONResponse, err error) {
	// 			k := "/v1/echo"
	// 			res.Data = map[string]any{k: req.Data[k]}
	// 			return
	// 		},
	// 		"/v1/version": func(ctx context.Context, wshs ws.Handshake, wshd ws.Header, req service.JSONRequest) (res service.JSONResponse, err error) {
	// 			return
	// 		},
	// 	},
	// }
	// svcWebSocket := pkg.Must1(websocket.New(ctx, cfg.Service.WebSocket, dep.Service.WebSocket))

	dep.Service.HTTPREST = httprest.Dependency{
		MapHandler: map[string]http.Handler{
			"/favicon.ico": http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte{}) }),
			// "/.well-known/jwks.json": &jwksHandler{},
			// "/ws":                    svcWebSocket,
		},
		MapHandlerJSON: map[string]httprest.HandlerJSON{
			"/v1/echo/{text}": func(ctx context.Context, req service.JSONRequest, r *http.Request, wCode *int, wHeader *http.Header) (res service.JSONResponse, err error) {
				k := "/v1/echo"
				res.Data = map[string]any{k: r.PathValue("text")}
				return
			},
			"/v1/version": func(ctx context.Context, req service.JSONRequest, r *http.Request, wCode *int, wHeader *http.Header) (res service.JSONResponse, err error) {
				return
			},
		},
	}
	svcHttpRest := pkg.Must1(httprest.New(ctx, cfg.Service.HTTPREST, dep.Service.HTTPREST))

	l := pkg.Must1(net.Listen("tcp", ":8080"))
	svcHttpRest.Serve(l)

	nop(
		repoDatastore,
		// featRole,
		svcHttpRest,
		// svcWebSocket,
	)
}

// ---------------------------------------------------------------------------------------------------------------------
type errorLevelHandler struct{ slog.Handler }

func (x errorLevelHandler) Handle(ctx context.Context, r slog.Record) error {
	r.Attrs(func(a slog.Attr) bool {
		if a.Key == "err" {
			if err, isErr := a.Value.Any().(error); isErr && err != nil {
				r.Level = slog.LevelError //change level to error
			}
		}
		return true
	})
	return x.Handler.Handle(ctx, r)
}

var errorLevelHandlerOptions = &slog.HandlerOptions{
	AddSource: false,
	ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
		// const red = "[redacted]"
		if a.Key == "err" {
			if err, isErr := a.Value.Any().(error); !isErr || err == nil {
				return slog.Attr{}
			}
		}
		return a
	},
}

// ---------------------------------------------------------------------------------------------------------------------
// type jwksHandler struct {
// 	cache map[string]pkg.JWKS
// }

// func (h *jwksHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
// 	if h.cache == nil {
// 		h.cache = map[string]pkg.JWKS{}
// 	}
// 	type end struct{}
// 	var redirect = func(url string, code int) (_ end) {
// 		http.Redirect(w, r, url, code)
// 		return
// 	}
// 	var responseJWKS = func(jwks pkg.JWKS, errs service.JSONErrors) (_ end) {
// 		w.Header().Set("content-type", "application/jwk+json")
// 		_ = json.NewEncoder(w).Encode(struct {
// 			Keys   pkg.JWKS           `json:"keys"`
// 			Errors service.JSONErrors `json:"errors,omitempty"`
// 		}{jwks, errs})
// 		return
// 	}
// 	_ = func() (_ end) {
// 		switch r.Method { // -------------------------------------------------------------------------------
// 		default:
// 			return responseJWKS(pkg.JWKS{}, nil)
// 		case http.MethodGet: // ----------------------------------------------------------------------------
// 			if jwks, ok := h.cache[r.URL.Query().Get("ephemeral")]; ok {
// 				return responseJWKS(jwks, nil)
// 			}
// 			return responseJWKS(pkg.JWKS{}, nil)
// 		case http.MethodPost: // ---------------------------------------------------------------------------
// 			var req struct{ Keys pkg.JWKS }
// 			var err = json.NewDecoder(r.Body).Decode(&req)
// 			var keys = req.Keys
// 			switch {
// 			default:
// 				err = pkg.ErrorStr("expecting 1 EC public key or 2 public keys of x25519 & Ed255129")
// 				return responseJWKS(nil, service.NewJSONErrors(err))
// 			case err != nil:
// 				return responseJWKS(nil, service.NewJSONErrors(err))
// 			case len(keys) == 1:
// 				var ecPub = &ecdsa.PublicKey{}
// 				if !keys[0].As(&ecPub) {
// 					err = pkg.ErrorStr("expecting an EC public key when sending with 1 key")
// 					return responseJWKS(nil, service.NewJSONErrors(err))
// 				}
// 				switch ecPub.Curve {
// 				default:
// 					err = pkg.ErrorStr("invalid EC curve")
// 					return responseJWKS(nil, service.NewJSONErrors(err))
// 				case elliptic.P256(), elliptic.P384(), elliptic.P521():
// 					//
// 				}
// 				var ecKey *ecdsa.PrivateKey
// 				if ecKey, err = ecdsa.GenerateKey(ecPub.Curve, rand.Reader); err != nil {
// 					return responseJWKS(nil, service.NewJSONErrors(err))
// 				}
// 				eph := xid.New().String()
// 				h.cache[eph] = pkg.JWKS{
// 					pkg.NewJWK(&ecKey.PublicKey).WithKID(xid.New().String()),
// 				}
// 				url := r.URL.Path + "?ephemeral=" + eph
// 				return redirect(url, http.StatusFound)
// 			case len(keys) == 2:
// 				var edPub ed25519.PublicKey
// 				var xPub = &ecdh.PublicKey{}
// 				if !((keys[0].As(&edPub) && keys[1].As(&xPub)) || (keys[0].As(&xPub) && keys[1].As(&edPub))) {
// 					err = pkg.ErrorStr("expecting an Ed25519 & X25519 public key when sending with 2 keys")
// 					return responseJWKS(nil, service.NewJSONErrors(err))
// 				}

// 				var xKey *ecdh.PrivateKey
// 				if xKey, err = xPub.Curve().GenerateKey(rand.Reader); err != nil {
// 					return responseJWKS(nil, service.NewJSONErrors(err))
// 				}
// 				var edKey ed25519.PrivateKey
// 				var edPub0 ed25519.PublicKey
// 				if edPub0, edKey, err = ed25519.GenerateKey(rand.Reader); err != nil {
// 					return responseJWKS(nil, service.NewJSONErrors(err))
// 				}
// 				eph := xid.New().String()
// 				h.cache[eph] = pkg.JWKS{
// 					pkg.NewJWK(edPub0).WithKID(xid.New().String()),
// 					pkg.NewJWK(xKey.PublicKey()).WithKID(xid.New().String()),
// 				}
// 				_ = edKey
// 				url := r.URL.Path + "?ephemeral=" + eph
// 				return redirect(url, http.StatusFound)
// 			}
// 		} // -----------------------------------------------------------------------------------------------
// 	}()
// }

// catalog      - manage (create/update) product, details, mapping (e.g. 1 box = 40 pcs of indomie or 1 chicken steak = 200gr chicken fillet, 50gr fries, 50gr ranch sauce)
// inventory    - stock keeping, manage shelves/racks, lost/expired articles & return to supplier
// orderspot    - spot (table/takeaway), cart of products, payment, order request
// transaction  - orderspot selling & return from customer
// intelligence - product bundling, promo, pricing
