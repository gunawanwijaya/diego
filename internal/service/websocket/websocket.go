package websocket

// import (
// 	"bufio"
// 	"compress/flate"
// 	"context"
// 	"encoding/json"
// 	"errors"
// 	"io"
// 	"log/slog"
// 	"net"
// 	"net/http"
// 	"sync/atomic"
// 	"time"

// 	"github.com/gobwas/ws"
// 	"github.com/gobwas/ws/wsflate"
// 	"github.com/gobwas/ws/wsutil"
// 	"github.com/gunawanwijaya/diego/internal/service"
// 	"github.com/gunawanwijaya/diego/pkg"
// )

// type Configuration struct {
// 	ShutdownTimeout time.Duration
// 	ReadTimeout     time.Duration
// 	WriteTimeout    time.Duration
// 	MaxFrameSize    int64
// }

// func (x Configuration) Validate() (err error) {
// 	if max := 30 * time.Second; x.ShutdownTimeout < 0 || x.ShutdownTimeout > max {
// 		x.ShutdownTimeout = max
// 	}
// 	return nil
// }

// type HandlerJSON func(ctx context.Context, wshs ws.Handshake, wshd ws.Header, req service.JSONRequest) (res service.JSONResponse, err error)

// type Dependency struct {
// 	MapHandlerJSON map[string]HandlerJSON `json:"-"`
// }

// func (x Dependency) Validate() (err error) {
// 	if len(x.MapHandlerJSON) < 1 {
// 		return pkg.ErrorStr("required to have a valid map handler")
// 	}
// 	for k, v := range x.MapHandlerJSON {
// 		if k == "" {
// 			return pkg.ErrorStr("required to have a valid map handler key")
// 		}
// 		if v == nil {
// 			return pkg.ErrorStr("required to have a valid map handler func")
// 		}
// 	}
// 	return nil
// }

// type WebSocket interface {
// 	service.Service[WebSocket]
// 	http.Handler
// }

// type websocket struct {
// 	Configuration
// 	Dependency

// 	ext *wsflate.Extension
// 	flags
// }

// type flags struct {
// 	isClosing atomic.Bool
// 	hasClosed atomic.Bool
// }

// func New(ctx context.Context, cfg Configuration, dep Dependency) (_ WebSocket, err error) {
// 	ext := &wsflate.Extension{
// 		Parameters: wsflate.DefaultParameters,
// 	}
// 	return pkg.Validate(&websocket{cfg, dep, ext, flags{}})
// }

// func (x *websocket) Validate() (err error) {
// 	if _, err = pkg.Validate(x.Configuration); err != nil {
// 		return err
// 	}
// 	if _, err = pkg.Validate(x.Dependency); err != nil {
// 		return err
// 	}

// 	return nil
// }

// const (
// 	ErrServerClosed        = pkg.ErrorStr("service/websocket: Server closed")
// 	ErrTerminateConnection = pkg.ErrorStr("service/websocket: Terminate connection")
// )

// func (x *websocket) Close() error { return x.Shutdown(context.Background()) }

// func (x *websocket) Shutdown(ctx context.Context) error {
// 	if x.hasClosed.Load() {
// 		return ErrServerClosed
// 	}

// 	ctx, cancel := context.WithTimeout(ctx, x.ShutdownTimeout)
// 	defer cancel()
// 	x.isClosing.Store(true)
// 	return nil
// }

// func (x *websocket) ServeHTTP(w http.ResponseWriter, r *http.Request) {
// 	if x.hasClosed.Load() {
// 		return // ErrServerClosed
// 	}
// 	x.ext.Reset()
// 	u := ws.HTTPUpgrader{
// 		Negotiate: x.ext.Negotiate,
// 	}
// 	x.serve(u.Upgrade(r, w))
// }

// func (x *websocket) Serve(l net.Listener) (err error) {
// 	slog.Info("serve", slog.String("addr", l.Addr().String()))
// 	for {
// 		if x.hasClosed.Load() {
// 			return ErrServerClosed
// 		}
// 		var conn net.Conn
// 		var wshs ws.Handshake
// 		if conn, err = l.Accept(); err != nil {
// 			return err
// 		}
// 		x.ext.Reset()
// 		u := ws.Upgrader{
// 			Negotiate: x.ext.Negotiate,
// 		}
// 		if wshs, err = u.Upgrade(conn); err != nil {
// 			return err
// 		}
// 		go x.serve(conn, nil, wshs, err)
// 	}
// }

// func (x *websocket) serve(conn net.Conn, _ *bufio.ReadWriter, wshs ws.Handshake, err error) {
// 	ctx, cancel := context.WithCancelCause(context.Background())
// 	defer func() { cancel(err) }()
// 	defer conn.Close()
// 	var ch = wsutil.ControlFrameHandler(conn, ws.StateServerSide)
// 	var rd *wsutil.Reader
// 	var wr *wsutil.Writer
// 	var msg wsflate.MessageState
// 	var fr = wsflate.NewReader(nil, func(r io.Reader) wsflate.Decompressor { return flate.NewReader(r) })
// 	var fw = wsflate.NewWriter(nil, func(w io.Writer) wsflate.Compressor { f, _ := flate.NewWriter(w, 9); return f })

// 	if _, ok := x.ext.Accepted(); ok {
// 		state := ws.StateServerSide | ws.StateExtended
// 		rd, wr = &wsutil.Reader{Source: conn, OnIntermediate: ch, MaxFrameSize: x.Configuration.MaxFrameSize,
// 			State:      state,
// 			Extensions: []wsutil.RecvExtension{&msg},
// 		}, wsutil.NewWriter(conn, state, 0)
// 		wr.SetExtensions(&msg)
// 	} else {
// 		state := ws.StateServerSide
// 		rd, wr = &wsutil.Reader{Source: conn, OnIntermediate: ch, MaxFrameSize: x.Configuration.MaxFrameSize,
// 			State:     state,
// 			CheckUTF8: true,
// 		}, wsutil.NewWriter(conn, state, 0)
// 	}

// 	for {
// 		if x.Configuration.ReadTimeout > 0 {
// 			_ = conn.SetReadDeadline(time.Now().Add(x.Configuration.ReadTimeout))
// 		}
// 		if x.Configuration.WriteTimeout > 0 {
// 			_ = conn.SetWriteDeadline(time.Now().Add(x.Configuration.WriteTimeout))
// 		}
// 		if x.isClosing.Load() && !x.hasClosed.Load() {
// 			x.hasClosed.Store(true)
// 			return
// 		}
// 		var wshd ws.Header
// 		if wshd, err = rd.NextFrame(); err != nil {
// 			return
// 		} else if wshd.OpCode.IsControl() {
// 			if err = ch(wshd, rd); err != nil {
// 				return
// 			}
// 			continue
// 		}

// 		wr.ResetOp(wshd.OpCode)
// 		var src io.Reader = rd
// 		var dst io.Writer = wr
// 		if msg.IsCompressed() {
// 			fr.Reset(src)
// 			fw.Reset(dst)
// 			src = fr
// 			dst = fw
// 		}

// 		var req service.JSONRequest
// 		var res service.JSONResponse
// 		if err = json.NewDecoder(src).Decode(&req); err != nil {
// 			return
// 		}
// 		if res, err = x.handle(ctx, wshs, wshd, req); err != nil {
// 			return
// 		}
// 		if err = json.NewEncoder(dst).Encode(res); err != nil {
// 			return
// 		}
// 		if msg.IsCompressed() {
// 			if err = fw.Close(); err != nil {
// 				return
// 			}
// 		}
// 		if err = wr.Flush(); err != nil {
// 			return
// 		}
// 	}
// }

// func (x *websocket) handle(ctx context.Context, wshs ws.Handshake, wshd ws.Header, req service.JSONRequest) (res service.JSONResponse, err error) {
// 	var ress service.JSONResponses
// 	var errs []error
// 	for k := range req.Data {
// 		fn, ok := x.MapHandlerJSON[k]
// 		if !ok {
// 			continue
// 		}
// 		res, err = fn(ctx, wshs, wshd, req)
// 		slog.DebugContext(ctx, "handle",
// 			slog.Any("wshs", wshs),
// 			slog.Any("wshd", wshd),
// 			slog.Any("req", req),
// 			slog.Any("res", res),
// 			slog.Any("err", err),
// 		)
// 		ress = append(ress, res)
// 		switch {
// 		default:
// 			errs = append(errs, err)
// 		case errors.Is(err, ErrTerminateConnection):
// 			return service.JSONResponse{}, err
// 		}
// 	}
// 	res = ress.Merge()
// 	res.Errors.Store(errs...)
// 	return res, nil
// }
