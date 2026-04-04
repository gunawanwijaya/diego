package service

import (
	"context"
	"encoding/json"
	"io"
	"net"

	"github.com/gunawanwijaya/diego/pkg"
)

type Service[T any] interface {
	io.Closer
	Serve(l net.Listener) error
	Shutdown(ctx context.Context) error
	pkg.Validator
}

type JSONRequest struct {
	Data       map[string]json.RawMessage `json:"data"`
	Extensions map[string]json.RawMessage `json:"extensions,omitempty"`
}

type JSONResponse struct {
	Data       map[string]any `json:"data,omitempty"`
	Errors     JSONErrors     `json:"errors,omitempty"`
	Extensions map[string]any `json:"extensions,omitempty"`
}

type JSONResponses []JSONResponse

func (x JSONResponses) Merge() (res JSONResponse) {
	for _, e := range x {
		for k, v := range e.Data {
			if k == "" || v == nil {
				continue
			}
			if res.Data == nil {
				res.Data = map[string]any{}
			}
			res.Data[k] = v
		}
		res.Errors = append(res.Errors, e.Errors...)
		for k, v := range e.Extensions {
			if k == "" || v == nil {
				continue
			}
			if res.Extensions == nil {
				res.Extensions = map[string]any{}
			}
			res.Extensions[k] = v
		}
	}
	return
}

func NewJSONErrors(errs ...error) JSONErrors { return *new(JSONErrors).Store(errs...) }

type JSONErrors []json.RawMessage

func (x JSONErrors) Load() (errs []error) {
	for _, p := range x {
		v := map[string]string{}
		_ = json.Unmarshal(p, &v)
		if m, ok := v["message"]; ok && m != "" {
			errs = append(errs, pkg.ErrorStr(m))
		}
	}
	return errs
}
func (x *JSONErrors) Append(errs ...error) *JSONErrors {
	for _, err := range errs {
		for _, err = range unwrap(err) {
			p, _ := json.Marshal(map[string]string{"message": err.Error()})
			*x = append(*x, p)
		}
	}
	return x
}
func (x *JSONErrors) Store(errs ...error) *JSONErrors { *x = JSONErrors{}; return x.Append(errs...) }

func unwrap(err error) (errs []error) {
	if err != nil {
		switch x := any(err).(type) {
		default:
			errs = append(errs, err)
		case []error:
			errs = x
		// case interface{ Unwrap() error }:
		// 	errs = append(errs, unwrap(errors.Unwrap(err))...)
		case interface{ Unwrap() []error }:
			for _, err = range x.Unwrap() {
				errs = append(errs, unwrap(err)...)
			}
		}
	}
	return errs
}
