package service_test

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/gunawanwijaya/diego/internal/service"
	"github.com/gunawanwijaya/diego/pkg"
)

func TestJSONResponseError(t *testing.T) {
	var (
		res1 service.JSONResponse
		res2 service.JSONResponse
		p    []byte
	)

	res1.Errors.Store(
		pkg.ErrorStr("error 1"),
		errors.Join(
			pkg.ErrorStr("error 2.1"),
			pkg.Errorf("error 2.2.1 %w", pkg.ErrorStr("error 2.2.2")),
			pkg.ErrorStr("error 2.3"),
		),
		pkg.ErrorStr("error 3"),
	)

	p = pkg.Must1(json.Marshal(res1))

	pkg.Must(json.Unmarshal(p, &res2))

	p = pkg.Must1(json.Marshal(res2))

	res2.Errors.Append(
		pkg.ErrorStr("error 4"),
		pkg.ErrorStr("error 5"),
	)

	p = pkg.Must1(json.Marshal(res2))

}
