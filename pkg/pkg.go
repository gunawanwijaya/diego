package pkg

import (
	"cmp"
	"encoding"
	"fmt"
	"slices"
	"strconv"
	"strings"
)

type ErrorStr string

func (e ErrorStr) Error() string { var _ error = e; return string(e) }

const (
	ErrUnimplemented ErrorStr = "unimplemented"
)

// Errorf formats according to a format specifier and returns the string as a
// value that satisfies error.
//
// If the format specifier includes a %w verb with an error operand,
// the returned error will implement an Unwrap method returning the operand.
// If there is more than one %w verb, the returned error will implement an
// Unwrap method returning a []error containing all the %w operands in the
// order they appear in the arguments.
// It is invalid to supply the %w verb with an operand that does not implement
// the error interface. The %w verb is otherwise a synonym for %v.
func Errorf(format string, a ...any) error { return fmt.Errorf(format, a...) }

// Sprintf formats according to a format specifier and returns the resulting string.
func Sprintf(format string, a ...any) string { return fmt.Sprintf(format, a...) }

// Validator is a generic trait that any data type need to implement in order to be able to validate in runtime
type Validator interface{ Validate() error }

// Validate is a nice helper function to those `Validator` trait
func Validate[T Validator](t T) (T, error) {
	if any(t) == nil {
		return *new(T), ErrUnimplemented
	}
	if err := t.Validate(); err != nil {
		return *new(T), err
	}
	return t, nil
}

// Must will panic only if err is not nil
func Must(err error) {
	if err != nil {
		panic(err)
	}
}

// Must1 will panic only if err is not nil, else will return t1
func Must1[T1 any](t1 T1, err error) (_ T1) { Must(err); return t1 }

// Must2 will panic only if err is not nil, else will return t1 & t2
func Must2[T1, T2 any](t1 T1, t2 T2, err error) (_ T1, _ T2) { Must(err); return t1, t2 }

// Ok will panic only if not ok
func Ok(ok bool) {
	if !ok {
		panic("not ok")
	}
}

// Ok1 will panic only if not ok, else will return t1
func Ok1[T1 any](t1 T1, ok bool) (_ T1) { Ok(ok); return t1 }

// Ok2 will panic only if not ok, else will return t1 & t2
func Ok2[T1, T2 any](t1 T1, t2 T2, ok bool) (_ T1, _ T2) { Ok(ok); return t1, t2 }

// Mask is useful for redaction any sensitive information like password to avoid accident logging
func Mask[T any](t T) Masked[T] { return Masked[T]{_t: t} }

// Masked hold sensitive information, equipped with `Unmask` method to retrieve the concealed information
type Masked[T any] struct{ _t T }

func (x Masked[T]) Unmask() (t T)  { return x._t }
func (Masked[T]) String() string   { return "[***]" }
func (Masked[T]) GoString() string { return "[***]" }

// ContentNegotiate is used to parse accept* directive like accept-encoding & accept-language
type ContentNegotiate []contentNegotiate
type contentNegotiate struct {
	Content string
	Q       float64
}

func (ContentNegotiate) cmp(a, b contentNegotiate) int {
	return cmp.Or(cmp.Compare(b.Q, a.Q), strings.Compare(a.Content, b.Content))
}
func (c *ContentNegotiate) UnmarshalText(p []byte) error {
	var _ encoding.TextUnmarshaler = c
	var ps = strings.Split(string(p), (","))
	*c = make(ContentNegotiate, len(ps), cap(ps))
	for i, v := range ps {
		var cq = strings.Split(string(v), (";q="))
		switch len(cq) {
		default:
			(*c)[i].Content = string(v)
			(*c)[i].Q = 1
		case 2:
			var err error
			(*c)[i].Content = string(cq[0])
			(*c)[i].Q, err = strconv.ParseFloat(string(cq[1]), 64)
			if err != nil {
				*c = *new(ContentNegotiate)
				return err
			}
		}
	}
	slices.SortFunc(*c, c.cmp)
	return nil
}
func (c *ContentNegotiate) Filter(fn func(c string, q float64) bool) ContentNegotiate {
	var o ContentNegotiate
	for _, cc := range *c {
		if fn != nil && fn(cc.Content, cc.Q) {
			o = append(o, cc)
		}
	}
	slices.SortFunc(o, c.cmp)
	return o
}
