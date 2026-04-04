package datastore

import (
	"compress/gzip"
	"context"
	"database/sql"

	"github.com/gunawanwijaya/diego/pkg"
)

type Configuration struct {
	//
}

func (x Configuration) Validate() (err error) {
	// var _ csvq.Driver
	return nil
}

type Dependency struct {
	CipherResolver

	AuthenticationSQLite3 *sql.DB
	// AuthenticationBuntDB  *buntdb.DB

	LocalSQLite3 *sql.DB
	// LocalBuntDB *buntdb.DB
}

func (x Dependency) Validate() (err error) {
	return nil
}

type Datastore interface {
	Authentication
	pkg.Validator
}

type datastore struct {
	Configuration
	Dependency
}

func New(ctx context.Context, cfg Configuration, dep Dependency) (_ Datastore, err error) {
	return pkg.Validate(&datastore{cfg, dep})
}

func (x *datastore) Validate() (err error) {
	if _, err = pkg.Validate(x.Configuration); err != nil {
		return err
	}
	if _, err = pkg.Validate(x.Dependency); err != nil {
		return err
	}

	// tx,_:=x.LocalBuntDB.Begin(true)
	// tx.Set()

	return nil
}

func _() {
	gw, _ := gzip.NewWriterLevel(nil, gzip.BestCompression)
	_ = gw
}

// ---------------------------------------------------------------------------------------------------------------------
// XID
// ---------------------------------------------------------------------------------------------------------------------

// type XID struct{ *xid.ID }

// func (x XID) Value() (driver.Value, error) {
// 	if x.ID == nil || x.ID.IsNil() {
// 		return nil, nil
// 	}
// 	return x.ID[:], nil
// }

// func (x *XID) Scan(value interface{}) (err error) {
// 	if x.ID == nil {
// 		return
// 	}
// 	switch val := value.(type) {
// 	case []byte:
// 		i, err := xid.FromBytes(val)
// 		if err != nil {
// 			return err
// 		}
// 		*x.ID = i
// 		return nil
// 	case nil:
// 		*x.ID = xid.NilID()
// 		return nil
// 	default:
// 		return pkg.Errorf("xid: scanning unsupported type: %T", value)
// 	}
// }

// ---------------------------------------------------------------------------------------------------------------------
// Context
// ---------------------------------------------------------------------------------------------------------------------

type ctxKeySQLConnDBStmtTx struct{}

func (ctxKeySQLConnDBStmtTx) Put(ctx context.Context, tcd SQLConnDBStmtTx) context.Context {
	return context.WithValue(ctx, ctxKeySQLConnDBStmtTx{}, tcd)
}

func (ctxKeySQLConnDBStmtTx) Get(ctx context.Context, or SQLConnDBStmtTx) SQLConnDBStmtTx {
	if tcd, ok := ctx.Value(ctxKeySQLConnDBStmtTx{}).(SQLConnDBStmtTx); ok && tcd != nil {
		return tcd
	}
	return or
}

type SQLConnDBStmtTx interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
	// Commit() error
	// Exec(query string, args ...any) (sql.Result, error)
	// Prepare(query string) (*sql.Stmt, error)
	// PrepareContext(ctx context.Context, query string) (*sql.Stmt, error)
	// Query(query string, args ...any) (*sql.Rows, error)
	// QueryRow(query string, args ...any) *sql.Row
	// Rollback() error
	// Stmt(stmt *sql.Stmt) *sql.Stmt
	// StmtContext(ctx context.Context, stmt *sql.Stmt) *sql.Stmt
}

// ---------------------------------------------------------------------------------------------------------------------

// type ctxKeyBuntDBTx struct{}

// func (ctxKeyBuntDBTx) Put(ctx context.Context, tcd BuntDBTx) context.Context {
// 	return context.WithValue(ctx, ctxKeyBuntDBTx{}, tcd)
// }

// func (ctxKeyBuntDBTx) Get(ctx context.Context, or BuntDBTx) BuntDBTx {
// 	if tcd, ok := ctx.Value(ctxKeyBuntDBTx{}).(BuntDBTx); ok && tcd != nil {
// 		return tcd
// 	}
// 	return or
// }

// type BuntDBTx interface {
// 	Ascend(index string, iterator func(key string, value string) bool) error
// 	AscendEqual(index string, pivot string, iterator func(key string, value string) bool) error
// 	AscendGreaterOrEqual(index string, pivot string, iterator func(key string, value string) bool) error
// 	AscendKeys(pattern string, iterator func(key string, value string) bool) error
// 	AscendLessThan(index string, pivot string, iterator func(key string, value string) bool) error
// 	AscendRange(index string, greaterOrEqual string, lessThan string, iterator func(key string, value string) bool) error
// 	Descend(index string, iterator func(key string, value string) bool) error
// 	DescendEqual(index string, pivot string, iterator func(key string, value string) bool) error
// 	DescendGreaterThan(index string, pivot string, iterator func(key string, value string) bool) error
// 	DescendKeys(pattern string, iterator func(key string, value string) bool) error
// 	DescendLessOrEqual(index string, pivot string, iterator func(key string, value string) bool) error
// 	DescendRange(index string, lessOrEqual string, greaterThan string, iterator func(key string, value string) bool) error
// 	Get(key string, ignoreExpired ...bool) (val string, err error)
// 	GetLess(index string) (func(a string, b string) bool, error)
// 	Set(key string, value string, opts *buntdb.SetOptions) (previousValue string, replaced bool, err error)
// 	TTL(key string) (time.Duration, error)
// 	// Commit() error
// 	// CreateIndex(name string, pattern string, less ...func(a string, b string) bool) error
// 	// CreateIndexOptions(name string, pattern string, opts *buntdb.IndexOptions, less ...func(a string, b string) bool) error
// 	// CreateSpatialIndex(name string, pattern string, rect func(item string) (min []float64, max []float64)) error
// 	// CreateSpatialIndexOptions(name string, pattern string, opts *buntdb.IndexOptions, rect func(item string) (min []float64, max []float64)) error
// 	// Delete(key string) (val string, err error)
// 	// DeleteAll() error
// 	// DropIndex(name string) error
// 	// GetRect(index string) (func(s string) (min []float64, max []float64), error)
// 	// Indexes() ([]string, error)
// 	// Intersects(index string, bounds string, iterator func(key string, value string) bool) error
// 	// Nearby(index string, bounds string, iterator func(key string, value string, dist float64) bool) error
// 	// Rollback() error
// 	// Len() (int, error)
// }
