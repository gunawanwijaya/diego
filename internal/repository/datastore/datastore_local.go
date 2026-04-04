package datastore

// import (
// 	"context"
// 	"crypto/x509"
// 	"math"
// 	"time"

// 	"github.com/govalues/decimal"
// 	"github.com/govalues/money"
// 	"github.com/gunawanwijaya/diego/internal/repository/datastore/local"
// 	"github.com/gunawanwijaya/diego/pkg"

// 	// "github.com/ncruces/go-sqlite3"
// 	// "github.com/rs/xid"
// )

// type Local interface {
// 	MutCompany(ctx context.Context, req MutCompanyRequest) (MutCompanyResponse, error)
// 	QryCompany(ctx context.Context, req QryCompanyRequest) (QryCompanyResponse, error)
// }

// type MutCompanyRequest local.Company
// type MutCompanyResponse local.Company

// func (x *datastore) MutCompany(ctx context.Context, req MutCompanyRequest) (MutCompanyResponse, error) {
// 	var zero = *new(MutCompanyResponse)
// 	var tcd = ctxKeySQLConnDBStmtTx{}.Get(ctx, x.LocalSQLite3)
// 	switch {
// 	default: // insert
// 		if _, err := tcd.ExecContext(ctx, "insert"); err != nil {
// 			return zero, err
// 		}
// 		return MutCompanyResponse{}, pkg.ErrUnimplemented
// 	case !req.ID.IsZero(): // update by id
// 		if _, err := tcd.ExecContext(ctx, "update"); err != nil {
// 			return zero, err
// 		}
// 		return MutCompanyResponse{}, pkg.ErrUnimplemented
// 	}
// }

// type QryCompanyRequest local.Company
// type QryCompanyResponse local.Company

// func (x *datastore) QryCompany(ctx context.Context, req QryCompanyRequest) (QryCompanyResponse, error) {
// 	asn1CSR, _ := x509.CreateCertificateRequest(nil, nil, nil)
// 	csr, _ := x509.ParseCertificateRequest(asn1CSR)
// 	_ = csr

// 	var zero = *new(QryCompanyResponse)
// 	var tcd = ctxKeySQLConnDBStmtTx{}.Get(ctx, x.LocalSQLite3)
// 	switch {
// 	default: // invalid
// 		return zero, pkg.ErrUnimplemented
// 	case !req.ID.IsZero(): // search by id
// 		if err := tcd.QueryRowContext(ctx, "search by id",
// 			nil,
// 		).Scan(
// 			nil,
// 		); err != nil {
// 			return zero, err
// 		}
// 		return zero, pkg.ErrUnimplemented
// 	case req.Name != "": // search by name
// 		if err := tcd.QueryRowContext(ctx, "search by name",
// 			nil,
// 		).Scan(
// 			nil,
// 		); err != nil {
// 			return zero, err
// 		}
// 		return zero, pkg.ErrUnimplemented
// 	}
// }

// type Tag struct {
// 	ID          xid.ID `json:"id"`            //
// 	Name        string `json:"name"`          //
// 	ParentTagID xid.ID `json:"parent_tag_id"` //
// }

// type Product struct {
// 	ID        xid.ID   `json:"id"`         //
// 	Name      string   `json:"name"`       //
// 	ScannedAs string   `json:"scanned_as"` // e.g. GTIN
// 	PrintedAs string   `json:"printed_as"` // name printed on receipt
// 	Details   string   `json:"details"`    //
// 	CompanyID xid.ID   `json:"company_id"` // FK to Company
// 	TagIDs    []xid.ID `json:"tag_ids"`    // FK to Tag
// }

// type ProductPrice struct {
// 	ProductID    xid.ID          `json:"product_id"`    //
// 	BuyingPrice  decimal.Decimal `json:"buying_price"`  //
// 	SellingPrice decimal.Decimal `json:"selling_price"` //
// 	StartedAt    time.Time       `json:"started_at"`    //
// }

// type ProductStock struct {
// 	ProductID  xid.ID          `json:"product_id"`  //
// 	SKU        string          `json:"sku"`         //
// 	Qty        decimal.Decimal `json:"qty"`         //
// 	ReceivedAt time.Time       `json:"received_at"` //
// 	ExpiredAt  time.Time       `json:"expired_at"`  //
// }

// type CartItem struct {
// 	SortKey   int             `json:"sort_key"`   //
// 	BuyerID   xid.ID          `json:"buyer_id"`   //
// 	ProductID xid.ID          `json:"product_id"` //
// 	Qty       decimal.Decimal `json:"qty"`        //
// }

// type CheckoutItem struct {
// 	ProductID    xid.ID          `json:"product_id"`    //
// 	Qty          decimal.Decimal `json:"qty"`           //
// 	SellingPrice decimal.Decimal `json:"selling_price"` //
// }

// type NonCheckoutItem struct {
// 	Name         string          `json:"name"`          //
// 	PrintedAs    string          `json:"printed_as"`    // name printed on receipt
// 	Qty          decimal.Decimal `json:"qty"`           //
// 	SellingPrice decimal.Decimal `json:"selling_price"` //
// }

// type TransactionItem struct {
// 	*CheckoutItem
// 	*NonCheckoutItem
// }

// type Transaction struct {
// 	ID                xid.ID            `json:"id"`                  //
// 	BuyerID           xid.ID            `json:"buyer_id"`            //
// 	Items             []TransactionItem `json:"items"`               //
// 	CreatedAt         time.Time         `json:"created_at"`          //
// 	TotalSellingPrice decimal.Decimal   `json:"total_selling_price"` //
// }

// // ---------------------------------------------------------------------------------------------------------------------
// //
// // ---------------------------------------------------------------------------------------------------------------------

// var _ money.Currency

// // var _ = sqlite3.Initialize()

// var m = map[ProductUnit]map[ProductUnit]float64{
// 	UNIT_Q_DOZEN:    {UNIT_Q_PIECE: 12},
// 	UNIT_Q_PKG20:    {UNIT_Q_PIECE: 20},
// 	UNIT_Q_PKG24:    {UNIT_Q_PIECE: 24},
// 	UNIT_Q_PKG40:    {UNIT_Q_PIECE: 40},
// 	UNIT_Q_PKG48:    {UNIT_Q_PIECE: 48},
// 	UNIT_W_KILOGRAM: {UNIT_W_GRAM: 1_000},
// 	UNIT_V_LITER:    {UNIT_V_MILLILITER: 1_000},
// }

// const (
// 	UNIT_Q_PIECE ProductUnit = "piece"
// 	UNIT_Q_DOZEN ProductUnit = "dozen"
// 	UNIT_Q_PKG20 ProductUnit = "pkg20"
// 	UNIT_Q_PKG24 ProductUnit = "pkg24"
// 	UNIT_Q_PKG40 ProductUnit = "pkg40"
// 	UNIT_Q_PKG48 ProductUnit = "pkg48"

// 	UNIT_W_GRAM     ProductUnit = "gram"
// 	UNIT_W_KILOGRAM ProductUnit = "kilogram"

// 	UNIT_V_LITER      ProductUnit = "liter"
// 	UNIT_V_MILLILITER ProductUnit = "milliliter"
// )

// type ProductUnit string

// func (x ProductUnit) Exchange(y ProductUnit) (decimal.Decimal, error) {
// 	if mm, ok := m[x]; ok {
// 		if rate, ok := mm[y]; ok && rate > 0 {
// 			return decimal.NewFromFloat64(rate)
// 		}
// 	} else if mm, ok := m[y]; ok {
// 		if rate, ok := mm[x]; ok && rate > 0 {
// 			return decimal.NewFromFloat64(1 / rate)
// 		}
// 	}
// 	return decimal.NewFromFloat64(math.NaN())
// }
