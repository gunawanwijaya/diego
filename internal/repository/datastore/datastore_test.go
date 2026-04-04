package datastore_test

import (
	"context"
	"crypto/rand"
	"runtime/debug"
	"testing"

	"github.com/gunawanwijaya/diego/internal/repository/datastore"
	"github.com/gunawanwijaya/diego/pkg"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/nacl/box"
)

// type Shelf struct {
// 	ProductID string  `json:"product_id"`
// 	Qty       float64 `json:"qty"`
// 	Unit      string  `json:"unit"`
// }

func Test(t *testing.T) {
	// var prod datastore.Product
	// // prod.Price = datastore.Price{
	// // 	Amount: currency.IDR.Amount(12_999.99),
	// // 	// Formatter: currency.NarrowSymbol,
	// // }
	// p, err := json.Marshal(prod)
	// t.Log(string(p), err)

	// t.Skip()
	// h := crypto.SHA1
	// msg := []byte("good day")
	// hh := hmac.New(h.New, pkg.Nonce(212))
	// hh.Write(msg)
	// sum := hh.Sum(msg)

	// t.Log(string(sum), len(sum) == hh.Size(), len(sum), hh.BlockSize())
}

// func TestBadger(t *testing.T) {
// 	nop := func(...any) { return }
// 	db, _ := badger.Open(badger.DefaultOptions("").WithInMemory(true))
// 	nop(db.Update(func(txn *badger.Txn) error {
// 		idAlfamart := xid.New()
// 		idBeverages := xid.New()
// 		idAMDK := xid.New()
// 		nop(txn.Set(idAlfamart[:], datastore.Company{Name: "Alfamart", Details: "Alfamart company"}.Bytes()))
// 		nop(txn.Set(idBeverages[:], datastore.Tag{Name: "Beverages"}.Bytes()))
// 		nop(txn.Set(idAMDK[:], datastore.Tag{Name: "AMDK", ParentTagID: &idBeverages}.Bytes()))
// 		nop(txn.Set(xid.New().Bytes(), datastore.Product{
// 			Name:      "Alfamart Air Mineral 1500ml",
// 			ScannedAs: "8994016013234",
// 			PrintedAs: "ALF MNRL 1500",
// 			Details:   "",
// 			CompanyID: &idAlfamart,
// 			Units:     map[string]float64{"pcs": 1, "box": 12},
// 			TagIDs:    []*xid.ID{&idAMDK},
// 		}.Bytes()))
// 		return nil
// 	}))
// 	// var tag datastore.Tag
// 	// var product datastore.Product
// 	nop(db.View(func(txn *badger.Txn) error {
// 		it := txn.NewIterator(badger.DefaultIteratorOptions)
// 		defer it.Close()
// 		// prefix := []byte(`{"tag":`)
// 		// for it.Seek(prefix); it.ValidForPrefix(prefix); it.Next() {
// 		// 	nop(it.Item().Value(func(val []byte) error {

// 		// 		return nil
// 		// 	}))
// 		// 	xid.FromBytes(it.Item().Key())

// 		// }
// 		return nil
// 	}))
// }
// func TestBunt(t *testing.T) {
// 	nop := func(...any) { return }
// 	db, _ := buntdb.Open(":memory:")
// 	// db.Load()
// 	nop(db.CreateIndex("company__name", "*", buntdb.IndexJSON("company.name")))
// 	nop(db.CreateIndex("tag__name", "*", buntdb.IndexJSON("tag.name")))
// 	nop(db.CreateIndex("product__name", "*", buntdb.IndexJSON("product.name")))
// 	nop(db.CreateIndex("product__scanned_as", "*", buntdb.IndexJSON("product.scanned_as")))
// 	nop(db.CreateIndex("product__company_id", "*", buntdb.IndexJSON("product.company_id")))
// 	nop(db.CreateIndex("product__tag_ids", "*", buntdb.IndexJSON("product.tag_ids")))
// 	nop(db.Update(func(tx *buntdb.Tx) error {
// 		idAlfamart := xid.New()
// 		idBeverages := xid.New()
// 		idAMDK := xid.New()
// 		nop(tx.Set(idAlfamart.String(), datastore.Company{Name: "Alfamart", Details: "Alfamart company"}.String(), nil))
// 		nop(tx.Set(idBeverages.String(), datastore.Tag{Name: "Beverages"}.String(), nil))
// 		nop(tx.Set(idAMDK.String(), datastore.Tag{Name: "AMDK", ParentTagID: &idBeverages}.String(), nil))
// 		nop(tx.Set(xid.New().String(), datastore.Product{
// 			Name:      "Alfamart Air Mineral 1500ml",
// 			ScannedAs: "8994016013234",
// 			PrintedAs: "ALF MNRL 1500",
// 			Details:   "",
// 			CompanyID: &idAlfamart,
// 			Units:     map[string]float64{"pcs": 1, "box": 12},
// 			TagIDs:    []*xid.ID{&idAMDK},
// 		}.String(), nil))
// 		return nil
// 	}))
// 	var tag datastore.Tag
// 	var product datastore.Product
// 	nop(db.View(func(tx *buntdb.Tx) error {
// 		nop(tx.Descend("tag__name", func(key, value string) bool {
// 			if o := gjson.Get(value, "tag"); o.Get("name").Str == "AMDK" {
// 				id, _ := xid.FromString(key)
// 				return nil != tag.ResolveBuntDB(tx, &id)
// 			}
// 			return true
// 		}), tag)
// 		nop(tx.Descend("product__scanned_as", func(key, value string) bool {
// 			if o := gjson.Get(value, "product"); o.Get("scanned_as").Str == "8994016013234" {
// 				id, _ := xid.FromString(key)
// 				return nil != product.ResolveBuntDB(tx, &id)
// 			}
// 			return true
// 		}), product)

// 		t.Log(tag.String())
// 		t.Log(product.String())
// 		return nil
// 	}))
// 	db.Shrink()
// 	key := pkg.Nonce(32)
// 	func() {
// 		f, _ := os.Create("./local.buntdb.gz")
// 		sw := pkg.Must1(pkg.AES_CTR(key).StreamWriter(f))
// 		gw := pkg.Must1(gzip.NewWriterLevel(sw, gzip.BestCompression))
// 		defer f.Close()
// 		defer gw.Close()
// 		t.Log(db.Save(gw))

// 	}()
// 	func() {
// 		f, _ := os.Open("./local.buntdb.gz")
// 		sr := pkg.Must1(pkg.AES_CTR(key).StreamReader(f))
// 		gr := pkg.Must1(gzip.NewReader(sr))
// 		p := pkg.Must1(io.ReadAll(gr))
// 		t.Log("len(p)", len(p))
// 		t.Log(db.Load(gr))
// 	}()
// }

func TestDatastore(t *testing.T) {
	var err error
	var _, cancel = context.WithCancelCause(context.Background())
	defer func() {
		cancel(err)
		if err != nil {
			t.Fatalf("%s: %s", err, debug.Stack())
		}
	}()
	var m, cip []byte
	var n = pkg.Nonce(32)
	_, k1, _ := box.GenerateKey(rand.Reader)
	ld := datastore.DefaultCipherResolver(k1)
	l, e := ld.New()
	cip = pkg.Must1(e.Encrypt(n))
	d := ld.Load(l)
	m = pkg.Must1(d.Decrypt(cip))
	require.Equal(t, n, m, "l=%q cip=%v", l, cip)

}
