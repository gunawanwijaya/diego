package datastore

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/gunawanwijaya/diego/internal/repository/datastore/query"
	"github.com/gunawanwijaya/diego/pkg"
	// "github.com/rs/xid"
)

type Authentication interface {
	MutAccountInsert(ctx context.Context, req MutAccountInsertRequest) (MutAccountInsertResponse, error)
	MutAccountUpdate(ctx context.Context, req MutAccountUpdateRequest) (MutAccountUpdateResponse, error)
	QryAccount(ctx context.Context, req QryAccountRequest) (QryAccountResponse, error)
	TxAuthentication(ctx context.Context, fn func(ctx context.Context) error) error
	pkg.Validator
}

type MutAccountInsertRequest struct {
	Username       string
	HashedPassword pkg.Masked[[]byte]
}

type MutAccountInsertResponse struct {
	// ID xid.ID
}

func (x *datastore) TxAuthentication(ctx context.Context, fn func(ctx context.Context) error) error {
	if fn != nil {
		var conn *sql.Conn
		var err error
		if conn, err = x.AuthenticationSQLite3.Conn(ctx); err != nil {
			return err
		}
		var tx *sql.Tx
		if tx, err = conn.BeginTx(ctx, nil); err != nil {
			return err
		}
		ctx = ctxKeySQLConnDBStmtTx{}.Put(ctx, tx)
		if err = fn(ctx); err != nil {
			return errors.Join(tx.Rollback(), err, conn.Close())
		} else if err = tx.Commit(); err != nil {
			return errors.Join(tx.Rollback(), err, conn.Close())
		}
		return conn.Close()
	}
	return nil
}

func (x *datastore) MutAccountInsert(ctx context.Context, req MutAccountInsertRequest) (MutAccountInsertResponse, error) {
	var tcd = ctxKeySQLConnDBStmtTx{}.Get(ctx, x.AuthenticationSQLite3)
	var now = time.Now()
	// var accountID = xid.New()
	var updateKey = pkg.Nonce(16)
	var keyID, c = x.CipherResolver.New()
	var password []byte
	var err error
	if password, err = c.Encrypt(req.HashedPassword.Unmask()); err != nil {
		return *new(MutAccountInsertResponse), err
	}

	if _, err = tcd.ExecContext(ctx, query.SQLITE3_AUTHN_MUTATION_ACCOUNT_INSERT_SQL(),
		// sql.Named("id", XID{&accountID}),
		sql.Named("username", arg(req.Username)),
		sql.Named("key_id", arg(keyID)),
		sql.Named("password", arg(password)),
		sql.Named("passwordless", []byte(nil)),
		sql.Named("totp_secret", []byte(nil)),
		sql.Named("totp_recovery", []byte(nil)),
		sql.Named("email_address", []byte(nil)),
		sql.Named("phone_number", []byte(nil)),
		sql.Named("update_key", arg(updateKey)),
		sql.Named("updated_at", arg(now.Unix())),
	); err != nil {
		return *new(MutAccountInsertResponse), err
	}
	return MutAccountInsertResponse{
		// ID: accountID,
	}, nil
}

type MutAccountUpdateRequest struct {
	// ID        xid.ID
	KeyID     []byte
	UpdateKey []byte

	Username                string               // plaintext
	HashedPassword          pkg.Masked[[]byte]   // ciphertext
	HashedPasswordLess      pkg.Masked[[]byte]   // ciphertext
	TOTPSecret              pkg.Masked[string]   // ciphertext
	HashedTOTPRecoveryCodes pkg.Masked[[][]byte] // ciphertext
	HashedEmailAddress      pkg.Masked[[]byte]   // plaintext
	HashedPhoneNumber       pkg.Masked[[]byte]   // plaintext
}

type MutAccountUpdateResponse struct {
	// ID        xid.ID
	UpdateKey []byte
}

const (
	_RECORD_SEPARATOR byte = 0x1E
)

func (x *datastore) MutAccountUpdate(ctx context.Context, req MutAccountUpdateRequest) (MutAccountUpdateResponse, error) {
	var tcd = ctxKeySQLConnDBStmtTx{}.Get(ctx, x.AuthenticationSQLite3)
	var now = time.Now()
	// var err error
	var updateKey = pkg.Nonce(16)
	var password, passwordLess, totpSecret, totpRecovery []byte
	if c, err := pkg.Validate(x.CipherResolver.Load(req.KeyID)); err == nil {
		password, _ = c.Encrypt(req.HashedPassword.Unmask())
		passwordLess, _ = c.Encrypt(req.HashedPasswordLess.Unmask())
		totpSecret, _ = c.Encrypt([]byte(req.TOTPSecret.Unmask()))
		for i, v := range req.HashedTOTPRecoveryCodes.Unmask() {
			if i > 0 {
				totpRecovery = append(totpRecovery, _RECORD_SEPARATOR)
			}
			totpRecovery = append(totpRecovery, v...)
		}
		totpRecovery, _ = c.Encrypt(totpRecovery)
	}

	if _, err := tcd.ExecContext(ctx, query.SQLITE3_AUTHN_MUTATION_ACCOUNT_UPDATE_SQL(),
		// sql.Named("id", XID{&req.ID}),
		sql.Named("username", arg(req.Username)),
		sql.Named("key_id", arg(req.KeyID)),
		sql.Named("password", arg(password)),
		sql.Named("passwordless", arg(passwordLess)),
		sql.Named("totp_secret", arg(totpSecret)),
		sql.Named("totp_recovery", arg(totpRecovery)),
		sql.Named("email_address", arg(req.HashedEmailAddress.Unmask())),
		sql.Named("phone_number", arg(req.HashedPhoneNumber.Unmask())),
		sql.Named("update_key", arg(updateKey)),
		sql.Named("last_update_key", arg(req.UpdateKey)),
		sql.Named("updated_at", arg(now.Unix())),
	); err != nil {
		return *new(MutAccountUpdateResponse), err
	}

	return MutAccountUpdateResponse{
		// ID: req.ID,
		UpdateKey: updateKey}, nil
}

func arg[T any](v T) sql.Null[T] {
	var valid bool = any(v) != nil
	switch v := any(v).(type) {
	case []byte:
		valid = len(v) > 0
	case string:
		valid = len(v) > 0
	}
	return sql.Null[T]{V: v, Valid: valid}
}

type QryAccountRequest struct {
	// ID                 xid.ID
	Username           string             // plaintext
	HashedEmailAddress pkg.Masked[[]byte] // plaintext
	HashedPhoneNumber  pkg.Masked[[]byte] // plaintext
	KeyID              []byte             // plaintext
	Lookup             string
}

type QryAccountResponse struct {
	// ID        xid.ID
	UpdateKey []byte

	Username                string               // plaintext
	KeyID                   []byte               // plaintext
	HashedPassword          pkg.Masked[[]byte]   // ciphertext
	HashedPasswordLess      pkg.Masked[[]byte]   // ciphertext
	TOTPSecret              pkg.Masked[string]   // ciphertext
	HashedTOTPRecoveryCodes pkg.Masked[[][]byte] // ciphertext
	HashedEmailAddress      pkg.Masked[[]byte]   // plaintext
	HashedPhoneNumber       pkg.Masked[[]byte]   // plaintext
	UpdatedAt               time.Time            //
}

func (x *datastore) QryAccount(ctx context.Context, req QryAccountRequest) (QryAccountResponse, error) {
	var tcd = ctxKeySQLConnDBStmtTx{}.Get(ctx, x.AuthenticationSQLite3)
	var password, passwordLess, totpSecret, totpRecovery, emailAddress, phoneNumber []byte
	var updatedAt int64
	var res QryAccountResponse
	var err error
	if err = tcd.QueryRowContext(ctx, query.SQLITE3_AUTHN_QUERY_ACCOUNT_LOOKUP_SQL(),
		// sql.Named("id", XID{&req.ID}),
		sql.Named("username", arg(req.Username)),
		sql.Named("email_address", arg(req.HashedEmailAddress.Unmask())),
		sql.Named("phone_number", arg(req.HashedPhoneNumber.Unmask())),
		sql.Named("key_id", arg(req.KeyID)),
		sql.Named("lookup", arg(req.Lookup)),
	).Scan(
		// &XID{&res.ID},
		&res.Username,
		&res.KeyID,
		&password,
		&passwordLess,
		&totpSecret,
		&totpRecovery,
		&emailAddress,
		&phoneNumber,
		&res.UpdateKey,
		&updatedAt,
	); err != nil {
		return *new(QryAccountResponse), err
	}

	if c, err := pkg.Validate(x.CipherResolver.Load(res.KeyID)); err == nil {
		if password, err = c.Decrypt(password); err == nil {
			res.HashedPassword = pkg.Mask(password)
		}
		if passwordLess, err = c.Decrypt(passwordLess); err == nil {
			res.HashedPasswordLess = pkg.Mask(passwordLess)
		}
		if totpSecret, err = c.Decrypt(totpSecret); err == nil {
			res.TOTPSecret = pkg.Mask(string(totpSecret))
		}
		if totpRecovery, err = c.Decrypt(totpRecovery); err == nil {
			var hs [][]byte
			for _, v := range bytes.Split(totpRecovery, []byte{_RECORD_SEPARATOR}) {
				hs = append(hs, v)
			}
			res.HashedTOTPRecoveryCodes = pkg.Mask(hs)
		}
	}

	res.HashedEmailAddress = pkg.Mask(emailAddress)
	res.HashedPhoneNumber = pkg.Mask(phoneNumber)
	res.UpdatedAt = time.Unix(updatedAt, 0)
	return res, nil
}
