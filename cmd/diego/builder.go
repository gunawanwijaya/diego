package main

import (
	"context"
	"database/sql"
	"errors"
	"flag"
	"io/fs"
	"log/slog"
	"os"

	// "github.com/gunawanwijaya/diego/internal/feature/role"
	"github.com/gunawanwijaya/diego/internal/repository/datastore"
	"github.com/gunawanwijaya/diego/internal/service/httprest"
	"github.com/gunawanwijaya/diego/pkg"
	// "github.com/rs/xid"
	// "gopkg.in/yaml.v3"
)

// Flag
// ---------------------------------------------------------------------------------------------------------------------
type Flag struct {
	ConfigurationFile string
	SecretFile        string
}

// Secret
// ---------------------------------------------------------------------------------------------------------------------
type Secret struct {
	// XID xid.ID
	// Root struct { // base64.RawURLEncoding format
	// 	P384    *pkg.JWK[*ecdsa.PrivateKey]
	// 	X25519  *pkg.JWK[*ecdh.PrivateKey]
	// 	Ed25519 *pkg.JWK[ed25519.PrivateKey]
	// }
	Repository struct {
		Datastore struct {
			DBAuthn    ArgSQLOpen
			RecordKeys map[string]*pkg.JWK[[]byte] // using NaCl key material, len should be at least 32
		}
	}
}

// Configuration
// ---------------------------------------------------------------------------------------------------------------------
type Configuration struct {
	Feature struct {
		// Role role.Configuration
	}
	Repository struct {
		Datastore datastore.Configuration
	}
	Service struct {
		HTTPREST httprest.Configuration
		// WebSocket websocket.Configuration
	}
}

// Dependency
// ---------------------------------------------------------------------------------------------------------------------
type Dependency struct {
	Feature struct {
		// Role role.Dependency
	}
	Repository struct {
		Datastore datastore.Dependency
	}
	Service struct {
		HTTPREST httprest.Dependency
		// WebSocket websocket.Dependency
	}
}

// marshall
// ---------------------------------------------------------------------------------------------------------------------
func marshall(ctx context.Context, sec *Secret, cfg *Configuration) (err error) {
	var f Flag
	const defaultConfigFile = "./diego.config.yml"
	const usageConfigFile = "config file path"
	flag.StringVar(&f.ConfigurationFile, "config", defaultConfigFile, "")
	flag.StringVar(&f.ConfigurationFile, "c", defaultConfigFile, "")

	const defaultSecretFile = "./diego.secret.yml"
	const usageSecretFile = "secret file path"
	flag.StringVar(&f.SecretFile, "secret", defaultSecretFile, "")
	flag.StringVar(&f.SecretFile, "s", defaultSecretFile, "")

	flag.Parse()

	var file *os.File
	var info os.FileInfo
	_ = file

	for k, v := range map[string]struct {
		d string
		v any
	}{
		f.SecretFile:        {defaultSecretFile, sec},
		f.ConfigurationFile: {defaultConfigFile, cfg},
	} {
		info, err = os.Stat(k)
		if errors.Is(err, fs.ErrNotExist) && k == v.d {
			if file, err = os.Create(k); err != nil {
				return
			}
			if k == f.SecretFile {
				// sec.XID = xid.New()
				// sec.Repository.Datastore.DBAuthn = ArgSQLOpen{"sqlite3", "file:authn.db?cache=shared&mode=memory"}
				// sec.Repository.Datastore.RecordKeys = map[string]*pkg.JWK[[]byte]{
				// 	sec.XID.String(): pkg.NewJWK(pkg.Nonce(32)),
				// }
				// v.v = sec
			}
			// x := yaml.NewEncoder(file)
			// slog.Info("new", slog.String("path", k), slog.Any("err", errors.Join(
			// 	x.Encode(v.v),
			// 	x.Close(),
			// 	file.Close(),
			// )))
			err = nil // reset the error
		} else if !info.IsDir() {
			if file, err = os.Open(k); err != nil {
				return
			}
			// y := yaml.NewDecoder(file)
			// slog.Info("load", slog.String("path", k), slog.Any("err", errors.Join(
			// 	y.Decode(v.v),
			// 	file.Close(),
			// )))
			if k == f.SecretFile {
				// sec.XID = xid.New()
				// if len(sec.Repository.Datastore.RecordKeys) < 1 {
				// 	sec.Repository.Datastore.RecordKeys = map[string]*pkg.JWK[[]byte]{}
				// }
				// now, addAfter := time.Now(), -24*time.Hour
				add := len(sec.Repository.Datastore.RecordKeys) == 0
				// for k := range sec.Repository.Datastore.RecordKeys {
				// 	if id, err := xid.FromString(k); err == nil {
				// 		add = true
				// 		if id.Time().After(now.Add(addAfter)) {
				// 			add = false
				// 			break
				// 		}
				// 	}
				// }
				if add {
					// sec.Repository.Datastore.RecordKeys[sec.XID.String()] = pkg.NewJWK(pkg.Nonce(32))
					if file, err = os.Create(k); err != nil {
						return
					}
					// x := yaml.NewEncoder(file)
					// slog.Info("load_new", slog.String("path", k), slog.Any("err", errors.Join(
					// 	x.Encode(v.v),
					// 	x.Close(),
					// 	file.Close(),
					// )))
				}
			}
		} else if info.IsDir() {
			slog.ErrorContext(ctx, pkg.Sprintf("%s is dir", k))
		} else {
			slog.ErrorContext(ctx, pkg.Sprintf("%s is invalid or missing", k))
		}
		// slog.Info("sec.Root", slog.Any("sec.Root", sec.Root))
	}
	return
}

// build
// ---------------------------------------------------------------------------------------------------------------------
func build(ctx context.Context, cfg *Configuration, dep *Dependency) (err error) {
	// setup
	var sec = &Secret{}
	defer func() { *sec = Secret{} }()
	if err = marshall(ctx, sec, cfg); err != nil {
		return err
	}

	// dep.Repository.Datastore.CipherAdapter = datastore.ECDH_AESGCM_CipherAdapter{PrivateKey: sec.Root.X25519.Key}

	if dep.Repository.Datastore.AuthenticationSQLite3, err = sec.Repository.Datastore.DBAuthn.Open(); err != nil {
		return err
	}

	return nil
}

// ---------------------------------------------------------------------------------------------------------------------
// Composites & Methods
// ---------------------------------------------------------------------------------------------------------------------

type ArgSQLOpen struct{ Driver, DSN string }

func (x ArgSQLOpen) Open() (*sql.DB, error) {
	switch x.Driver {
	case "sqlite3":
		// _ = sqlite3.Version
	}
	return sql.Open(x.Driver, x.DSN)
}

// func b64encode(src []byte) string { return base64.RawURLEncoding.Strict().EncodeToString(src) }

// func b64decode(dst string) ([]byte, error) { return base64.RawURLEncoding.Strict().DecodeString(dst) }
