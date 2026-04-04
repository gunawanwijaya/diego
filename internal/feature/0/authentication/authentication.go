package authentication

import (
	"context"
	"slices"

	// "github.com/golang-jwt/jwt/v5"
	"github.com/gunawanwijaya/diego/internal/repository/datastore"
	"github.com/gunawanwijaya/diego/pkg"
)

type Configuration struct {
	//
}

func (x Configuration) Validate() (err error) {
	return nil
}

type Dependency struct {
	Authentication datastore.Authentication

	HasherPassword          pkg.Hasher
	HasherPasswordLess      pkg.Hasher
	HasherTOTPRecoveryCodes pkg.Hasher
	HasherEmailAddress      pkg.Hasher
	HasherPhoneNumber       pkg.Hasher
}

func (x Dependency) Validate() (err error) {
	return nil
}

type Authentication interface {
	pkg.Validator
	AuthenticationHTTP
	Authenticate(ctx context.Context, req AuthenticateRequest) (AuthenticateResponse, error)
	Register(ctx context.Context, req AuthenticateRequest) (AuthenticateResponse, error)
	LinkTOTP(ctx context.Context, req AuthenticateRequest) (AuthenticateResponse, error)
}

type authentication struct {
	Configuration
	Dependency
}

func New(ctx context.Context, cfg Configuration, dep Dependency) (_ Authentication, err error) {
	return pkg.Validate(&authentication{cfg, dep})
}

func (x *authentication) Validate() (err error) {
	if _, err = pkg.Validate(x.Configuration); err != nil {
		return err
	}
	if _, err = pkg.Validate(x.Dependency); err != nil {
		return err
	}
	return nil
}

type AuthenticateRequest struct {
	Lookup       string             // Password based
	Password     pkg.Masked[string] // Password based
	PasswordLess pkg.Masked[string] // Password less
	TOTP         string             // TOTP
	TOTPRecovery string             // TOTP
}

type AuthenticateResponse struct {
	ID string

	Payload pkg.Masked[[]byte]
}

const ErrInvalidCredentials = pkg.ErrorStr("invalid credentials")
const ErrRequiredTOTP = pkg.ErrorStr("required totp")

func (x *authentication) Authenticate(ctx context.Context, req AuthenticateRequest) (AuthenticateResponse, error) {
	// var resZero AuthenticateResponse
	var authn = x.Authentication
	if err := authn.TxAuthentication(ctx, func(ctx context.Context) error {
		// -----------------------------------------------------------------------------------------------------------------
		// query using lookup
		// -----------------------------------------------------------------------------------------------------------------
		var res1 datastore.QryAccountResponse
		var err error
		if res1, err = authn.QryAccount(ctx, datastore.QryAccountRequest{
			Lookup: req.Lookup,
		}); err != nil {
			return err
		}
		var updateKey = res1.UpdateKey

		// -----------------------------------------------------------------------------------------------------------------
		// 1 factor authentication is required
		// -----------------------------------------------------------------------------------------------------------------
		if pw := []byte(req.Password.Unmask()); len(pw) > 0 {
			if err = x.HasherPassword.Compare(pw, res1.HashedPassword.Unmask()); err != nil {
				return err
			}
		} else if pwl := []byte(req.PasswordLess.Unmask()); len(pw) > 0 {
			if err = x.HasherPasswordLess.Compare(pwl, res1.HashedPassword.Unmask()); err != nil {
				return err
			}
		} else {
			return ErrInvalidCredentials
		}

		// -----------------------------------------------------------------------------------------------------------------
		// 2 factor authentication is required if setup
		// -----------------------------------------------------------------------------------------------------------------
		if sec := res1.TOTPSecret.Unmask(); len(sec) > 0 {
			if len(req.TOTP) <= 0 {
				return ErrRequiredTOTP
				// } else if !gotp.NewDefaultTOTP(sec).VerifyTime(req.TOTP, time.Now()) {
				// 	return ErrInvalidCredentials
			}
		}
		// -----------------------------------------------------------------------------------------------------------------
		// compare against HashedTOTPRecoveryCodes & remove element that we found
		// -----------------------------------------------------------------------------------------------------------------
		if s := res1.HashedTOTPRecoveryCodes.Unmask(); len(req.TOTPRecovery) > 0 {
			foundAt := -1
			for i, code := range s {
				if err = x.HasherTOTPRecoveryCodes.Compare([]byte(req.TOTPRecovery), code); err != nil {
					foundAt = i
					break
				}
			}
			if foundAt >= 0 && foundAt < len(s) {
				var res2 datastore.MutAccountUpdateResponse
				if res2, err = authn.MutAccountUpdate(ctx, datastore.MutAccountUpdateRequest{
					// ID:                      res1.ID,
					KeyID:                   res1.KeyID,
					UpdateKey:               updateKey,
					HashedTOTPRecoveryCodes: pkg.Mask(slices.Delete(s, foundAt, foundAt+1)),
				}); err != nil {
					return err
				}
				updateKey = res2.UpdateKey
			}
		}

		// var claims = struct {
		// 	jwt.RegisteredClaims
		// 	XID string `json:"xid,omitempty"`
		// }{
		// 	jwt.RegisteredClaims{},
		// 	xid.New().String(),
		// }

		// _ = jwt.SigningMethodRS256
		// jwt.NewWithClaims(jwt.SigningMethodES256, claims).SignedString(nil)

		// _ = xid.New().String()
		// _ = jwt.Claims(nil)

		return nil
	}); err != nil {
		return *new(AuthenticateResponse), err
	}
	return AuthenticateResponse{}, nil
}

func (x *authentication) Register(ctx context.Context, req AuthenticateRequest) (AuthenticateResponse, error) {
	return AuthenticateResponse{}, nil
}

// 1. user GET request & get response of QR code + hidden form of encrypt([xid, totp_secret, ...totp_recovery codes])
// 2. user POST request containing TOTP from client + timestamp
func (x *authentication) LinkTOTP(ctx context.Context, req AuthenticateRequest) (AuthenticateResponse, error) {
	return AuthenticateResponse{}, nil
}
