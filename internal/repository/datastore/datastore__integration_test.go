package datastore_test

// func TestDatastoreIntegration(t *testing.T) {
// 	// _ = sqlite3.Version

// 	var ctx, cancel = context.WithCancel(context.Background())
// 	defer cancel()
// 	var dir = t.TempDir()
// 	_, k1, _ := box.GenerateKey(rand.Reader)

// 	var cfg = datastore.Configuration{}
// 	var dep = datastore.Dependency{
// 		CipherResolver:        datastore.DefaultCipherResolver(k1),
// 		AuthenticationSQLite3: pkg.Must1(sql.Open("sqlite3", "file:"+dir+"test.s3db?_auth&_auth_user=admin&_auth_pass=admin&_auth_crypt=sha1")),
// 	}
// 	_ = pkg.Must1(dep.AuthenticationSQLite3.ExecContext(ctx, query.SQLITE3_AUTHN_MIGRATION_SQL()))
// 	var x = pkg.Must1(datastore.New(ctx, cfg, dep))

// 	var res1 = pkg.Must1(x.MutAccountInsert(ctx, datastore.MutAccountInsertRequest{"username", pkg.Mask([]byte("password"))}))
// 	t.Log(res1)
// 	var res2 = pkg.Must1(x.QryAccount(ctx, datastore.QryAccountRequest{Lookup: "username"}))
// 	t.Log(res2)

// 	var lenOfRecoveryCodeChars = 12
// 	var hasherEmailAddress = pkg.HKDF(pkg.HKDFDefaultOpts(32, []byte("email_address")))
// 	var hasherPhoneNumber = pkg.HKDF(pkg.HKDFDefaultOpts(32, []byte("phone_number")))
// 	var hasherRecoveryCode = pkg.HKDF(pkg.HKDFDefaultOpts(lenOfRecoveryCodeChars, []byte("recovery_code")))
// 	var numOfRecoveryCodes = 16
// 	var recoveryCodes = make([][]byte, numOfRecoveryCodes, numOfRecoveryCodes)
// 	var res3 = pkg.Must1(x.MutAccountUpdate(ctx, datastore.MutAccountUpdateRequest{
// 		ID:        res2.ID,
// 		KeyID:     res2.KeyID,
// 		UpdateKey: res2.UpdateKey,

// 		TOTPSecret: pkg.Mask(gotp.RandomSecret(64)),
// 		HashedTOTPRecoveryCodes: pkg.Mask(func() [][]byte {
// 			hs := make([][]byte, numOfRecoveryCodes, numOfRecoveryCodes)
// 			for i := range numOfRecoveryCodes {
// 				for j, b := range pkg.Nonce(lenOfRecoveryCodeChars) {
// 					recoveryCodes[i] = strconv.AppendInt(recoveryCodes[i], int64(b%10), 10)
// 					char := recoveryCodes[i][j]
// 					require.True(t, '0' <= char && char <= '9', "%s", recoveryCodes[i])
// 				}
// 				var h, _ = hasherRecoveryCode.Hash(recoveryCodes[i])
// 				hs[i] = h
// 			}
// 			return hs
// 		}()),
// 		// HashedTOTPRecoveryCodes: ,
// 		HashedEmailAddress: pkg.Mask(func() []byte {
// 			var h, _ = hasherEmailAddress.Hash([]byte("me@example.com"))
// 			return h
// 		}()),
// 		HashedPhoneNumber: pkg.Mask(func() []byte {
// 			var h, _ = hasherPhoneNumber.Hash([]byte("+6281234567890"))
// 			return h
// 		}()),
// 	}))
// 	t.Log(res3)
// 	t.Logf("%s", recoveryCodes)
// 	var res4 = pkg.Must1(x.QryAccount(ctx, datastore.QryAccountRequest{ID: res3.ID}))
// 	t.Log(res4)

// 	pkg.Must(hasherEmailAddress.Compare([]byte("me@example.com"), res4.HashedEmailAddress.Unmask()))
// 	pkg.Must(hasherPhoneNumber.Compare([]byte("+6281234567890"), res4.HashedPhoneNumber.Unmask()))
// 	for i, code := range res4.HashedTOTPRecoveryCodes.Unmask() {
// 		pkg.Must(hasherRecoveryCode.Compare(recoveryCodes[i], code))
// 	}
// }
