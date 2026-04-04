package pkg

// import "iter"

// func NewLinkedList[T any](s ...T) (ll *LinkedList[T]) {
// 	if l := len(s); l > 0 {
// 		ll = new(LinkedList[T])
// 		p, c := (*LinkedList[T])(nil), ll
// 		for i, v := range s {
// 			*c = LinkedList[T]{
// 				Prev: p,
// 				Next: new(LinkedList[T]),
// 				Idx:  i,
// 				Len:  l,
// 				Val:  v,
// 			}
// 			p, c = c, c.Next
// 		}
// 		p.Next = nil // remove Next on last node
// 	}
// 	return ll
// }

// type LinkedList[T any] struct {
// 	Prev, Next *LinkedList[T]
// 	Idx, Len   int
// 	Val        T
// }

// func (x LinkedList[T]) List() (s []T) {
// 	if x.Len > 1 {
// 		s = make([]T, x.Len, x.Len)
// 		for i, v := range x.Seq2() {
// 			s[i] = v
// 		}
// 	}
// 	return s
// }

// func (x LinkedList[T]) Seq() iter.Seq[T] {
// 	return func(yield func(T) bool) {
// 		for c := &x; c != nil; c = c.Next {
// 			if !yield(c.Val) {
// 				return
// 			}
// 		}
// 	}
// }

// func (x LinkedList[T]) Seq2() iter.Seq2[int, T] {
// 	return func(yield func(int, T) bool) {
// 		for c := &x; c != nil; c = c.Next {
// 			if !yield(c.Idx, c.Val) {
// 				return
// 			}
// 		}
// 	}
// }
// ---------------------------------------------------------------------------------------------------------------------

// func TestLinkedList(t *testing.T) {
// 	p := []byte("abba")
// 	ll := pkg.NewLinkedList(p...)

// 	require.True(t, bytes.Equal(p, ll.List()), "p=(%s) ll.List()=(%s)", p, ll.List())

// 	for v := range ll.Seq() {
// 		t.Logf("seq v=(%v)", v)
// 	}

// 	for k, v := range ll.Seq2() {
// 		t.Logf("seq2 k=(%d) v=(%v)", k, v)
// 	}

// 	t.Logf("%v", ll)
// 	for range ll.Len {
// 		ll = ll.Next
// 		t.Logf("%v", ll)
// 	}
// }

// func TestXxx(t *testing.T) {
// 	// km1 := pkg.Nonce(64)
// 	// ps, ks := pkg.Must2(sign.GenerateKey(bytes.NewReader(km1)))
// 	// for range 10_000 {
// 	// 	p0, k0 := pkg.Must2(sign.GenerateKey(bytes.NewReader(km1)))
// 	// 	require.Equal(t, p0, ps)
// 	// 	require.Equal(t, k0, ks)
// 	// }

// 	// pb, kb := pkg.Must2(box.GenerateKey(bytes.NewReader(km1)))
// 	// for range 10_000 {
// 	// 	p1, k1 := pkg.Must2(box.GenerateKey(bytes.NewReader(km1)))
// 	// 	require.Equal(t, p1, pb)
// 	// 	require.Equal(t, k1, kb)
// 	// }

// 	// t.SkipNow()
// 	var now = time.Now()
// 	var mux http.ServeMux
// 	for k, v := range map[string]http.Handler{
// 		"/callback/diego": http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
// 			var err error
// 			if err = r.ParseForm(); err != nil {
// 				return
// 			}

// 			return
// 		}),
// 		"/oauth2/auth": http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
// 			var err error
// 			if err = r.ParseForm(); err != nil {
// 				return
// 			}

// 			return
// 		}),
// 		"/oauth2/auth_device/code": http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
// 			var err error
// 			if err = r.ParseForm(); err != nil {
// 				return
// 			}

// 			return
// 		}),
// 		"/oauth2/auth_device": http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
// 			var err error
// 			if err = r.ParseForm(); err != nil {
// 				return
// 			}
// 			w.Header().Set("content-type", "application/json")
// 			_ = json.NewEncoder(w).Encode(xoauth2.DeviceAuthResponse{
// 				DeviceCode:      "device/1",
// 				UserCode:        "user/1",
// 				Expiry:          now.Add(time.Minute),
// 				Interval:        int64(time.Second.Seconds()),
// 				VerificationURI: "/oauth2/auth_device/code",
// 			})
// 			return
// 		}),
// 		"/oauth2/token": http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
// 			var err error
// 			if err = r.ParseForm(); err != nil {
// 				return
// 			}
// 			_ = r.Form.Get("client_id")
// 			_ = r.Form.Get("client_secret")
// 			_ = r.Form.Get("code_challenge")
// 			_ = r.Form.Get("code_challenge_method")
// 			_ = r.Form.Get("device_code")
// 			_ = r.Form.Get("grant_type")
// 			switch r.Form.Get("grant_type") {
// 			case "urn:ietf:params:oauth:grant-type:device_code":
// 			}

// 			w.Header().Set("content-type", "application/json")
// 			_ = json.NewEncoder(w).Encode(xoauth2.Token{
// 				AccessToken:  "123",
// 				TokenType:    "",
// 				RefreshToken: "123",
// 				Expiry:       now.Add(time.Minute),
// 			})

// 			return
// 		}),
// 	} {
// 		mux.Handle(k, v)
// 	}
// 	srv := httptest.NewUnstartedServer(&mux)
// 	srv.Start()
// 	defer srv.Close()
// 	addr := srv.Listener.Addr().String()
// 	ctx := context.Background()
// 	cfg := &xoauth2.Config{
// 		ClientID:     "ID",
// 		ClientSecret: "SECRET",
// 		Endpoint: xoauth2.Endpoint{
// 			AuthURL:       "http://" + addr + "/oauth2/auth",
// 			DeviceAuthURL: "http://" + addr + "/oauth2/auth_device",
// 			TokenURL:      "http://" + addr + "/oauth2/token",
// 		},
// 		RedirectURL: "/callback/diego",
// 		Scopes: []string{
// 			"openid",
// 			"profile",
// 			"email",
// 			"address",
// 			"phone",
// 			"offline_access",
// 		},
// 	}

// 	var dvc *xoauth2.DeviceAuthResponse
// 	var tok *xoauth2.Token
// 	var acu string
// 	var tsrc xoauth2.TokenSource
// 	var cli *http.Client
// 	var err error
// 	var vrf = xoauth2.GenerateVerifier()
// 	acu = cfg.AuthCodeURL("state", xoauth2.AccessTypeOffline, xoauth2.S256ChallengeOption(vrf))

// 	dvc, err = cfg.DeviceAuth(ctx, xoauth2.S256ChallengeOption(vrf))
// 	t.Log(err, dvc)
// 	tok, err = cfg.DeviceAccessToken(ctx, dvc)
// 	t.Log(err, tok)
// 	tok, err = cfg.Exchange(ctx, "CODE", xoauth2.VerifierOption(vrf), xoauth2.S256ChallengeOption(vrf))
// 	t.Log(err, tok)
// 	tok, err = cfg.PasswordCredentialsToken(ctx, "USERNAME", "PASSWORD")
// 	t.Log(err, tok)

// 	cli = cfg.Client(ctx, tok)
// 	tsrc = cfg.TokenSource(ctx, tok)
// 	cli = xoauth2.NewClient(ctx, tsrc)

// 	_ = acu
// 	_ = cli
// 	return
// }
