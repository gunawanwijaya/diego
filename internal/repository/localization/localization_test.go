package localization_test

// "github.com/goccy/go-yaml"

// func TestLocalization(t *testing.T) {
// 	en, id, jp := language.English, language.Indonesian, language.Japanese
// 	const k = localization.Key("L10N_HELLO")
// 	l := localization.New(en, id).WithKeys(
// 		k,
// 		"L10N_BYE",
// 	)

// 	p := []byte(`
// 	` + k + `:
// 	  en: [1,"Hi %[1]s, how are you?"]
// 	  id: [2,"Halo %[1]s %[2]s, bagaimana kabarmu?"]
// 	L10N_BYE:
// 	  en: [0,"See you later"]
// 	  id: [0,"Sampai jumpa lagi"]
// 	`)
// 	p = []byte(strings.ReplaceAll(string(p), "\t", "  "))
// 	var tmp map[string]map[string][2]any
// 	pkg.Must(yaml.Unmarshal(p, &tmp))
// 	p = pkg.Must1(json.Marshal(tmp))
// 	pkg.Must(json.Unmarshal(p, l))
// 	require.JSONEq(t, string(p), string(pkg.Must1(json.Marshal(l))))

// 	var v *localization.Val
// 	v = pkg.Must1(l.Get(k, en))
// 	require.Equal(t, "Hi John, how are you?", v.Sprint("John"))
// 	v = pkg.Must1(l.Get(k, id))
// 	require.Equal(t, "Halo Pak John, bagaimana kabarmu?", v.Sprint("Pak", "John"))

// 	var err error
// 	v, err = l.Get(k, jp)
// 	require.Error(t, err)
// 	v, err = l.Get("??", id)
// 	require.Error(t, err)
// 	err = json.Unmarshal([]byte(`{"`+k+`":{},"NO_KEY":{"jp":[]}}`), l)
// 	require.Error(t, err)
// }
