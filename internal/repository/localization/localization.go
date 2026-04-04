package localization

// type Key string

// type Val struct {
// 	NumArgs int
// 	Format  string
// }

// func (x Val) Sprint(a ...any) string { return pkg.Sprintf(x.Format, a...) }

// func New(tags ...language.Tag) *l10n {
// 	var tagIndexes = make(tagIndexes)
// 	for _, v := range tags {
// 		tagIndexes[v] = struct{}{}
// 	}
// 	return &l10n{tagIndexes: tagIndexes}
// }

// type l10n struct {
// 	keyIndexes
// 	tagIndexes
// 	dict dict
// }

// func (x l10n) Get(k Key, t language.Tag) (*Val, error) {
// 	if _, ok := x.dict[k]; !ok {
// 		return nil, pkg.Errorf("invalid key: %s", string(k))
// 	} else if v, ok := x.dict[k][t]; !ok {
// 		return nil, pkg.Errorf("invalid tag: %s", t.String())
// 	} else {
// 		return v, nil
// 	}
// }

// func (x l10n) MarshalJSON() (p []byte, err error) {
// 	var w wire
// 	if w, err = x.dict.wire(x.keyIndexes, x.tagIndexes); err == nil {
// 		p, err = json.Marshal(w)
// 	}
// 	return p, err
// }

// func (x *l10n) UnmarshalJSON(p []byte) (err error) {
// 	var w wire
// 	if err = json.Unmarshal(p, &w); err == nil {
// 		x.dict, err = w.dict(x.keyIndexes, x.tagIndexes)
// 	}
// 	return err
// }

// func (x *l10n) WithKeys(keys ...Key) *l10n {
// 	var keyIndexes = make(keyIndexes)
// 	for _, v := range keys {
// 		keyIndexes[v] = struct{}{}
// 	}
// 	x.keyIndexes = keyIndexes
// 	return x
// }

// type wire map[string]map[string][2]any

// func (w wire) dict(sk keyIndexes, st tagIndexes) (d dict, err error) {
// 	errs := []error{}
// 	for k, v := range w {
// 		valid, lk := true, Key(k)
// 		if _, ok := sk[lk]; !ok || k == "" {
// 			valid, errs = false, append(errs, pkg.Errorf("unsupported key: %s", k))
// 		}
// 		for t, v := range v {
// 			lt := language.Make(t)
// 			if _, ok := st[lt]; !ok || t == "" {
// 				valid, errs = false, append(errs, pkg.Errorf("unsupported tag: %s", t))
// 			}
// 			fi, vi, vs, ok := 0.0, 0, "", false
// 			if vi, ok = v[0].(int); !ok || vi < 0 {
// 				if fi, ok = v[0].(float64); !ok || fi < 0 {
// 					valid, errs = false, append(errs, pkg.Errorf("invalid int: %[1]v (%[1]T)", v[0]))
// 				} else {
// 					vi = int(fi)
// 				}
// 			}
// 			if vs, ok = v[1].(string); !ok || vs == "" {
// 				valid, errs = false, append(errs, pkg.Errorf("invalid str: %[1]v (%[1]T)", v[1]))
// 			}
// 			if valid {
// 				if d == nil {
// 					d = make(map[Key]map[language.Tag]*Val)
// 				}
// 				if m, ok := d[lk]; !ok || m == nil {
// 					d[lk] = make(map[language.Tag]*Val)
// 				}
// 				d[lk][lt] = &Val{vi, vs}
// 			}
// 		}
// 	}
// 	return d, errors.Join(errs...)
// }

// type dict map[Key]map[language.Tag]*Val

// func (d dict) wire(sk keyIndexes, st tagIndexes) (w wire, err error) {
// 	errs := []error{}
// 	for lk, v := range d {
// 		valid, k := true, string(lk)
// 		if _, ok := sk[lk]; !ok || lk == "" {
// 			valid, errs = false, append(errs, pkg.Errorf("unsupported key: %s", k))
// 		}
// 		for lt, v := range v {
// 			if _, ok := st[lt]; !ok || lt.IsRoot() {
// 				valid, errs = false, append(errs, pkg.Errorf("unsupported tag: %s", lt.String()))
// 			}
// 			if v.NumArgs < 0 {
// 				valid, errs = false, append(errs, pkg.Errorf("invalid int: %v", v.NumArgs))
// 			}
// 			if v.Format == "" {
// 				valid, errs = false, append(errs, pkg.Errorf("invalid str: %v", v.Format))
// 			}
// 			if valid {
// 				if w == nil {
// 					w = make(map[string]map[string][2]any)
// 				}
// 				if m, ok := w[k]; !ok || m == nil {
// 					w[k] = make(map[string][2]any)
// 				}
// 				w[k][lt.String()] = [2]any{v.NumArgs, v.Format}
// 			}
// 		}
// 	}
// 	return w, errors.Join(errs...)
// }

// type keyIndexes map[Key]struct{}

// type tagIndexes map[language.Tag]struct{}
