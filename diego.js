function decrypt() { return }
function encrypt() { return }
function exportKey() { return }
function generateKey() { return }
function importKey() { return }
function sign() { return }
function verify() { return }

// upon new connection
// 1 client > will generateKey, then exportKey the privateKey to the localStorage and the publicKey via
//      POST /.well-known/jwks.json
// { "keys":
//  [
//      { "kty":("ECDH"|"OKP"), "crv":("P256"|"P384"|"P521"|"X25519") } ,
//      { "kty":("ECDSA"|"OKP"), "crv":("P256"|"P384"|"P521"|"Ed25519") }
//  ]
// }
// 2 client > also exportKey the generated privateKey to the localStorage
// 3 server > response with a importable ephemeral publicKey that usable in 30secs
//  { "ephemeral": $ } + SetCookie "ephemeral": $ (note that /.well-known/jwks.json is dynamic), invalid ephemeral resulting in keys:[]
// 4 client > navigate to /.well-known/jwks.json?ephemeral=$, and generate a shared secret key with server's ephemeral publicKey
// 5 client > encrypt {"name":("ECDH"&"ECDSA"|"X25519"&"Ed25519"),"publicKey":?} and again
//      POST /v1/client/key {"decrypt":{"name":("AES-CTR"|"AES-CBC"|"AES-GCM"),"length":256,"counter":?,"iv":?,"cipher":?}}, {signature:?}

// "name":("AES-CTR"|"AES-CBC"|"AES-GCM"):{cipher:?}
