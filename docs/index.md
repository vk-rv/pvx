## PVX

PVX is a (work in progress) PASETO implementation for Go programming language.
Currently, library supports version 2 and version 4, and partially version 3 local purpose (if you need NIST-approved algorithms), but it is under active development, does not have unnecessary dependencies and has greater than 86% of test coverage.

You can use https://github.com/o1egl/paseto if you are looking for version 1. 

Why this library exists:
1. https://paragonie.com/blog/2017/03/jwt-json-web-tokens-is-bad-standard-that-everyone-should-avoid 
2. https://www.howmanydayssinceajwtalgnonevuln.com

Check "Intended Use-Cases for PASETO" before using this library. 
https://paseto.io/rfc/draft-00 

[![Go Reference](https://pkg.go.dev/badge/github.com/vk-rv/pvx.svg)](https://pkg.go.dev/github.com/vk-rv/pvx)

# Go version
A minimal version is 1.14

# Installation 
```
go get -u github.com/vk-rv/pvx
```

# General usage

# Version 4 (local)
Recommended

Encrypt / Decrypt 
```go
k, err := hex.DecodeString("707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f")
if err != nil {
    return err 
}
symK := pvx.NewSymmetricKey(k, pvx.Version4)
pv4 := pvx.NewPV4Local()
token, err := pv4.Encrypt(symK, claims, pvx.WithAssert([]byte("test")))
if err != nil {
	return err
}
cc := MyClaims{}
err = pv4.
    Decrypt(token, symK, pvx.WithAssert([]byte("test"))).
    ScanClaims(&cc)
if err != nil {
    return err 
}
// work with cc claims ...

// or without assert
token, err := pv4.Encrypt(symK, claims)
if err != nil {
	return err
}
err = pv4.Decrypt(token, symK).ScanClaims(&cc)

// more info about implicit asserts is here
// https://github.com/paseto-standard/paseto-spec/blob/master/docs/Rationale-V3-V4.md#implicit-assertions-feature

```

# Version 4 (public)
Recommended

Sign / Verify 

```go
publicKey, privateKey, _ := ed25519.GenerateKey(nil)
sk := pvx.NewAsymmetricSecretKey(privateKey, pvx.Version4)
pk := pvx.NewAsymmetricPublicKey(publicKey, pvx.Version4)

pv4 := pvx.NewPV4Public()

token, err := pv4.Sign(sk, claims, pvx.WithAssert([]byte("test")))
if err != nil {//...}

var claims MyClaims 
if err := pv4.Verify(token, pk, pvx.WithAssert([]byte("test")).ScanClaims(&claims); err != nil {//...}

// more info about implicit asserts is here
// https://github.com/paseto-standard/paseto-spec/blob/master/docs/Rationale-V3-V4.md#implicit-assertions-feature

```




# Version 3 (local)
If you need NIST-approved algorithms
```go
k, err := hex.DecodeString("707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f")
if err != nil {
    return err 
}
symK := pvx.NewSymmetricKey(k, pvx.Version3)
pv3 := pvx.NewPV3Local()
token, err := pv3.Encrypt(symK, claims, pvx.WithAssert([]byte("test")))
if err != nil {
	return err
}
cc := MyClaims{}
err = pv3.
    Decrypt(token, symK, pvx.WithAssert([]byte("test"))).
    ScanClaims(&cc)
if err != nil {
    return err 
}
// work with cc claims ...

// or without assert
token, err := pv3.Encrypt(symK, claims)
if err != nil {
	return err
}
err = pv3.Decrypt(token, symK).ScanClaims(&cc)

// more info about implicit asserts is here
// https://github.com/paseto-standard/paseto-spec/blob/master/docs/Rationale-V3-V4.md#implicit-assertions-feature

```

# Claims validation 
PVX adds extra layer of security by adding validation of time-based registered claims during a scan by default.
During validation multiple errors can occur, and you can check every of them by calling sugar routines on special type.
```go
 // For additional layer of safety, 
 // ScanClaims verifies exp, iss and nbf claims automatically under the hood and you can check whether validation error occurred or not 
 if err := decrypted.ScanClaims(&myClaimsScanned); err != nil {
    var validationErr *pvx.ValidationError
    if errors.As(err, &validationErr) {
        if validationErr.HasExpiredErr() { 
                // handle 
		}
		if validationErr.HasNotBeforeErr() { 
                // handle 
		}
	}
}
```

You can also use extend validation rules implementing Claims interface on your custom type
```go
type MyClaims struct {
	pvx.RegisteredClaims
	AdditionalData string
	OtherData string 
} 

func (c *MyClaims) Valid() error {

	validationErr := &pvx.ValidationError{}
	
	// first, check the validity of registered claims
	if err := c.RegisteredClaims.Valid(); err != nil {
		errors.As(err, &validationErr)
	}
	
	//  then, perform custom validation
	
	
	return nil 
	
}

```

To disable validation of registered claims you should implement Claims interface explicitly returning nil in your checks.
This is from design. 

# PASETO V3 and V4
A library has a work in progress status because currently is the next iteration of the PASETO specification.
https://paragonie.com/blog/2021/08/paseto-is-even-more-secure-alternative-jose-standards-jwt-etc
