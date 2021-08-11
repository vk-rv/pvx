## PVX

PVX is a (work in progress) PASETO implementation for Go programming language.
Currently, library supports version 2 and version 3 (local), but it is under active development, does not have unnecessary dependencies and has greater than 91% of test coverage.

You can use https://github.com/o1egl/paseto if you are looking for version 1. 

Why this library exists:
1. https://paragonie.com/blog/2017/03/jwt-json-web-tokens-is-bad-standard-that-everyone-should-avoid 
2. https://www.howmanydayssinceajwtalgnonevuln.com

Check "Intended Use-Cases" before using PASETO 
https://paseto.io/rfc/draft-00 


[![Go Reference](https://pkg.go.dev/badge/github.com/vk-rv/pvx.svg)](https://pkg.go.dev/github.com/vk-rv/pvx)

# Go version
A minimal version is 1.14

# Installation 
```
go get -u github.com/vk-rv/pvx
```

# General usage

## Shared-Key Encryption
```go
type AdditionalClaims struct {
    Number int    `json:"num"`
    Data   string `json:"data"`
}

type MyClaims struct {
    pvx.RegisteredClaims
    AdditionalClaims
}

now := time.Now()
issuedAt := now
expiresAt := now.Add(12 * time.Hour)

claims := MyClaims{
    RegisteredClaims: pvx.RegisteredClaims{
        Issuer:     "paragonie.com", 
        Subject:    "test",
        Audience:   "pie-hosted.com",
        TokenID:    "87IFSGFgPNtQNNuw0AtuLttP",
        IssuedAt:   &issuedAt,
        Expiration: &expiresAt,
		}, 
    AdditionalClaims: AdditionalClaims{
        Number: 14, 
        Data:   "additional data here",
    },
}

symmetricKey := []byte("YELLOW SUBMARINE, BLACK WIZARDRY") // must be 32 bytes

pv2 := pvx.NewPV2Local()
// this encrypts our claims according to PASETO version 2 local purpose algorithm
// this function does not take footer argument because it is optional in PASETO
token, err := pv2.EncryptFooterNil(symmetricKey, &myClaims)
if err != nil { 
    // handle err
}
fmt.Println(token)

// your generated token is
// v2.local.L688dlSnD4EAjIWOhdnE0CRaNWBgDTdB0X0zPbESj0RS8eiaDkrD-lS2xaNMskbOK0rQyTtZCzkHEZB6sj7sGyjLUtI2TyCUFZim8LLK6TIRRN-yzgc6MQYYWtHPCrHgMnhX50yqhpvH0zA2zgwsLOfYpUrT_YrIaOKZRNg7PC7wH9sSOp7Prz2lM8-Xq2Jdc6bO6i_JBROh0l_jhnAoeQZn6OGjnWGKW5BDmBPmxNL80s87YLNOLYU-2IG7Y0FflKeYOqwIWSlEJaCZbA63D39K7rDppec6IXC_uYeFWrCaqGidqImhSVrTcscxI62aHHj5ohxtk_I6lrZHQQ
// where v2 designates PASETO version, local designates purpose and the last part is base64-encoded ciphertext among with nonce, so that nobody can't decrypt it without your key

decrypted := pv2.Decrypt(token, symmetricKey)
if err = decrypted.Err(); err != nil {
    // decryption unsuccessful
}

// here we have decrypted json claims
// {"iss":"paragonie.com","sub":"test","aud":"pie-hosted.com","exp":"2021-01-12T18:35:17.73122+03:00","iat":"2021-01-12T17:35:17.73122+03:00","jti":"87IFSGFgPNtQNNuw0AtuLttP","num":14,"data":"additional data here"}
// scan it to our structure
claimsDest := MyClaims{}
if err := decrypted.ScanClaims(&claimsDest); err != nil {
    // handle err
}

// or you can chain API calls
// in this case decryption error will be deferred until Scan
if err := pv2.Decrypt(token, symmetricKey).ScanClaims(&claimsDest); err != nil {
    // handle err 	
}
```

## Public-Key Authentication
```go
publicKey, privateKey, _ := ed25519.GenerateKey(nil)
pv2 := NewPV2Public()
token, err := pv2.SignFooterNil(privateKey, &myClaims)
if err != nil {//...}

var claims MyClaims 
if err := pv2.Verify(token, publicKey).ScanClaims(&claims); err != nil {//...}


```

# Version 3 (local)
If you need NIST-approved algorithms
```go
k, err := hex.DecodeString("707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f")
if err != nil {
    return err 
}
symK := NewSymmetricKey(k, pvx.Version3)
pv3 := NewPV3Local()
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

// more info about implicit asserts
// https://github.com/paseto-standard/paseto-spec/blob/master/docs/Rationale-V3-V4.md#implicit-assertions-feature
```

# Version 4 (local)
Recommended
```go
k, err := hex.DecodeString("707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f")
if err != nil {
    return err 
}
symK := NewSymmetricKey(k, pvx.Version4)
pv4 := NewPV4Local()
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
