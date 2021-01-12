## PVX

PVX is a PASETO implementation for Go programming language.
Currently, API is not stabilized and supports only local purpose of version 2 which
encrypts claims and authenticates footer (preserving it in base64 encoded plaintext), but the library is under active development, does not have unnecessary dependencies and has greater than 91% of test coverage.

# Go version
A minimal version is 1.14

# Installation 
```
go get -u github.com/vk-rv/pvx
```

# General usage
```go
type AdditionalClaims struct {
		Number int    `json:"num"`
		Data   string `json:"data"`
	}

	type MyClaims struct {
		pvx.RegisteredClaims
		AdditionalClaims
	}

	myClaims := MyClaims{
		RegisteredClaims: RegisteredClaims{
			Issuer:     "paragonie.com",
			Subject:    "test",
			Audience:   "pie-hosted.com",
			TokenID:    "87IFSGFgPNtQNNuw0AtuLttP",
			IssuedAt:   TimePtr(time.Now()),
			Expiration: TimePtr(time.Now().Add(time.Hour * 1)),
		},
		AdditionalClaims: AdditionalClaims{
			Number: 14,
			Data:   "additional data here",
		},
	}

	key, err := pvx.NewSymmetricKey([]byte("YELLOW SUBMARINE, BLACK WIZARDRY")) // must be 32 bytes
	if err != nil {
		// handle err
	}

	pv2 := pvx.NewPV2Local()

	// this encrypts our claims according to PASETO version 2 local purpose algorithm
	// this function does not take footer argument because it is optional in PASETO
	token, err := pv2.EncryptFooterNil(key, &myClaims)
	if err != nil {
		// handle err
	}

	fmt.Println(token)

	// your generated token is
	// v2.local.L688dlSnD4EAjIWOhdnE0CRaNWBgDTdB0X0zPbESj0RS8eiaDkrD-lS2xaNMskbOK0rQyTtZCzkHEZB6sj7sGyjLUtI2TyCUFZim8LLK6TIRRN-yzgc6MQYYWtHPCrHgMnhX50yqhpvH0zA2zgwsLOfYpUrT_YrIaOKZRNg7PC7wH9sSOp7Prz2lM8-Xq2Jdc6bO6i_JBROh0l_jhnAoeQZn6OGjnWGKW5BDmBPmxNL80s87YLNOLYU-2IG7Y0FflKeYOqwIWSlEJaCZbA63D39K7rDppec6IXC_uYeFWrCaqGidqImhSVrTcscxI62aHHj5ohxtk_I6lrZHQQ
	// where v2 designates PASETO version, local designates purpose and the last part is base64-encoded ciphertext among with nonce, so that nobody can't decrypt it without your key

	decrypted, err := pv2.Decrypt(token, key)
	if err != nil {
		// decryption unsuccessful, handle err
	}

	// here we have decrypted json claims
	// {"iss":"paragonie.com","sub":"test","aud":"pie-hosted.com","exp":"2021-01-12T18:35:17.73122+03:00","iat":"2021-01-12T17:35:17.73122+03:00","jti":"87IFSGFgPNtQNNuw0AtuLttP","num":14,"data":"additional data here"}
	// scan it to our structure
	myClaimsScanned := MyClaims{}
	if err := decrypted.ScanClaims(&myClaimsScanned); err != nil {
		// handle err
	}
```

# Claims validation 
PVX adds extra layer of security by adding validation of time-based registered claims during a scan by default.
During validation multiple errors can occur, and you can check every of them by calling sugar routines on special type.
```go
 // For additional layer of safety, 
 // ScanClaims verifies exp, iss and nbf claims automatically under the hood and you can check whether validation error occurred or not
	if err := decrypted.ScanClaims(&myClaimsScanned); err != nil {
		var pvx.validationErr *ValidationError
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

You can also use extend validation rules implementing ClaimsValidator interface on your custom type
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
	
	if c.Audience != "mysite.com" {
		validationErr.Inner = fmt.Errorf("aud - audience does not match: %w", validationErr.Inner)
		validationErr.Errors |= pvx.ValidationErrorAudience
	}
	
	// for general errors, set ValidationErrorClaimsInvalid
	
	if c.AdditionalData != "myVal" {
		validationErr.Inner = fmt.Errorf("additionalData - other data is empty: %w", validationErr.Inner)
		validationErr.Errors |= pvx.ValidationErrorClaimsInvalid
	}
	
	if c.OtherData == "" {
		validationErr.Inner = fmt.Errorf("otherData - other data is empty: %w", validationErr.Inner)
		validationErr.Errors |= pvx.ValidationErrorClaimsInvalid
	}
	
	if validationErr.Errors != 0 {
		return validationErr
	}
	
	return nil 
	
}

```

To disable validation of registered claims you should implement ClaimsValidator explicitly returning nil in your checks.
This is from design. 