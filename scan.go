package pvx

import (
	"encoding/json"
	"fmt"
)

// Token is a structure which encapsulates raw claims and optionally raw footer or error which occurred in case of decryption/verification.
type Token struct {
	claims, footer []byte
	err            error // deferred error for easy chaining
}

// HasFooter reports whether footer was not empty after token decryption.
func (t *Token) HasFooter() bool { return len(t.footer) > 0 }

// Err is a getter which helps to separate decryption error from scanning or validation problem.
func (t *Token) Err() error { return t.err }

// Scan deserialize claims to claims object and footer to footer object
// Performs claims validation (or user-provided in case of wrapping) under the hood for safer defaults.
func (t *Token) Scan(claims Claims, footer interface{}) error {
	return t.scan(claims, footer)
}

// ScanClaims deserialize claims to object
// Performs claims validation (or user-provided in case of wrapping) under the hood for safer defaults.
func (t *Token) ScanClaims(claims Claims) error {
	return t.scan(claims, nil)
}

func (t *Token) scan(claims Claims, footer interface{}) error {

	if t.err != nil {
		return t.err
	}

	if err := json.Unmarshal(t.claims, claims); err != nil {
		return fmt.Errorf("can't perform json unmarshal for provided claims: %w", err)
	}

	if err := claims.Valid(); err != nil {
		return err
	}

	if footer != nil {
		if len(t.footer) == 0 {
			return fmt.Errorf("can't decode footer: destination for footer was provided, however there is no footer in token")
		}
		if err := decodeFooter(t.footer, footer); err != nil {
			return err
		}
	}

	return nil

}
