package pvx

import (
	"fmt"
	"time"
)

const (
	ValidationErrorIssuer uint32 = 1 << iota
	ValidationErrorSubject
	ValidationErrorAudience
	ValidationErrorExpired
	ValidationErrorNotValidYet
	ValidationErrorIssuedAt
	ValidationErrorTokenID
	ValidationErrorKeyID
	ValidationErrorClaimsInvalid // generic validation error
)

// ClaimsValidator provides means to validate claims.
type ClaimsValidator interface {
	Valid() error
}

// TimePtr converts time structure to time pointer for optional json marshalling.
func TimePtr(t time.Time) *time.Time { return &t }

// RegisteredClaims are claims indicated in RFC.
type RegisteredClaims struct {
	Issuer     string     `json:"iss,omitempty"`
	Subject    string     `json:"sub,omitempty"`
	Audience   string     `json:"aud,omitempty"`
	Expiration *time.Time `json:"exp,omitempty"`
	NotBefore  *time.Time `json:"nbf,omitempty"`
	IssuedAt   *time.Time `json:"iat,omitempty"`
	TokenID    string     `json:"jti,omitempty"`
	KeyID      string     `json:"kid,omitempty"`
}

// ValidationError is a struct that encapsulates multiple validation errors which can occur during claims validation.
type ValidationError struct {
	Inner  error
	Errors uint32
}

// HasIssuerErr checks the existence of iss validation problem.
func (e *ValidationError) HasIssuerErr() bool { return e.Errors&ValidationErrorIssuer != 0 }

// HasSubjectErr checks the existence of sub validation problem.
func (e *ValidationError) HasSubjectErr() bool { return e.Errors&ValidationErrorSubject != 0 }

// HasAudienceErr checks the existence of aud validation problem.
func (e *ValidationError) HasAudienceErr() bool { return e.Errors&ValidationErrorAudience != 0 }

// HasExpiredErr checks the existence of exp validation problem.
func (e *ValidationError) HasExpiredErr() bool { return e.Errors&ValidationErrorExpired != 0 }

// HasNotBeforeErr checks the existence of nbf validation problem.
func (e *ValidationError) HasNotBeforeErr() bool { return e.Errors&ValidationErrorNotValidYet != 0 }

// HasIssuedAtErr checks the existence of iat validation problem.
func (e *ValidationError) HasIssuedAtErr() bool { return e.Errors&ValidationErrorIssuedAt != 0 }

// HasTokenIDErr checks the existence of jti validation problem.
func (e *ValidationError) HasTokenIDErr() bool { return e.Errors&ValidationErrorTokenID != 0 }

// HasKeyIDErr checks the existence of kid validation problem.
func (e *ValidationError) HasKeyIDErr() bool { return e.Errors&ValidationErrorKeyID != 0 }

// HasGenericValidationErr checks the existence of generic validation problem.
func (e *ValidationError) HasGenericValidationErr() bool {
	return e.Errors&ValidationErrorClaimsInvalid != 0
}

func (e ValidationError) Error() string { return e.Inner.Error() }

// Validates time-based claims "exp, iat, nbf".
// If any of the above claims are not in the token, it will still be considered a valid claim.
func (c *RegisteredClaims) Valid() error {

	t := time.Now()

	validationErr := &ValidationError{}

	if c.Expiration != nil && !c.Expiration.IsZero() && t.After(*c.Expiration) {
		validationErr.Inner = fmt.Errorf("exp - token is expired, delta is equal to %v", time.Since(*c.Expiration))
		validationErr.Errors |= ValidationErrorExpired
	}

	if c.NotBefore != nil && !c.NotBefore.IsZero() && t.Before(*c.NotBefore) {
		validationErr.Inner = fmt.Errorf("nbf - is not valid yet: %w", validationErr.Inner)
		validationErr.Errors |= ValidationErrorNotValidYet
	}

	if c.IssuedAt != nil && !c.IssuedAt.IsZero() && t.Before(*c.IssuedAt) {
		validationErr.Inner = fmt.Errorf("iss - token is issued in the future: %w", validationErr.Inner)
		validationErr.Errors |= ValidationErrorIssuedAt
	}

	if validationErr.Errors != 0 {
		return validationErr
	}

	return nil
}
