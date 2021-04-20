package pvx

import (
	"encoding/json"
	"errors"
	"testing"
	"time"
)

func TestRegisteredClaimsValidation(t *testing.T) {

	// zero values are always ok
	rc := &RegisteredClaims{}
	if err := rc.Valid(); err != nil {
		t.Errorf("zero initialized claims are not valid: %v", err)
	}

	// expiration problem
	now := time.Now()
	rc = &RegisteredClaims{Expiration: TimePtr(now.AddDate(0, -1, 0))}
	if err := rc.Valid(); err == nil {
		t.Errorf("claims should expire")
	} else {
		validationErr := &ValidationError{}
		if !errors.As(err, &validationErr) {
			t.Errorf("error is not a type of validation error")
		}
		if !validationErr.HasExpiredErr() {
			t.Errorf("field should have expired error")
		}
	}

	// NotBeforeProblem
	rc = &RegisteredClaims{NotBefore: TimePtr(time.Now().Add(time.Minute * 60))}
	if err := rc.Valid(); err == nil {
		t.Errorf("claims should be invalid because time is less then nbf")
	} else {
		validationErr := &ValidationError{}
		if !errors.As(err, &validationErr) {
			t.Errorf("error is not a type of validation error")
		}
		if !validationErr.HasNotBeforeErr() {
			t.Errorf("field should have nbf error")
		}
	}

	rc = &RegisteredClaims{IssuedAt: TimePtr(time.Now().Add(time.Minute * 60))}
	if err := rc.Valid(); err == nil {
		t.Errorf("claims should be invalid because token issued at in future")
	} else {
		validationErr := &ValidationError{}
		if !errors.As(err, &validationErr) {
			t.Errorf("error is not a type of validation error")
		}
		if !validationErr.HasIssuedAtErr() {
			t.Errorf("field should have issued at error")
		}
	}

	// Multiple problems at once
	now = time.Now()
	rc = &RegisteredClaims{
		IssuedAt:   TimePtr(now.Add(time.Minute * 60)),
		NotBefore:  TimePtr(now.Add(time.Minute * 60)),
		Expiration: TimePtr(now.AddDate(0, 0, -1))}
	if err := rc.Valid(); err == nil {
		t.Errorf("claims must be invalid")
	} else {
		validationErr := &ValidationError{}
		if !errors.As(err, &validationErr) {
			t.Errorf("error is not a type of validation error")
		}
		passed := validationErr.HasIssuedAtErr() &&
			validationErr.HasNotBeforeErr() &&
			validationErr.HasExpiredErr() &&
			!validationErr.HasAudienceErr() &&
			!validationErr.HasGenericValidationErr() &&
			!validationErr.HasIssuerErr() &&
			!validationErr.HasKeyIDErr() &&
			!validationErr.HasSubjectErr() &&
			!validationErr.HasKeyIDErr() &&
			!validationErr.HasTokenIDErr()
		if !passed {
			t.Errorf("claims should have simultaneously 3 errors and don't have others")
		}

	}
}

func TestRegisteredClaimsMarshalJSON(t *testing.T) {
	iat := time.Now()
	exp := time.Now()
	c := RegisteredClaims{IssuedAt: &iat, Expiration: &exp, NotBefore: &time.Time{}}
	b, err := json.Marshal(c)
	if err != nil {
		t.Errorf("problem while trying to marshal registered claims: %v", err)
	}

	cc := RegisteredClaims{}
	if err := json.Unmarshal(b, &cc); err != nil {
		t.Errorf("problem while trying to unmarshal registered claims: %v", err)
	}

	if !cc.NotBefore.IsZero() {
		t.Errorf("not before must be zero")
	}

	if cc.Expiration.IsZero() || cc.IssuedAt.IsZero() {
		t.Errorf("exp and iat must not be zero")
	}

	passed := c.IssuedAt.Equal(*cc.IssuedAt) && c.Expiration.Equal(*cc.Expiration) && c.NotBefore.Equal(*cc.NotBefore)
	if !passed {
		t.Errorf("serialized and deserialized values are not equal")
	}

	nbf := time.Now()
	c = RegisteredClaims{NotBefore: &nbf}
	b, err = json.Marshal(c)
	if err != nil {
		t.Errorf("serialization problem: %v", err)
	}

	cc = RegisteredClaims{}
	if err := json.Unmarshal(b, &cc); err != nil {
		t.Errorf("deserialization problem: %v", err)
	}

	if !c.NotBefore.Equal(*cc.NotBefore) {
		t.Errorf("nbf are not equal")
	}

}
