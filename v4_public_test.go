package pvx

import (
	"encoding/hex"
	"errors"
	"testing"
	"time"
)

func TestV4Sign(t *testing.T) {

	privateKeyMaterial, err := hex.DecodeString("b4cbfb43df4ce210727d953e4a713307fa19bb7d9f85041438d9e11b942a37741eb9dbbbbc047c03fd70604e0071f0987e16b28b757225c11f00415d0e20b1a2")
	if err != nil {
		t.Errorf("error while decoding private key: %v", err)
	}

	asymmetricSecretKey := NewAsymmetricSecretKey(privateKeyMaterial, Version4)

	pv4 := NewPV4Public()

	tests := []struct {
		name              string
		payload           []byte
		footer            []byte
		implicitAssertion []byte

		// want
		token string
	}{
		{
			name:              "4-S-1",
			token:             "v4.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAyMi0wMS0wMVQwMDowMDowMCswMDowMCJ9bg_XBBzds8lTZShVlwwKSgeKpLT3yukTw6JUz3W4h_ExsQV-P0V54zemZDcAxFaSeef1QlXEFtkqxT1ciiQEDA",
			payload:           []byte(`{"data":"this is a signed message","exp":"2022-01-01T00:00:00+00:00"}`),
			footer:            []byte(""),
			implicitAssertion: []byte(""),
		},
		{
			name:              "4-S-2",
			token:             "v4.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAyMi0wMS0wMVQwMDowMDowMCswMDowMCJ9v3Jt8mx_TdM2ceTGoqwrh4yDFn0XsHvvV_D0DtwQxVrJEBMl0F2caAdgnpKlt4p7xBnx1HcO-SPo8FPp214HDw.eyJraWQiOiJ6VmhNaVBCUDlmUmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9",
			payload:           []byte(`{"data":"this is a signed message","exp":"2022-01-01T00:00:00+00:00"}`),
			footer:            []byte(`{"kid":"zVhMiPBP9fRf2snEcT7gFTioeA9COcNy9DfgL1W60haN"}`),
			implicitAssertion: []byte(""),
		},
		{
			name:              "4-S-3",
			token:             "v4.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAyMi0wMS0wMVQwMDowMDowMCswMDowMCJ9NPWciuD3d0o5eXJXG5pJy-DiVEoyPYWs1YSTwWHNJq6DZD3je5gf-0M4JR9ipdUSJbIovzmBECeaWmaqcaP0DQ.eyJraWQiOiJ6VmhNaVBCUDlmUmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9",
			payload:           []byte(`{"data":"this is a signed message","exp":"2022-01-01T00:00:00+00:00"}`),
			footer:            []byte(`{"kid":"zVhMiPBP9fRf2snEcT7gFTioeA9COcNy9DfgL1W60haN"}`),
			implicitAssertion: []byte(`{"test-vector":"4-S-3"}`),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token, err := pv4.sign(asymmetricSecretKey.keyMaterial, tt.payload, tt.footer, tt.implicitAssertion)
			if err != nil {
				t.Errorf("signing problem: %v", err)
			}
			if token != tt.token {
				t.Errorf("got token %v not equal to want token %v", token, tt.token)
			}
		})
	}
}

func TestV4SignVerify(t *testing.T) {

	type AdditionalClaims struct {
		Name string    `json:"string"`
		Num  int       `json:"num"`
		Date time.Time `json:"date"`
	}

	type MyClaims struct {
		RegisteredClaims
		AdditionalClaims
	}

	claims := &MyClaims{
		RegisteredClaims: RegisteredClaims{
			Audience: "paragoni.com",
			IssuedAt: TimePtr(time.Now()),
		},
		AdditionalClaims: AdditionalClaims{Name: "name", Num: 4, Date: time.Now().Add(time.Minute * 60)},
	}

	pv4 := NewPV4Public()

	k, err := hex.DecodeString("b4cbfb43df4ce210727d953e4a713307fa19bb7d9f85041438d9e11b942a37741eb9dbbbbc047c03fd70604e0071f0987e16b28b757225c11f00415d0e20b1a2")
	if err != nil {
		t.Errorf("can't hex decode key")
	}

	asymSK := NewAsymmetricSecretKey(k, Version4)

	k, err = hex.DecodeString("1eb9dbbbbc047c03fd70604e0071f0987e16b28b757225c11f00415d0e20b1a2")
	if err != nil {
		t.Error("can't hex decode key")
	}
	asymPk := NewAsymmetricPublicKey(k, Version4)

	{
		// sign / verify with the same key and the same implicit assertion

		token, err := pv4.Sign(asymSK, claims, WithAssert([]byte("test")))
		if err != nil {
			t.Errorf("can't generate paseto token")
		}

		tk := pv4.Verify(token, asymPk, WithAssert([]byte("test")))
		if tk.Err() != nil {
			t.Errorf("can't verify paseto token, err is %v", tk.Err())
		}

		if tk.HasFooter() {
			t.Errorf("footer was not passed to the library")
		}

		cc := MyClaims{}
		if err := tk.ScanClaims(&cc); err != nil {
			t.Errorf("problem while scanning claims without footer: %v", err)
		}

		testPassed := claims.Audience == cc.Audience && claims.IssuedAt.Equal(*cc.IssuedAt) &&
			claims.Num == cc.Num && claims.Name == cc.Name
		if !testPassed {
			t.Errorf("original structure doesn't equal to parsed")
		}

	}

	{
		// with wrong key

		token, err := pv4.Sign(asymSK, claims, WithAssert([]byte("test")))
		if err != nil {
			t.Errorf("can't generate paseto token")
		}

		wrongKey, err := hex.DecodeString("9eb9dbbbbc047c03fd70604e0071f0987e16b28b757225c11f00415d0e20b1a2")
		if err != nil {
			t.Errorf("can't hex decode key")
		}

		wrongPk := NewAsymmetricPublicKey(wrongKey, Version4)

		tk := pv4.Verify(token, wrongPk, WithAssert([]byte("test")))
		if tk.Err() == nil {
			t.Errorf("error must not be nil")
		}

	}

	{
		// verify with wrong implicit assertion must have error

		token, err := pv4.Sign(asymSK, claims, WithAssert([]byte("test")))
		if err != nil {
			t.Errorf("can't generate paseto token")
		}

		tk := pv4.Verify(token, asymPk, WithAssert([]byte("wrongAssertion")))
		if tk.Err() == nil {
			t.Errorf("verify must not work with wrong assertion")
		} else if !errors.Is(tk.Err(), ErrInvalidSignature) {
			t.Errorf("error should be a type of invalid signature")
		}

	}

	{
		// encrypt / decrypt with footer
		type Footer struct {
			Kid   int    `json:"kid"`
			Other string `json:"other"`
		}
		f := Footer{Kid: 3, Other: "other"}
		token, err := PV4Public.Sign(asymSK, claims, WithFooter(f), WithAssert([]byte("test")))
		if err != nil {
			t.Errorf("can't create paseto token: %v", err)
		}

		tk := PV4Public.Verify(token, asymPk, WithAssert([]byte("test")))
		if tk.Err() != nil {
			t.Errorf("verify err: %v", err)
		}

		ff := Footer{}
		cc := MyClaims{}
		if err := tk.Scan(&cc, &ff); err != nil {
			t.Errorf("scan claims and footer err: %v", err)
		}

		claimsOk := claims.Audience == cc.Audience && claims.IssuedAt.Equal(*cc.IssuedAt) &&
			claims.Num == cc.Num && claims.Name == cc.Name
		if !claimsOk {
			t.Errorf("original structure doesn't equal to parsed")
		}

		footerOk := ff.Kid == f.Kid && ff.Other == f.Other
		if !footerOk {
			t.Errorf("footer scan problem: %v", err)
		}

	}

}

func TestV4PublicWrongVersionKey(t *testing.T) {

	k, err := hex.DecodeString("b4cbfb43df4ce210727d953e4a713307fa19bb7d9f85041438d9e11b942a37741eb9dbbbbc047c03fd70604e0071f0987e16b28b757225c11f00415d0e20b1a2")
	if err != nil {
		t.Errorf("can't hex decode key")
	}

	asymSK := NewAsymmetricSecretKey(k, Version3)
	rc := &RegisteredClaims{}
	_, err = PV4Public.Sign(asymSK, rc)
	if !errors.Is(err, ErrWrongKey) {
		t.Errorf("error should be a type of wrong key")
	}

	tok := "v4.local.JvdVM1RIKh2R1HhGJ4VLjaa4BCp5ZlI8K0BOjbvn9_LwY78vQnDait-Q-sjhF88dG2B0ROIIykcrGHn8wzPbTrqObHhyoKpjy3cwZQzLdiwRsdEK5SDvl02_HjWKJW2oqGMOQJlxnt5xyhQjFJomwnt7WW_7r2VT0G704ifult011-TgLCyQ2X8imQhniG_hAQ4BydM"

	asymPk := NewAsymmetricPublicKey(k, Version3)

	tk := PV4Public.Verify(tok, asymPk)

	if !errors.Is(tk.Err(), ErrWrongKey) {
		t.Errorf("error should be a type of wrong key")
	}
}
