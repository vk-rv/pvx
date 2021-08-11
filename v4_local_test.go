package pvx

import (
	"encoding/hex"
	"errors"
	"testing"
	"time"
)

func TestV4Encrypt(t *testing.T) {
	tests := []struct {
		name              string
		key               string
		nonce             string
		payload           []byte
		footer            []byte
		implicitAssertion []byte

		// want
		token string
	}{
		{
			name:              "4-E-1",
			key:               "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f",
			nonce:             "0000000000000000000000000000000000000000000000000000000000000000",
			token:             "v4.local.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAr68PS4AXe7If_ZgesdkUMvSwscFlAl1pk5HC0e8kApeaqMfGo_7OpBnwJOAbY9V7WU6abu74MmcUE8YWAiaArVI8XJ5hOb_4v9RmDkneN0S92dx0OW4pgy7omxgf3S8c3LlQg",
			payload:           []byte(`{"data":"this is a secret message","exp":"2022-01-01T00:00:00+00:00"}`),
			footer:            []byte(""),
			implicitAssertion: []byte(""),
		},
		{
			name:    "4-E-2",
			key:     "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f",
			nonce:   "0000000000000000000000000000000000000000000000000000000000000000",
			token:   "v4.local.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAr68PS4AXe7If_ZgesdkUMvS2csCgglvpk5HC0e8kApeaqMfGo_7OpBnwJOAbY9V7WU6abu74MmcUE8YWAiaArVI8XIemu9chy3WVKvRBfg6t8wwYHK0ArLxxfZP73W_vfwt5A",
			payload: []byte(`{"data":"this is a hidden message","exp":"2022-01-01T00:00:00+00:00"}`),
		},
		{
			name:              "4-E-3",
			key:               "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f",
			nonce:             "df654812bac492663825520ba2f6e67cf5ca5bdc13d4e7507a98cc4c2fcc3ad8",
			token:             "v4.local.32VIErrEkmY4JVILovbmfPXKW9wT1OdQepjMTC_MOtjA4kiqw7_tcaOM5GNEcnTxl60WkwMsYXw6FSNb_UdJPXjpzm0KW9ojM5f4O2mRvE2IcweP-PRdoHjd5-RHCiExR1IK6t6-tyebyWG6Ov7kKvBdkrrAJ837lKP3iDag2hzUPHuMKA",
			payload:           []byte(`{"data":"this is a secret message","exp":"2022-01-01T00:00:00+00:00"}`),
			footer:            []byte(""),
			implicitAssertion: []byte(""),
		},

		{
			name:              "4-E-4",
			key:               "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f",
			nonce:             "df654812bac492663825520ba2f6e67cf5ca5bdc13d4e7507a98cc4c2fcc3ad8",
			token:             "v4.local.32VIErrEkmY4JVILovbmfPXKW9wT1OdQepjMTC_MOtjA4kiqw7_tcaOM5GNEcnTxl60WiA8rd3wgFSNb_UdJPXjpzm0KW9ojM5f4O2mRvE2IcweP-PRdoHjd5-RHCiExR1IK6t4gt6TiLm55vIH8c_lGxxZpE3AWlH4WTR0v45nsWoU3gQ",
			payload:           []byte(`{"data":"this is a hidden message","exp":"2022-01-01T00:00:00+00:00"}`),
			footer:            []byte(""),
			implicitAssertion: []byte(""),
		},

		{
			name:              "4-E-5",
			key:               "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f",
			nonce:             "df654812bac492663825520ba2f6e67cf5ca5bdc13d4e7507a98cc4c2fcc3ad8",
			token:             "v4.local.32VIErrEkmY4JVILovbmfPXKW9wT1OdQepjMTC_MOtjA4kiqw7_tcaOM5GNEcnTxl60WkwMsYXw6FSNb_UdJPXjpzm0KW9ojM5f4O2mRvE2IcweP-PRdoHjd5-RHCiExR1IK6t4x-RMNXtQNbz7FvFZ_G-lFpk5RG3EOrwDL6CgDqcerSQ.eyJraWQiOiJ6VmhNaVBCUDlmUmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9",
			payload:           []byte(`{"data":"this is a secret message","exp":"2022-01-01T00:00:00+00:00"}`),
			footer:            []byte(`{"kid":"zVhMiPBP9fRf2snEcT7gFTioeA9COcNy9DfgL1W60haN"}`),
			implicitAssertion: []byte(""),
		}, // here

		{
			name:              "4-E-6",
			key:               "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f",
			nonce:             "df654812bac492663825520ba2f6e67cf5ca5bdc13d4e7507a98cc4c2fcc3ad8",
			token:             "v4.local.32VIErrEkmY4JVILovbmfPXKW9wT1OdQepjMTC_MOtjA4kiqw7_tcaOM5GNEcnTxl60WiA8rd3wgFSNb_UdJPXjpzm0KW9ojM5f4O2mRvE2IcweP-PRdoHjd5-RHCiExR1IK6t6pWSA5HX2wjb3P-xLQg5K5feUCX4P2fpVK3ZLWFbMSxQ.eyJraWQiOiJ6VmhNaVBCUDlmUmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9",
			payload:           []byte(`{"data":"this is a hidden message","exp":"2022-01-01T00:00:00+00:00"}`),
			footer:            []byte(`{"kid":"zVhMiPBP9fRf2snEcT7gFTioeA9COcNy9DfgL1W60haN"}`),
			implicitAssertion: []byte(""),
		},

		{
			name:              "4-E-7",
			key:               "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f",
			nonce:             "df654812bac492663825520ba2f6e67cf5ca5bdc13d4e7507a98cc4c2fcc3ad8",
			token:             "v4.local.32VIErrEkmY4JVILovbmfPXKW9wT1OdQepjMTC_MOtjA4kiqw7_tcaOM5GNEcnTxl60WkwMsYXw6FSNb_UdJPXjpzm0KW9ojM5f4O2mRvE2IcweP-PRdoHjd5-RHCiExR1IK6t40KCCWLA7GYL9KFHzKlwY9_RnIfRrMQpueydLEAZGGcA.eyJraWQiOiJ6VmhNaVBCUDlmUmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9",
			payload:           []byte(`{"data":"this is a secret message","exp":"2022-01-01T00:00:00+00:00"}`),
			footer:            []byte(`{"kid":"zVhMiPBP9fRf2snEcT7gFTioeA9COcNy9DfgL1W60haN"}`),
			implicitAssertion: []byte(`{"test-vector":"4-E-7"}`),
		},

		{
			name:              "4-E-8",
			key:               "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f",
			nonce:             "df654812bac492663825520ba2f6e67cf5ca5bdc13d4e7507a98cc4c2fcc3ad8",
			token:             "v4.local.32VIErrEkmY4JVILovbmfPXKW9wT1OdQepjMTC_MOtjA4kiqw7_tcaOM5GNEcnTxl60WiA8rd3wgFSNb_UdJPXjpzm0KW9ojM5f4O2mRvE2IcweP-PRdoHjd5-RHCiExR1IK6t5uvqQbMGlLLNYBc7A6_x7oqnpUK5WLvj24eE4DVPDZjw.eyJraWQiOiJ6VmhNaVBCUDlmUmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9",
			payload:           []byte(`{"data":"this is a hidden message","exp":"2022-01-01T00:00:00+00:00"}`),
			footer:            []byte(`{"kid":"zVhMiPBP9fRf2snEcT7gFTioeA9COcNy9DfgL1W60haN"}`),
			implicitAssertion: []byte(`{"test-vector":"4-E-8"}`),
		},

		{
			name:              "4-E-9",
			key:               "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f",
			nonce:             "df654812bac492663825520ba2f6e67cf5ca5bdc13d4e7507a98cc4c2fcc3ad8",
			token:             "v4.local.32VIErrEkmY4JVILovbmfPXKW9wT1OdQepjMTC_MOtjA4kiqw7_tcaOM5GNEcnTxl60WiA8rd3wgFSNb_UdJPXjpzm0KW9ojM5f4O2mRvE2IcweP-PRdoHjd5-RHCiExR1IK6t6tybdlmnMwcDMw0YxA_gFSE_IUWl78aMtOepFYSWYfQA.YXJiaXRyYXJ5LXN0cmluZy10aGF0LWlzbid0LWpzb24",
			payload:           []byte(`{"data":"this is a hidden message","exp":"2022-01-01T00:00:00+00:00"}`),
			footer:            []byte("arbitrary-string-that-isn't-json"),
			implicitAssertion: []byte(`{"test-vector":"4-E-9"}`),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pv4 := NewPV4Local()
			if len(tt.nonce) > 0 {
				n, err := hex.DecodeString(tt.nonce)
				if err != nil {
					t.Errorf("problem while decoding nonce: %v", err)
				}
				pv4.testNonce = n
			}

			symmetricKey, err := hex.DecodeString(tt.key)
			if err != nil {
				t.Errorf("problem while decoding symmetric key: %v", err)
			}

			token, err := pv4.encrypt(symmetricKey, tt.payload, tt.footer, tt.implicitAssertion)
			if err != nil {
				t.Errorf("encryption problem: %v", err)
			}
			if token != tt.token {
				t.Errorf("got token %v not equal to want token %v", token, tt.token)
			}
		})
	}
}

func TestV4EncryptDecrypt(t *testing.T) {

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

	pv4 := NewPV4Local()

	k, err := hex.DecodeString("707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f")
	if err != nil {
		t.Errorf("can't hex decode key")
	}

	symK := NewSymmetricKey(k, Version4)

	{
		// encrypt / decrypt with the same key and the same implicit assertion

		token, err := pv4.Encrypt(symK, claims, WithAssert([]byte("test")))
		if err != nil {
			t.Errorf("can't generate paseto token")
		}

		tk := pv4.Decrypt(token, symK, WithAssert([]byte("test")))
		if tk.Err() != nil {
			t.Errorf("can't decrypt paseto token, err is %v", tk.Err())
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
		// decrypt with wrong key
		// encrypt / decrypt with the same key and the same implicit assertion

		token, err := pv4.Encrypt(symK, claims, WithAssert([]byte("test")))
		if err != nil {
			t.Errorf("can't generate paseto token")
		}

		wrongKey, err := hex.DecodeString("707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8a")
		if err != nil {
			t.Errorf("can't hex decode key")
		}

		wrongSymK := NewSymmetricKey(wrongKey, Version4)

		tk := pv4.Decrypt(token, wrongSymK, WithAssert([]byte("test")))
		if tk.Err() == nil {
			t.Errorf("error must not be nil")
		}

	}

	{
		// decrypt with wrong implicit assertion must have error

		token, err := pv4.Encrypt(symK, claims, WithAssert([]byte("test")))
		if err != nil {
			t.Errorf("can't generate paseto token")
		}

		tk := pv4.Decrypt(token, symK, WithAssert([]byte("wrongAssertion")))
		if tk.Err() == nil {
			t.Errorf("decrypt must not work with wrong assertion")
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
		token, err := PV4Local.Encrypt(symK, claims, WithFooter(f), WithAssert([]byte("test")))
		if err != nil {
			t.Errorf("can't create paseto token: %v", err)
		}

		tk := PV4Local.Decrypt(token, symK, WithAssert([]byte("test")))
		if tk.Err() != nil {
			t.Errorf("decryption err: %v", err)
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

func TestV4WrongVersionKey(t *testing.T) {

	k, err := hex.DecodeString("707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f")
	if err != nil {
		t.Errorf("can't hex decode key")
	}

	sk := NewSymmetricKey(k, 3)
	rc := &RegisteredClaims{}
	_, err = PV4Local.Encrypt(sk, rc)
	if !errors.Is(err, ErrWrongKey) {
		t.Errorf("error should be a type of wrong key")
	}

	tok := "v3.local.JvdVM1RIKh2R1HhGJ4VLjaa4BCp5ZlI8K0BOjbvn9_LwY78vQnDait-Q-sjhF88dG2B0ROIIykcrGHn8wzPbTrqObHhyoKpjy3cwZQzLdiwRsdEK5SDvl02_HjWKJW2oqGMOQJlxnt5xyhQjFJomwnt7WW_7r2VT0G704ifult011-TgLCyQ2X8imQhniG_hAQ4BydM"

	tk := PV4Local.Decrypt(tok, sk)

	if !errors.Is(tk.Err(), ErrWrongKey) {
		t.Errorf("error should be a type of wrong key")
	}
}
