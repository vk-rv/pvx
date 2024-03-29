package pvx

import (
	"encoding/hex"
	"errors"
	"testing"
	"time"
)

func TestV3Encrypt(t *testing.T) {
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
			name:              "3-E-1",
			key:               "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f",
			nonce:             "0000000000000000000000000000000000000000000000000000000000000000",
			token:             "v3.local.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADbfcIURX_0pVZVU1mAESUzrKZAsRm2EsD6yBoZYn6cpVZNzSJOhSDN-sRaWjfLU-yn9OJH1J_B8GKtOQ9gSQlb8yk9Iza7teRdkiR89ZFyvPPsVjjFiepFUVcMa-LP18zV77f_crJrVXWa5PDNRkCSeHfBBeg",
			payload:           []byte(`{"data":"this is a secret message","exp":"2022-01-01T00:00:00+00:00"}`),
			footer:            []byte(""),
			implicitAssertion: []byte(""),
		},
		{
			name:    "3-E-2",
			key:     "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f",
			nonce:   "0000000000000000000000000000000000000000000000000000000000000000",
			token:   "v3.local.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADbfcIURX_0pVZVU1mAESUzrKZAqhWxBMDgyBoZYn6cpVZNzSJOhSDN-sRaWjfLU-yn9OJH1J_B8GKtOQ9gSQlb8yk9IzZfaZpReVpHlDSwfuygx1riVXYVs-UjcrG_apl9oz3jCVmmJbRuKn5ZfD8mHz2db0A",
			payload: []byte(`{"data":"this is a hidden message","exp":"2022-01-01T00:00:00+00:00"}`),
		},
		{
			name:              "3-E-3",
			key:               "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f",
			nonce:             "26f7553354482a1d91d4784627854b8da6b8042a7966523c2b404e8dbbe7f7f2",
			token:             "v3.local.JvdVM1RIKh2R1HhGJ4VLjaa4BCp5ZlI8K0BOjbvn9_LwY78vQnDait-Q-sjhF88dG2B0ROIIykcrGHn8wzPbTrqObHhyoKpjy3cwZQzLdiwRsdEK5SDvl02_HjWKJW2oqGMOQJlxnt5xyhQjFJomwnt7WW_7r2VT0G704ifult011-TgLCyQ2X8imQhniG_hAQ4BydM",
			payload:           []byte(`{"data":"this is a secret message","exp":"2022-01-01T00:00:00+00:00"}`),
			footer:            []byte(""),
			implicitAssertion: []byte(""),
		},

		{
			name:              "3-E-4",
			key:               "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f",
			nonce:             "26f7553354482a1d91d4784627854b8da6b8042a7966523c2b404e8dbbe7f7f2",
			token:             "v3.local.JvdVM1RIKh2R1HhGJ4VLjaa4BCp5ZlI8K0BOjbvn9_LwY78vQnDait-Q-sjhF88dG2B0X-4P3EcxGHn8wzPbTrqObHhyoKpjy3cwZQzLdiwRsdEK5SDvl02_HjWKJW2oqGMOQJlBZa_gOpVj4gv0M9lV6Pwjp8JS_MmaZaTA1LLTULXybOBZ2S4xMbYqYmDRhh3IgEk",
			payload:           []byte(`{"data":"this is a hidden message","exp":"2022-01-01T00:00:00+00:00"}`),
			footer:            []byte(""),
			implicitAssertion: []byte(""),
		},

		{
			name:              "3-E-5",
			key:               "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f",
			nonce:             "26f7553354482a1d91d4784627854b8da6b8042a7966523c2b404e8dbbe7f7f2",
			token:             "v3.local.JvdVM1RIKh2R1HhGJ4VLjaa4BCp5ZlI8K0BOjbvn9_LwY78vQnDait-Q-sjhF88dG2B0ROIIykcrGHn8wzPbTrqObHhyoKpjy3cwZQzLdiwRsdEK5SDvl02_HjWKJW2oqGMOQJlkYSIbXOgVuIQL65UMdW9WcjOpmqvjqD40NNzed-XPqn1T3w-bJvitYpUJL_rmihc.eyJraWQiOiJVYmtLOFk2aXY0R1poRnA2VHgzSVdMV0xmTlhTRXZKY2RUM3pkUjY1WVp4byJ9",
			payload:           []byte(`{"data":"this is a secret message","exp":"2022-01-01T00:00:00+00:00"}`),
			footer:            []byte(`{"kid":"UbkK8Y6iv4GZhFp6Tx3IWLWLfNXSEvJcdT3zdR65YZxo"}`),
			implicitAssertion: []byte(""),
		},

		{
			name:              "3-E-6",
			key:               "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f",
			nonce:             "26f7553354482a1d91d4784627854b8da6b8042a7966523c2b404e8dbbe7f7f2",
			token:             "v3.local.JvdVM1RIKh2R1HhGJ4VLjaa4BCp5ZlI8K0BOjbvn9_LwY78vQnDait-Q-sjhF88dG2B0X-4P3EcxGHn8wzPbTrqObHhyoKpjy3cwZQzLdiwRsdEK5SDvl02_HjWKJW2oqGMOQJmSeEMphEWHiwtDKJftg41O1F8Hat-8kQ82ZIAMFqkx9q5VkWlxZke9ZzMBbb3Znfo.eyJraWQiOiJVYmtLOFk2aXY0R1poRnA2VHgzSVdMV0xmTlhTRXZKY2RUM3pkUjY1WVp4byJ9",
			payload:           []byte(`{"data":"this is a hidden message","exp":"2022-01-01T00:00:00+00:00"}`),
			footer:            []byte(`{"kid":"UbkK8Y6iv4GZhFp6Tx3IWLWLfNXSEvJcdT3zdR65YZxo"}`),
			implicitAssertion: []byte(""),
		},

		{
			name:              "3-E-7",
			key:               "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f",
			nonce:             "26f7553354482a1d91d4784627854b8da6b8042a7966523c2b404e8dbbe7f7f2",
			token:             "v3.local.JvdVM1RIKh2R1HhGJ4VLjaa4BCp5ZlI8K0BOjbvn9_LwY78vQnDait-Q-sjhF88dG2B0ROIIykcrGHn8wzPbTrqObHhyoKpjy3cwZQzLdiwRsdEK5SDvl02_HjWKJW2oqGMOQJkzWACWAIoVa0bz7EWSBoTEnS8MvGBYHHo6t6mJunPrFR9JKXFCc0obwz5N-pxFLOc.eyJraWQiOiJVYmtLOFk2aXY0R1poRnA2VHgzSVdMV0xmTlhTRXZKY2RUM3pkUjY1WVp4byJ9",
			payload:           []byte(`{"data":"this is a secret message","exp":"2022-01-01T00:00:00+00:00"}`),
			footer:            []byte(`{"kid":"UbkK8Y6iv4GZhFp6Tx3IWLWLfNXSEvJcdT3zdR65YZxo"}`),
			implicitAssertion: []byte(`{"test-vector":"3-E-7"}`),
		},

		{
			name:              "3-E-8",
			key:               "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f",
			nonce:             "26f7553354482a1d91d4784627854b8da6b8042a7966523c2b404e8dbbe7f7f2",
			token:             "v3.local.JvdVM1RIKh2R1HhGJ4VLjaa4BCp5ZlI8K0BOjbvn9_LwY78vQnDait-Q-sjhF88dG2B0X-4P3EcxGHn8wzPbTrqObHhyoKpjy3cwZQzLdiwRsdEK5SDvl02_HjWKJW2oqGMOQJmZHSSKYR6AnPYJV6gpHtx6dLakIG_AOPhu8vKexNyrv5_1qoom6_NaPGecoiz6fR8.eyJraWQiOiJVYmtLOFk2aXY0R1poRnA2VHgzSVdMV0xmTlhTRXZKY2RUM3pkUjY1WVp4byJ9",
			payload:           []byte(`{"data":"this is a hidden message","exp":"2022-01-01T00:00:00+00:00"}`),
			footer:            []byte(`{"kid":"UbkK8Y6iv4GZhFp6Tx3IWLWLfNXSEvJcdT3zdR65YZxo"}`),
			implicitAssertion: []byte(`{"test-vector":"3-E-8"}`),
		},

		{
			name:              "3-E-9",
			key:               "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f",
			nonce:             "26f7553354482a1d91d4784627854b8da6b8042a7966523c2b404e8dbbe7f7f2",
			token:             "v3.local.JvdVM1RIKh2R1HhGJ4VLjaa4BCp5ZlI8K0BOjbvn9_LwY78vQnDait-Q-sjhF88dG2B0X-4P3EcxGHn8wzPbTrqObHhyoKpjy3cwZQzLdiwRsdEK5SDvl02_HjWKJW2oqGMOQJlk1nli0_wijTH_vCuRwckEDc82QWK8-lG2fT9wQF271sgbVRVPjm0LwMQZkvvamqU.YXJiaXRyYXJ5LXN0cmluZy10aGF0LWlzbid0LWpzb24",
			payload:           []byte(`{"data":"this is a hidden message","exp":"2022-01-01T00:00:00+00:00"}`),
			footer:            []byte("arbitrary-string-that-isn't-json"),
			implicitAssertion: []byte(`{"test-vector":"3-E-9"}`),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pv3 := NewPV3Local()
			if len(tt.nonce) > 0 {
				n, err := hex.DecodeString(tt.nonce)
				if err != nil {
					t.Errorf("problem while decoding nonce: %v", err)
				}
				pv3.testNonce = n
			}

			symmetricKey, err := hex.DecodeString(tt.key)
			if err != nil {
				t.Errorf("problem while decoding symmetric key: %v", err)
			}

			token, err := pv3.encrypt(symmetricKey, tt.payload, tt.footer, tt.implicitAssertion)
			if err != nil {
				t.Errorf("encryption problem: %v", err)
			}
			if token != tt.token {
				t.Errorf("got token %v not equal to want token %v", token, tt.token)
			}
		})
	}
}

func TestV3EncryptDecrypt(t *testing.T) {

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

	pv3 := NewPV3Local()

	k, err := hex.DecodeString("707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f")
	if err != nil {
		t.Errorf("can't hex decode key")
	}

	symK := NewSymmetricKey(k, Version3)

	{
		// encrypt / decrypt with the same key and the same implicit assertion

		token, err := pv3.Encrypt(symK, claims, WithAssert([]byte("test")))
		if err != nil {
			t.Errorf("can't generate paseto token")
		}

		tk := pv3.Decrypt(token, symK, WithAssert([]byte("test")))
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

		token, err := pv3.Encrypt(symK, claims, WithAssert([]byte("test")))
		if err != nil {
			t.Errorf("can't generate paseto token")
		}

		wrongKey, err := hex.DecodeString("707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8a")
		if err != nil {
			t.Errorf("can't hex decode key")
		}

		wrongSymK := NewSymmetricKey(wrongKey, Version3)

		tk := pv3.Decrypt(token, wrongSymK, WithAssert([]byte("test")))
		if tk.Err() == nil {
			t.Errorf("error must not be nil")
		}

	}

	{
		// decrypt with wrong implicit assertion must have error

		token, err := pv3.Encrypt(symK, claims, WithAssert([]byte("test")))
		if err != nil {
			t.Errorf("can't generate paseto token")
		}

		tk := pv3.Decrypt(token, symK, WithAssert([]byte("wrongAssertion")))
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
		token, err := PV3Local.Encrypt(symK, claims, WithFooter(f), WithAssert([]byte("test")))
		if err != nil {
			t.Errorf("can't create paseto token: %v", err)
		}

		tk := PV3Local.Decrypt(token, symK, WithAssert([]byte("test")))
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

func TestV3WrongVersionKey(t *testing.T) {

	k, err := hex.DecodeString("707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f")
	if err != nil {
		t.Errorf("can't hex decode key")
	}

	sk := NewSymmetricKey(k, 4)
	rc := &RegisteredClaims{}
	_, err = PV3Local.Encrypt(sk, rc)
	if !errors.Is(err, ErrWrongKey) {
		t.Errorf("error should be a type of wrong key")
	}

	tok := "v3.local.JvdVM1RIKh2R1HhGJ4VLjaa4BCp5ZlI8K0BOjbvn9_LwY78vQnDait-Q-sjhF88dG2B0ROIIykcrGHn8wzPbTrqObHhyoKpjy3cwZQzLdiwRsdEK5SDvl02_HjWKJW2oqGMOQJlxnt5xyhQjFJomwnt7WW_7r2VT0G704ifult011-TgLCyQ2X8imQhniG_hAQ4BydM"

	tk := PV3Local.Decrypt(tok, sk)

	if !errors.Is(tk.Err(), ErrWrongKey) {
		t.Errorf("error should be a type of wrong key")
	}
}
