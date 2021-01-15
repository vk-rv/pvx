package pvx

import (
	"crypto/ed25519"
	"encoding/hex"
	"testing"
	"time"
)

func TestSign(t *testing.T) {

	privateKey, err := hex.DecodeString("b4cbfb43df4ce210727d953e4a713307fa19bb7d9f85041438d9e11b942a37741eb9dbbbbc047c03fd70604e0071f0987e16b28b757225c11f00415d0e20b1a2")
	if err != nil {
		t.Errorf("error while decoding private key: %v", err)
	}

	pv2 := NewPV2Public()

	tests := []struct {
		name        string
		vector      string
		giveMessage []byte
		giveFooter  []byte
		wantToken   string
	}{
		{
			name:      "Empty string, 32-character NUL byte key",
			vector:    "Test Vector S-1",
			wantToken: "v2.public.xnHHprS7sEyjP5vWpOvHjAP2f0HER7SWfPuehZ8QIctJRPTrlZLtRCk9_iNdugsrqJoGaO4k9cDBq3TOXu24AA",
		},
		{
			name:       "Empty string, 32-character NUL byte key, non-empty footer",
			vector:     "Test Vector S-2",
			wantToken:  "v2.public.Qf-w0RdU2SDGW_awMwbfC0Alf_nd3ibUdY3HigzU7tn_4MPMYIKAJk_J_yKYltxrGlxEdrWIqyfjW81njtRyDw.Q3VvbiBBbHBpbnVz",
			giveFooter: []byte("Cuon Alpinus"),
		},
		{
			name:        "Non-empty string, 32-character 0xFF byte key",
			vector:      "Test Vector S-3",
			wantToken:   "v2.public.RnJhbmsgRGVuaXMgcm9ja3NBeHgns4TLYAoyD1OPHww0qfxHdTdzkKcyaE4_fBF2WuY1JNRW_yI8qRhZmNTaO19zRhki6YWRaKKlCZNCNrQM",
			giveMessage: []byte("Frank Denis rocks"),
		},
		{
			name:        "Non-empty string, 32-character 0xFF byte key. (One character difference)",
			vector:      "Test Vector S-4",
			wantToken:   "v2.public.RnJhbmsgRGVuaXMgcm9ja3qIOKf8zCok6-B5cmV3NmGJCD6y3J8fmbFY9KHau6-e9qUICrGlWX8zLo-EqzBFIT36WovQvbQZq4j6DcVfKCML",
			giveMessage: []byte("Frank Denis rockz"),
		},
		{
			name:        "Non-empty string, 32-character 0xFF byte key, non-empty footer",
			vector:      "Test Vector S-5",
			wantToken:   "v2.public.RnJhbmsgRGVuaXMgcm9ja3O7MPuu90WKNyvBUUhAGFmi4PiPOr2bN2ytUSU-QWlj8eNefki2MubssfN1b8figynnY0WusRPwIQ-o0HSZOS0F.Q3VvbiBBbHBpbnVz",
			giveMessage: []byte("Frank Denis rocks"),
			giveFooter:  []byte("Cuon Alpinus"),
		},
		{
			name:        "Non-empty JSON without footer",
			vector:      "Test Vector S-6",
			wantToken:   "v2.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAxOS0wMS0wMVQwMDowMDowMCswMDowMCJ9HQr8URrGntTu7Dz9J2IF23d1M7-9lH9xiqdGyJNvzp4angPW5Esc7C5huy_M8I8_DjJK2ZXC2SUYuOFM-Q_5Cw",
			giveMessage: []byte(`{"data":"this is a signed message","exp":"2019-01-01T00:00:00+00:00"}`),
		},
		{
			name:        "Non-empty JSON with footer",
			vector:      "Test Vector S-7",
			wantToken:   "v2.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAxOS0wMS0wMVQwMDowMDowMCswMDowMCJ9fgvV_frkjyH7h0CWrGfonEctefgzQaCkICOAxDdbixbPvH_SMm0T6343YfgEAlOi8--euLS5gLlykHhREL38BA.UGFyYWdvbiBJbml0aWF0aXZlIEVudGVycHJpc2Vz",
			giveFooter:  []byte("Paragon Initiative Enterprises"),
			giveMessage: []byte(`{"data":"this is a signed message","exp":"2019-01-01T00:00:00+00:00"}`),
		},
		{
			name:        "Non-empty JSON with JSON footer",
			vector:      "Test Vector S-8",
			wantToken:   "v2.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAxOS0wMS0wMVQwMDowMDowMCswMDowMCJ9flsZsx_gYCR0N_Ec2QxJFFpvQAs7h9HtKwbVK2n1MJ3Rz-hwe8KUqjnd8FAnIJZ601tp7lGkguU63oGbomhoBw.eyJraWQiOiJ6VmhNaVBCUDlmUmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9",
			giveMessage: []byte(`{"data":"this is a signed message","exp":"2019-01-01T00:00:00+00:00"}`),
			giveFooter:  []byte(`{"kid":"zVhMiPBP9fRf2snEcT7gFTioeA9COcNy9DfgL1W60haN"}`),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token, err := pv2.sign(privateKey, tt.giveMessage, tt.giveFooter)
			if err != nil {
				t.Errorf("err while signing: %v", err)
			}
			if tt.wantToken != token {
				t.Errorf("tokens are not equal - wantToken: %s, real token: %s", tt.wantToken, token)
			}
		})
	}

}

func TestSignVerify(t *testing.T) {

	type MyToken struct {
		RegisteredClaims
		ArbitraryInfo string `json:"arbitrary_info"`
	}

	myToken := &MyToken{ArbitraryInfo: "arbitrary info", RegisteredClaims: RegisteredClaims{IssuedAt: TimePtr(time.Now())}}

	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Errorf("error while trying to generate keys: %v", err)
	}

	publicKey2, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Errorf("error while trying to generate keys: %w", err)
	}

	pv2 := NewPV2Public()

	tokenStr, err := pv2.SignFooterNil(privateKey, myToken)
	if err != nil {
		t.Errorf("error while trying to sign claims: %v", err)
	}

	tok := pv2.Verify(tokenStr, publicKey2)
	if err := tok.Err(); err == nil {
		t.Errorf("error can't be nil")
	} else {
		if err != ErrInvalidSignature {
			t.Errorf("error should be a type of ErrInvalidSignature")
		}
	}

	tok = pv2.Verify(tokenStr, publicKey)
	if err := tok.Err(); err != nil {
		t.Errorf("error should be nil: %v", err)
	}

	var token MyToken
	if err := tok.ScanClaims(&token); err != nil {
		t.Errorf("error should be nil on scan: %v", err)
	}

	passed := token.IssuedAt.Equal(*myToken.IssuedAt) && token.ArbitraryInfo == myToken.ArbitraryInfo
	if !passed {
		t.Errorf("original claims do not comply with parsed")
	}
}

func TestKeys(t *testing.T) {

	key := []byte("ABCDFGHJKL;")
	pv2 := NewPV2Public()
	if _, err := pv2.Sign(key, nil, nil); err == nil {
		t.Errorf("sign must have key problem")
	}
	_, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Errorf("problem during key generation: %v", err)
	}

	token, err := pv2.Sign(private, nil, nil)
	if err != nil {
		t.Errorf("sign should have a error: %v", err)
	}

	if err := pv2.Verify(token, []byte("")).Err(); err == nil {
		t.Errorf("verify should have key problem")
	}

}

func TestVerifyPrefixMalformedToken(t *testing.T) {

	pv2 := NewPV2Public()
	publicKey, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Errorf("key generation problem: %v", err)
	}

	if err := pv2.Verify("v3.public.ABCD", publicKey).Err(); err == nil {
		t.Errorf("error must not be nil because of malformed token")
	} else {
		if err != ErrMalformedToken {
			t.Errorf("error should be a type of malformed token")
		}
	}
}
