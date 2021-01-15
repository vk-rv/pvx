package pvx

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"testing"
	"time"
)

func TestEncrypt(t *testing.T) {

	setupKeys := func() (nullKey, fullKey, symmetricKey SymmetricKey, err error) {
		nullKey = bytes.Repeat([]byte{0}, 32)
		fullKey = bytes.Repeat([]byte{0xff}, 32)
		symmetricKey, err = hex.DecodeString("707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f")
		if err != nil {
			return SymmetricKey{}, SymmetricKey{}, SymmetricKey{}, err
		}
		return
	}
	nullKey, fullKey, symmetricKey, err := setupKeys()
	if err != nil {
		t.Errorf("key setup failed: %v", err)
	}
	setupNonce := func() ([]byte, []byte, error) {
		nonce := bytes.Repeat([]byte{0}, 24)
		nonce2, err := hex.DecodeString("45742c976d684ff84ebdc0de59809a97cda2f64c84fda19b")
		if err != nil {
			return nil, nil, err
		}
		return nonce, nonce2, nil
	}
	emptyNonce, nonce, err := setupNonce()
	if err != nil {
		t.Errorf("nonces setup failed: %v", err)
	}
	footer := []byte("Cuon Alpinus")
	message := []byte("Love is stronger than hate or fear")

	tests := []struct {
		name         string
		givenMessage []byte
		givenFooter  []byte
		givenNonce   []byte
		givenKey     SymmetricKey
		wantToken    string
		testVector   string
	}{

		// everything is empty, split by key
		{
			name:       "Empty message, empty footer, empty nonce, null key",
			givenKey:   nullKey,
			givenNonce: emptyNonce,
			wantToken:  "v2.local.driRNhM20GQPvlWfJCepzh6HdijAq-yNUtKpdy5KXjKfpSKrOlqQvQ",
			testVector: "Test Vector 2E-1-1",
		},

		{
			name:       "Empty message, empty footer, empty nonce, full key",
			givenKey:   fullKey,
			givenNonce: emptyNonce,
			wantToken:  "v2.local.driRNhM20GQPvlWfJCepzh6HdijAq-yNSOvpveyCsjPYfe9mtiJDVg",
			testVector: "Test Vector 2E-1-2",
		},

		{
			name:       "Empty message, empty footer, empty nonce, symmetric key",
			givenKey:   symmetricKey,
			givenNonce: emptyNonce,
			wantToken:  "v2.local.driRNhM20GQPvlWfJCepzh6HdijAq-yNkIWACdHuLiJiW16f2GuGYA",
			testVector: "Test Vector 2E-1-3",
		},

		// everything is empty except of footer, split by key
		{
			name:        "Empty message, non-empty footer, empty nonce, null key",
			givenKey:    nullKey,
			givenNonce:  emptyNonce,
			wantToken:   "v2.local.driRNhM20GQPvlWfJCepzh6HdijAq-yNfzz6yGkE4ZxojJAJwKLfvg.Q3VvbiBBbHBpbnVz",
			givenFooter: footer,
			testVector:  "Test Vector 2E-2-1",
		},

		{
			name:        "Empty message, non-empty footer, empty nonce, full key",
			givenKey:    fullKey,
			givenNonce:  emptyNonce,
			wantToken:   "v2.local.driRNhM20GQPvlWfJCepzh6HdijAq-yNJbTJxAGtEg4ZMXY9g2LSoQ.Q3VvbiBBbHBpbnVz",
			givenFooter: footer,
			testVector:  "Test Vector 2E-2-2",
		},

		{
			name:        "Empty message, non-empty footer, empty nonce, symmetric key",
			givenKey:    symmetricKey,
			givenNonce:  emptyNonce,
			wantToken:   "v2.local.driRNhM20GQPvlWfJCepzh6HdijAq-yNreCcZAS0iGVlzdHjTf2ilg.Q3VvbiBBbHBpbnVz",
			givenFooter: footer,
			testVector:  "Test Vector 2E-2-3",
		},

		// everything is empty except of message split by key
		{
			name:         "Non-empty message, empty footer, empty nonce, null key",
			givenKey:     nullKey,
			givenNonce:   emptyNonce,
			wantToken:    "v2.local.BEsKs5AolRYDb_O-bO-lwHWUextpShFSvu6cB-KuR4wR9uDMjd45cPiOF0zxb7rrtOB5tRcS7dWsFwY4ONEuL5sWeunqHC9jxU0",
			givenMessage: message,
			testVector:   "Test Vector 2E-3-1",
		},

		{
			name:         "Non-empty message, empty footer, empty nonce, full key",
			givenKey:     fullKey,
			givenNonce:   emptyNonce,
			wantToken:    "v2.local.BEsKs5AolRYDb_O-bO-lwHWUextpShFSjvSia2-chHyMi4LtHA8yFr1V7iZmKBWqzg5geEyNAAaD6xSEfxoET1xXqahe1jqmmPw",
			givenMessage: message,
			testVector:   "Test Vector 2E-3-2",
		},

		{
			name:         "Non-empty message, empty footer, empty nonce, symmetric key",
			givenKey:     symmetricKey,
			givenNonce:   emptyNonce,
			wantToken:    "v2.local.BEsKs5AolRYDb_O-bO-lwHWUextpShFSXlvv8MsrNZs3vTSnGQG4qRM9ezDl880jFwknSA6JARj2qKhDHnlSHx1GSCizfcF019U",
			givenMessage: message,
			testVector:   "Test Vector 2E-3-3",
		},

		// Non-empty message, non-empty footer, non-empty nonce
		{
			name:         "Non-empty message, non-empty footer, non-empty nonce, null key",
			givenKey:     nullKey,
			givenNonce:   nonce,
			wantToken:    "v2.local.FGVEQLywggpvH0AzKtLXz0QRmGYuC6yvbcqXgWxM3vJGrJ9kWqquP61Xl7bz4ZEqN5XwH7xyzV0QqPIo0k52q5sWxUQ4LMBFFso.Q3VvbiBBbHBpbnVz",
			givenMessage: message,
			givenFooter:  footer,
			testVector:   "Test Vector 2E-4-1",
		},

		{
			name:         "Non-empty message, non-empty footer, non-empty nonce, full key",
			givenKey:     fullKey,
			givenNonce:   nonce,
			wantToken:    "v2.local.FGVEQLywggpvH0AzKtLXz0QRmGYuC6yvZMW3MgUMFplQXsxcNlg2RX8LzFxAqj4qa2FwgrUdH4vYAXtCFrlGiLnk-cHHOWSUSaw.Q3VvbiBBbHBpbnVz",
			givenMessage: message,
			givenFooter:  footer,
			testVector:   "Test Vector 2E-4-2",
		},

		{
			name:         "Non-empty message, non-empty footer, non-empty nonce, symmetric key",
			givenKey:     symmetricKey,
			givenNonce:   nonce,
			wantToken:    "v2.local.FGVEQLywggpvH0AzKtLXz0QRmGYuC6yvl05z9GIX0cnol6UK94cfV77AXnShlUcNgpDR12FrQiurS8jxBRmvoIKmeMWC5wY9Y6w.Q3VvbiBBbHBpbnVz",
			givenMessage: message,
			givenFooter:  footer,
			testVector:   "Test Vector 2E-4-3",
		},

		// json cases
		{
			name:         "Non-empty JSON message, non-empty footer, non-empty nonce, symmetric key",
			givenKey:     symmetricKey,
			givenNonce:   nonce,
			givenMessage: []byte(`{"data":"this is a signed message","exp":"2019-01-01T00:00:00+00:00"}`),
			givenFooter:  []byte("Paragon Initiative Enterprises"),
			testVector:   "Test Vector 2E-5",
			wantToken:    "v2.local.5K4SCXNhItIhyNuVIZcwrdtaDKiyF81-eWHScuE0idiVqCo72bbjo07W05mqQkhLZdVbxEa5I_u5sgVk1QLkcWEcOSlLHwNpCkvmGGlbCdNExn6Qclw3qTKIIl5-zKeei_8CY0oUMtEai3HYcQ.UGFyYWdvbiBJbml0aWF0aXZlIEVudGVycHJpc2Vz",
		},

		{
			name:         "Non-empty JSON message, non-empty footer, non-empty nonce, symmetric key",
			givenKey:     symmetricKey,
			givenNonce:   nonce,
			givenMessage: []byte(`{"data":"this is a signed message","exp":"2019-01-01T00:00:00+00:00"}`),
			givenFooter:  []byte(`{"kid":"zVhMiPBP9fRf2snEcT7gFTioeA9COcNy9DfgL1W60haN"}`),
			testVector:   "Test Vector 2E-6",
			wantToken:    "v2.local.5K4SCXNhItIhyNuVIZcwrdtaDKiyF81-eWHScuE0idiVqCo72bbjo07W05mqQkhLZdVbxEa5I_u5sgVk1QLkcWEcOSlLHwNpCkvmGGlbCdNExn6Qclw3qTKIIl5-zSLIrxZqOLwcFLYbVK1SrQ.eyJraWQiOiJ6VmhNaVBCUDlmUmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pv2 := NewPV2Local()
			if len(tt.givenNonce) > 0 {
				pv2.testNonce = tt.givenNonce
			}
			token, err := pv2.encrypt(tt.givenKey, tt.givenMessage, tt.givenFooter)
			if err != nil {
				t.Errorf("encryption problem: %v", err)
			}
			if token != tt.wantToken {
				t.Errorf("got token %v not equal to want token %v", token, tt.wantToken)
			}
		})
	}

}

func TestEncryptDecrypt(t *testing.T) {
	pv2 := NewPV2Local()
	k, err := hex.DecodeString("707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f")
	if err != nil {
		t.Errorf("can't hex decode key")
	}

	type AdditionalInformation struct {
		Info   string `json:"info"`
		Number int    `json:"number"`
	}

	type MyClaim struct {
		RegisteredClaims
		AdditionalInformation `json:"additional_info"`
	}

	c := MyClaim{RegisteredClaims: RegisteredClaims{Audience: "paragoni.com", IssuedAt: TimePtr(time.Now()), Expiration: TimePtr(time.Now().Add(time.Minute * 60))},
		AdditionalInformation: AdditionalInformation{Info: "additional info", Number: 10}}

	// first, let's check without a footer
	token, err := pv2.EncryptFooterNil(k, &c)
	if err != nil {
		t.Errorf("encryption problem: %v", err)
	}

	decrypted := pv2.Decrypt(token, k)
	if err := decrypted.Err(); err != nil {
		t.Errorf("decryption problem: %v", err)
	}

	if decrypted.HasFooter() {
		t.Errorf("there must be no footer")
	}

	cc := MyClaim{}
	if err := decrypted.ScanClaims(&cc); err != nil {
		t.Errorf("problem while scanning claims without footer: %v", err)
	}

	testPassed := c.Audience == cc.Audience && c.IssuedAt.Equal(*cc.IssuedAt) && c.Expiration.Equal(*cc.Expiration) &&
		c.AdditionalInformation.Number == cc.AdditionalInformation.Number && c.AdditionalInformation.Info == cc.AdditionalInformation.Info
	if !testPassed {
		t.Errorf("original structure doesn't equal to parsed")
	}

	type Footer struct {
		KID string `json:"kid"`
	}

	footer := Footer{KID: "key info"}

	token, err = pv2.Encrypt(k, &c, footer)
	if err != nil {
		t.Errorf("error during encryption: %v", err)
	}

	parsedFooter := Footer{}

	decrypted = pv2.Decrypt(token, k)
	if err := decrypted.Err(); err != nil {
		t.Errorf("problem while decryption: %v", err)
	}

	if !decrypted.HasFooter() {
		t.Errorf("there must be a footer")
	}

	cc = MyClaim{}

	if err := decrypted.Scan(&cc, &parsedFooter); err != nil {
		t.Errorf("problem while scanning: %v", err)
	}

	passedFooter := footer.KID == parsedFooter.KID
	if !passedFooter {
		t.Errorf("footers do not comply")
	}

	claimsPassed := c.Audience == cc.Audience && c.IssuedAt.Equal(*cc.IssuedAt) && c.Expiration.Equal(*cc.Expiration) &&
		c.AdditionalInformation.Number == cc.AdditionalInformation.Number && c.AdditionalInformation.Info == cc.AdditionalInformation.Info
	if !claimsPassed {
		t.Errorf("original structure doesn't equal to parsed")
	}

	token, err = pv2.Encrypt(k, &c, footer)
	if err != nil {
		t.Errorf("problem while encryption")
	}

	badKey := bytes.Repeat([]byte{2}, 32)
	if err = pv2.Decrypt(token, badKey).Err(); err == nil {
		t.Errorf("error can't be nil because key is different")
	}

	ch := make(chan struct{})
	if _, err := pv2.Encrypt(k, &c, ch); err == nil {
		t.Log("chan cannot be serialized as JSON")
	}
}

func TestPreAuthenticationEncoding(t *testing.T) {
	tests := []struct {
		name   string
		want   string
		pieces [][]byte
	}{
		{
			name:   "Empty slice",
			want:   "0000000000000000",
			pieces: [][]byte{},
		},
		{
			name:   "Slice with one empty elem",
			want:   "01000000000000000000000000000000",
			pieces: [][]byte{{}},
		},
		{
			name:   "Slice of empty elements",
			want:   "020000000000000000000000000000000000000000000000",
			pieces: [][]byte{{}, {}},
		},
		{
			name:   "Slice of non-empty element",
			want:   "0100000000000000070000000000000050617261676f6e",
			pieces: [][]byte{[]byte("Paragon")},
		},
		{
			name:   "Slice of two non-empty elements",
			want:   "0200000000000000070000000000000050617261676f6e0a00000000000000496e6974696174697665",
			pieces: [][]byte{[]byte("Paragon"), []byte("Initiative")},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			packed := preAuthenticationEncoding(tt.pieces...)
			given := hex.EncodeToString(packed)
			if tt.want != given {
				t.Errorf("result from pae doesn't equal to expected: want %s, given %s", tt.want, given)
			}
		})
	}
}

func TestEncodeDecodeFooter(t *testing.T) {

	// string footer
	footer := "mystring"
	b, err := encodeFooter(footer)
	if err != nil {
		t.Errorf("encode footer problem: %v", err)
	}
	if !bytes.Equal([]byte(footer), b) {
		t.Errorf("given string not equal to wanted")
	}

	var decodedFooter string
	if err := decodeFooter(b, &decodedFooter); err != nil {
		t.Errorf("problem while decoding footer: %v", err)
	}

	if decodedFooter != footer {
		t.Errorf("decoded footer not equal to original: %v", err)
	}

	type MyFooter struct {
		KeyID          string    `json:"key_id"`
		AdditionalInfo string    `json:"additional_info"`
		DateTime       time.Time `json:"date_time"`
	}

	// object footer
	mf := MyFooter{KeyID: "keyID", AdditionalInfo: "Additional info here", DateTime: time.Now()}
	b, err = encodeFooter(mf)
	if err != nil {
		t.Errorf("can't encode object footer: %v", err)
	}

	if !json.Valid(b) {
		t.Errorf("object encoded as not a valid json")
	}

	mfn := MyFooter{}
	if err := decodeFooter(b, &mfn); err != nil {
		t.Errorf("can't decode object footer: %v", err)
	}

	if !(mf.DateTime.Equal(mfn.DateTime) && mf.AdditionalInfo == mfn.AdditionalInfo && mf.KeyID == mfn.KeyID) {
		t.Errorf("serialized and deserialized values are not equal")
	}

	// nil footer
	b, err = encodeFooter(nil)
	if err != nil {
		t.Errorf("nil footer raised error: %v", err)
	}
	if !bytes.Equal(b, []byte("")) {
		t.Errorf("nil footer doesn't result in empty string")
	}

	var str string
	if err := decodeFooter(b, &str); err != nil {
		t.Errorf("decode empty footer should resulted in problem: %v", err)
	}

	if str != "" {
		t.Errorf("decoded string is bad")
	}

	bbOrig := []byte("123")
	res, err := encodeFooter(bbOrig)
	if err != nil {
		t.Errorf("problem while encoding byte footer: %v", err)
	}

	var bbParsed []byte
	if err := decodeFooter(res, &bbParsed); err != nil {
		t.Errorf("problem while decoding footer to byte slice pointer")
	}

	if err := decodeFooter([]byte("some footer"), nil); err == nil {
		t.Errorf("there should be error")
	}

	bp := bytes.Repeat([]byte{0}, 16)
	bpEncoded, err := encodeFooter(&bp)
	if err != nil {
		t.Errorf("bytes slice pointer returned error: %v", err)
	}
	if !bytes.Equal(bp, bpEncoded) {
		t.Errorf("bytes not equal")
	}

	sp := "string"
	spEncoded, err := encodeFooter(&sp)
	if err != nil {
		t.Errorf("string pointer encode footer problem: %v", err)
	}
	if !bytes.Equal(spEncoded, []byte(sp)) {
		t.Errorf("byte and string pointer are not equal")
	}

}

func TestEncode(t *testing.T) {
	type myClaims struct {
		RegisteredClaims
		Info string
	}
	mc := &myClaims{}
	footer := "footer"
	payload, ft, err := encode(mc, footer)
	if err != nil {
		t.Errorf("err on ecoding claims and footer: %v", err)
	}
	if !json.Valid(payload) {
		t.Errorf("payload should be JSON")
	}
	if json.Valid(ft) {
		t.Errorf("footer shouldn't be JSON")
	}

	// in this case empty json for payload and nothing for footer
	b, f, err := encode(nil, nil)
	if err != nil {
		t.Errorf("error while encoding body and footer: %v", err)
	}
	if !bytes.Equal(b, []byte("{}")) {
		t.Errorf("empty json should be on nil payload")
	}
	if !bytes.Equal(f, []byte("")) {
		t.Errorf("empty footer results in empty bytes")
	}

}

func TestDecode64ToRawBinary(t *testing.T) {
	const headerLen = len(headerV2Local)
	_, _, err := decodeB64ToRawBinary("v2.local.FGVEQLywggpvH0AzKtLXz0QRmGYuC6yvl05z9GIX0cnol6UK94cfV77AXnShlUcNgpDR12FrQiurS8jxBRmvoIKmeMWC5wY9Y6w.Q3VvbiBBbHBpbnVz", headerLen)
	if err != nil {
		t.Errorf("err while decoding base64 to raw binary: %v", err)
	}

	_, _, err = decodeB64ToRawBinary("v2.local.", len(headerV2Local))
	if err != nil {
		t.Errorf("err should be nil: %v", err)
	}

	// without footer
	_, _, err = decodeB64ToRawBinary("v2.local.FGVEQLywggpvH0AzKtLXz0QRmGYuC6yvl05z9GIX0cnol6UK94cfV77AXnShlUcNgpDR12FrQiurS8jxBRmvoIKmeMWC5wY9Y6w", headerLen)
	if err != nil {
		t.Errorf("err should be nil: %v", err)
	}

	// arbitrarily token
	_, _, err = decodeB64ToRawBinary("v2.local.something.very.strange", headerLen)
	if err == nil {
		t.Errorf("err should not be nil")
	}
	if !errors.Is(err, ErrMalformedToken) {
		t.Errorf("error should be a type of malformed token")
	}

	// not a base64 message
	_, _, err = decodeB64ToRawBinary("v2.local.453^^!.45&&", headerLen)
	if err == nil {
		t.Errorf("err should not be nil")
	}
	var corruptInput base64.CorruptInputError
	if !errors.As(err, &corruptInput) {
		t.Errorf("err should be corrupt input error")
	}

	// not a base64 footer
	_, _, err = decodeB64ToRawBinary("v2.local.FGVEQLywggpvH0AzKtLXz0QRmGYuC6yvl05z9GIX0cnol6UK94cfV77AXnShlUcNgpDR12FrQiurS8jxBRmvoIKmeMWC5wY9Y6w.&&?", headerLen)
	if err == nil {
		t.Errorf("err should not be nil")
	}
	var corruptInputFooter base64.CorruptInputError
	if !errors.As(err, &corruptInputFooter) {
		t.Errorf("err should be corrupt input error")
	}

}
