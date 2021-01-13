package pvx

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/chacha20poly1305"
)

const nonceLen = 24

const (
	headerVersion      = "v2"
	headerPurposeLocal = "local"
	headerV2Local      = "v2.local."
)

// ErrMalformedToken indicates that obtained token was not properly formed
var ErrMalformedToken = errors.New("token is malformed")

// SymmetricKey is an abstraction for real key aimed at setting up strong typing and invariant.
type SymmetricKey struct {
	key []byte
}

// NewSymmetricKey is a constructor-like function which creates encryption key suitable for Encrypt() / Decrypt() functions.
// Returns error in case when provided byte slice key length does not match to 32 bytes.
func NewSymmetricKey(key []byte) (SymmetricKey, error) {
	if l := len(key); l != chacha20poly1305.KeySize {
		return SymmetricKey{}, fmt.Errorf("key length should be %d bytes, provided %d bytes slice", chacha20poly1305.KeySize, l)
	}
	return SymmetricKey{key: key}, nil
}

// PV2Local can be used as a global reference for protocol version 2 with local purpose.
var PV2Local = NewPV2Local()

// ProtoV2Local is a protocol version 2 with local purpose.
type ProtoV2Local struct {
	testNonce []byte // for unit testing purposes
}

// NewPV2Local is a constructor-like sugar for protocol 2 version local purpose.
func NewPV2Local() *ProtoV2Local {
	return &ProtoV2Local{}
}

// Encrypt encrypts claims with provided symmetric key and authenticates footer,
// protecting it from tampering but preserving it in base64 encoded plaintext.
func (pv2 *ProtoV2Local) Encrypt(key SymmetricKey, claims ClaimsValidator, footer interface{}) (string, error) {
	payload, optionalFooter, err := encode(claims, footer)
	if err != nil {
		return "", err
	}
	return pv2.encrypt(key, payload, optionalFooter)
}

// EncryptFooterNil is a sugar function which eliminates optional footer from function parameter list
// Equivalent to Encrypt (key, claims, nil).
func (pv2 *ProtoV2Local) EncryptFooterNil(key SymmetricKey, claims ClaimsValidator) (string, error) {
	return pv2.Encrypt(key, claims, nil)
}

// encode performs json.Marshalling for claims and serialize footer interface (not necessary JSON) to byte slice if it is present.
func encode(claims ClaimsValidator, footerObj interface{}) ([]byte, []byte, error) {

	var (
		payload []byte
		err     error
	)

	if claims != nil {
		payload, err = json.Marshal(claims)
	} else {
		payload, err = json.Marshal(struct{}{})
	}
	if err != nil {
		return nil, nil, fmt.Errorf("json.Marshal problem with claims: %w", err)
	}

	footer := []byte("")
	if footerObj != nil {
		footer, err = encodeFooter(footerObj)
		if err != nil {
			return nil, nil, err
		}
	}

	return payload, footer, nil
}

func encodeFooter(i interface{}) ([]byte, error) {

	switch v := i.(type) {

	case nil:
		return []byte(""), nil

	case []byte:
		return v, nil

	case *[]byte:
		if v != nil {
			return *v, nil
		}

	case string:
		return []byte(v), nil

	case *string:
		if v != nil {
			return []byte(*v), nil
		}

	}

	return json.Marshal(i)

}

// encrypt is a step-by-step algorithm implemented according to RFC.
func (pv2 *ProtoV2Local) encrypt(key SymmetricKey, message []byte, optionalFooter []byte) (string, error) {

	const header = headerV2Local

	randomBytes := make([]byte, nonceLen)
	_, err := rand.Read(randomBytes)
	if err != nil {
		return "", fmt.Errorf("rand.Read problem: %w", err)
	}

	// this is supplementary and not exposed as a public API (for testing purposes only)
	// it is about replacing random bytes with specified in advance value if we called this from test
	if pv2.testNonce != nil {
		randomBytes = pv2.testNonce
	}

	hash, err := blake2b.New(nonceLen, randomBytes)
	if err != nil {
		return "", fmt.Errorf("blake2b.New hash problem: %w", err)
	}

	if _, err := hash.Write(message); err != nil {
		return "", fmt.Errorf("failed to hash payload: %w", err)
	}

	nonce := hash.Sum(nil)

	additionalData := preAuthenticationEncoding([]byte(header), nonce, optionalFooter)

	aead, err := chacha20poly1305.NewX(key.key)
	if err != nil {
		return "", fmt.Errorf("failed to create chacha20poly1305 aead: %w", err)
	}

	cipherText := aead.Seal(message[:0], nonce, message, additionalData)

	nonceWithCipherText := make([]byte, len(nonce)+len(cipherText))
	offset := 0
	offset += copy(nonceWithCipherText[offset:], nonce)
	copy(nonceWithCipherText[offset:], cipherText)

	b64NonceAndCipherText := b64(nonceWithCipherText)
	emptyFooter := len(optionalFooter) == 0
	var b64Footer string
	if !emptyFooter {
		b64Footer = b64(optionalFooter)
	}
	var token string
	if emptyFooter {
		token = strings.Join([]string{headerVersion, headerPurposeLocal, b64NonceAndCipherText}, ".")
	} else {
		token = strings.Join([]string{headerVersion, headerPurposeLocal, b64NonceAndCipherText, b64Footer}, ".")
	}

	return token, nil
}

// preAuthenticationEncoding is PAE(), find 2.2.1. PAE Definition of RFC
func preAuthenticationEncoding(pieces ...[]byte) []byte {

	count := len(pieces)
	output := &bytes.Buffer{}
	_ = binary.Write(output, binary.LittleEndian, uint64(count))
	for i := range pieces {
		_ = binary.Write(output, binary.LittleEndian, uint64(len(pieces[i])))
		output.Write(pieces[i])
	}

	return output.Bytes()
}

// DecryptedToken is a structure which encapsulates decrypted raw claims and optionally raw footer.
type DecryptedToken struct {
	claims, footer []byte
}

// HasFooter reports whether footer was not empty after token decryption.
func (dt *DecryptedToken) HasFooter() bool { return len(dt.footer) > 0 }

// Scan deserialize claims to claims object and footer to footer object
// Performs claims validation (or user-provided in case of wrapping) under the hood for safer defaults.
func (dt *DecryptedToken) Scan(claims ClaimsValidator, footer interface{}) error {
	return dt.scan(claims, footer)
}

// ScanClaims deserialize claims to object
// Performs claims validation (or user-provided in case of wrapping) under the hood for safer defaults.
func (dt *DecryptedToken) ScanClaims(claims ClaimsValidator) error {
	return dt.scan(claims, nil)
}

func (dt *DecryptedToken) scan(claims ClaimsValidator, footer interface{}) error {

	dec := json.NewDecoder(bytes.NewBuffer(dt.claims))
	if err := dec.Decode(claims); err != nil {
		return fmt.Errorf("can't perform json decode for provided claims: %w", err)
	}

	if err := claims.Valid(); err != nil {
		return err
	}

	if footer != nil {
		if len(dt.footer) == 0 {
			return fmt.Errorf("can't decode footer: destination for footer was provided, however there is no footer in token")
		}
		if err := decodeFooter(dt.footer, footer); err != nil {
			return err
		}
	}

	return nil

}

// Decrypt implements PASETO v2.Decrypt returning DecryptedToken struct ready for subsequent scan in case of success.
func (pv2 *ProtoV2Local) Decrypt(token string, key SymmetricKey) (*DecryptedToken, error) {

	if !strings.HasPrefix(token, headerV2Local) {
		return nil, fmt.Errorf("decrypted token does not have header v2 local prefix: %w", ErrMalformedToken)
	}

	bodyBytes, footerBytes, err := decodeB64ToRawBinary(token, len(headerV2Local))
	if err != nil {
		return nil, fmt.Errorf("failed to decode token: %w", err)
	}

	if len(bodyBytes) < nonceLen {
		return nil, fmt.Errorf("incorrect token size: %w", ErrMalformedToken)
	}

	nonce := bodyBytes[:nonceLen]
	cipherText := bodyBytes[nonceLen:]

	aead, err := chacha20poly1305.NewX(key.key)
	if err != nil {
		return nil, fmt.Errorf("failed to create chachapoly cipher: %w", err)
	}

	additionalData := preAuthenticationEncoding([]byte(headerV2Local), nonce, footerBytes)

	plainTextClaims, err := aead.Open(cipherText[:0], nonce, cipherText, additionalData)
	if err != nil {
		return nil, fmt.Errorf("problem while trying to decrypt token: %w", err)
	}

	return &DecryptedToken{claims: plainTextClaims, footer: footerBytes}, nil
}

func decodeFooter(data []byte, i interface{}) error {
	switch f := i.(type) {
	case *string:
		*f = string(data)
	case *[]byte:
		*f = data
	default:
		if err := json.Unmarshal(data, i); err != nil {
			return fmt.Errorf("problems while trying to unmarshal footer in JSON: %w", err)
		}
	}
	return nil
}

func decodeB64ToRawBinary(token string, headerLen int) (message, footer []byte, err error) {

	var (
		base64EncodedPayload []byte
		base64EncodedFooter  []byte
	)

	parts := strings.Split(token[headerLen:], ".")
	switch len(parts) {
	case 1:
		base64EncodedPayload = []byte(parts[0])
	case 2:
		base64EncodedPayload, base64EncodedFooter = []byte(parts[0]), []byte(parts[1])
	default:
		return nil, nil, ErrMalformedToken
	}

	base64RawURL := base64.RawURLEncoding

	message = make([]byte, base64RawURL.DecodedLen(len(base64EncodedPayload)))
	if _, err := base64RawURL.Decode(message, base64EncodedPayload); err != nil {
		return nil, nil, fmt.Errorf("failed to decode message claims from base64: %w", err)
	}

	if len(base64EncodedFooter) > 0 {
		footer = make([]byte, base64RawURL.DecodedLen(len(base64EncodedFooter)))
		if _, err := base64RawURL.Decode(footer, base64EncodedFooter); err != nil {
			return nil, nil, fmt.Errorf("failed to decode footer from base64: %w", err)
		}
	}

	return message, footer, nil
}

func b64(src []byte) string {
	b64RawURL := base64.RawURLEncoding
	dst := make([]byte, b64RawURL.EncodedLen(len(src)))
	b64RawURL.Encode(dst, src)
	return string(dst)
}
