package pvx

import (
	"crypto/rand"
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
func (pv2 *ProtoV2Local) Encrypt(key SymmetricKey, claims Claims, footer interface{}) (string, error) {
	payload, optionalFooter, err := encode(claims, footer)
	if err != nil {
		return "", err
	}
	return pv2.encrypt(key, payload, optionalFooter)
}

// EncryptFooterNil is a sugar function which eliminates optional footer from function parameter list
// Equivalent to Encrypt (key, claims, nil).
func (pv2 *ProtoV2Local) EncryptFooterNil(key SymmetricKey, claims Claims) (string, error) {
	return pv2.Encrypt(key, claims, nil)
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

// Decrypt implements PASETO v2.Decrypt returning Token struct ready for subsequent scan in case of success.
func (pv2 *ProtoV2Local) Decrypt(token string, key SymmetricKey) *Token {

	plaintextClaims, footer, err := pv2.decrypt(token, key)

	return &Token{claims: plaintextClaims, footer: footer, err: err}

}

// decrypt implements PASETO v2.Decrypt returning claims and footer in plaintext
func (pv2 *ProtoV2Local) decrypt(token string, key SymmetricKey) ([]byte, []byte, error) {

	if !strings.HasPrefix(token, headerV2Local) {
		return nil, nil, fmt.Errorf("decrypted token does not have header v2 local prefix: %w", ErrMalformedToken)
	}

	bodyBytes, footerBytes, err := decodeB64ToRawBinary(token, len(headerV2Local))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decode token: %w", err)
	}

	if len(bodyBytes) < nonceLen {
		return nil, nil, fmt.Errorf("incorrect token size: %w", ErrMalformedToken)
	}

	nonce := bodyBytes[:nonceLen]
	cipherText := bodyBytes[nonceLen:]

	aead, err := chacha20poly1305.NewX(key.key)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create chachapoly cipher: %w", err)
	}

	additionalData := preAuthenticationEncoding([]byte(headerV2Local), nonce, footerBytes)

	plainTextClaims, err := aead.Open(cipherText[:0], nonce, cipherText, additionalData)
	if err != nil {
		return nil, nil, fmt.Errorf("problem while trying to decrypt token: %w", err)
	}

	return plainTextClaims, footerBytes, nil
}
