package pvx

import (
	"crypto/hmac"
	"crypto/rand"
	"fmt"
	"strings"

	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/chacha20"
)

const (
	headerV4Version      = "v4"
	headerV4PurposeLocal = "local"
	headerV4Local        = "v4.local."
	nonceLenV4           = 32
	macSizeV4            = 32
)

// PV4Local can be used as a global reference for protocol version 4 with local purpose.
var PV4Local = NewPV4Local()

// NewPV4Local is a constructor-like sugar for protocol 4 version local purpose.
func NewPV4Local() *ProtoV4Local {
	return &ProtoV4Local{}
}

// ProtoV4Local is a protocol version 4 with local purpose.
type ProtoV4Local struct {
	testNonce []byte // for unit testing purposes
}

// Encrypt encrypts claims with provided symmetric key and authenticates footer,
// protecting it from tampering but preserving it in base64 encoded plaintext.
func (pv4 *ProtoV4Local) Encrypt(key *SymKey, claims Claims, ops ...ProvidedOption) (string, error) {

	if !key.isValidFor(Version4, purposeLocal) {
		return "", ErrWrongKey
	}

	opts := &optional{}
	for i := range ops {
		err := ops[i](opts)
		if err != nil {
			return "", err
		}
	}

	payload, optionalFooter, err := encode(claims, opts.footer)
	if err != nil {
		return "", err
	}

	return pv4.encrypt(key.keyMaterial, payload, optionalFooter, opts.assertion)
}

// encrypt is a step-by-step algorithm implemented according to RFC.
func (pv4 *ProtoV4Local) encrypt(
	key SymmetricKey,
	message []byte,
	optionalFooter []byte,
	assertion []byte) (string, error) {

	// step 1
	const header = headerV4Local

	// step 2
	nonce := make([]byte, nonceLenV4)
	_, err := rand.Read(nonce)
	if err != nil {
		return "", fmt.Errorf("rand.Read problem: %w", err)
	}

	// this is supplementary and not exposed as a public API (for testing purposes only)
	// it is about replacing random bytes with specified in advance value if we called this from test
	if pv4.testNonce != nil {
		nonce = pv4.testNonce
	}

	// step 3
	encKey, authKey, nonce2, err := splitV4(key, nonce)
	if err != nil {
		return "", fmt.Errorf("splitV4 problem: %w", err)
	}

	// step 4

	ciph, err := chacha20.NewUnauthenticatedCipher(encKey, nonce2)
	if err != nil {
		return "", fmt.Errorf("failed to create cipher: %w", err)
	}

	c := make([]byte, len(message))
	ciph.XORKeyStream(c, message)

	// step 5
	preAuth := preAuthenticationEncoding([]byte(header), nonce, c, optionalFooter, assertion)

	// step 6
	hash, err := blake2b.New(32, authKey)
	if err != nil {
		return "", fmt.Errorf("blake2b.New hash problem: %w", err)
	}

	if _, err := hash.Write(preAuth); err != nil {
		return "", fmt.Errorf("failed to hash payload: %w", err)
	}

	t := hash.Sum(nil)

	// step 7

	offset := 0
	b64Content := make([]byte, len(nonce)+len(c)+len(t))
	offset += copy(b64Content[offset:], nonce)
	offset += copy(b64Content[offset:], c)
	copy(b64Content[offset:], t)
	b64C := b64(b64Content)

	emptyFooter := len(optionalFooter) == 0
	var b64Footer string
	if !emptyFooter {
		b64Footer = b64(optionalFooter)
	}

	var token string
	if emptyFooter {
		token = strings.Join([]string{headerV4Version, headerV4PurposeLocal, b64C}, ".")
	} else {
		token = strings.Join([]string{headerV4Version, headerV4PurposeLocal, b64C, b64Footer}, ".")
	}

	return token, nil

}

func splitV4(key []byte, salt []byte) (ek []byte, ak []byte, n2 []byte, err error) {

	hash, err := blake2b.New(56, key)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("blake2b.New hash problem: %w", err)
	}

	msg := []byte("paseto-encryption-key")
	msg = append(msg, salt...)

	if _, err := hash.Write(msg); err != nil {
		return nil, nil, nil, fmt.Errorf("failed to hash payload: %w", err)
	}

	tmp := hash.Sum(nil)

	ek = tmp[:32]
	n2 = tmp[32:]

	msgAuth := []byte("paseto-auth-key-for-aead")
	msgAuth = append(msgAuth, salt...)

	hash, err = blake2b.New(32, key)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("blake2b.New hash problem: %w", err)
	}

	if _, err := hash.Write(msgAuth); err != nil {
		return nil, nil, nil, fmt.Errorf("failed to hash payload: %w", err)
	}

	ak = hash.Sum(nil)

	return ek, ak, n2, nil

}

// Decrypt implements PASETO v4.Decrypt returning Token struct ready for subsequent scan in case of success.
func (pv4 *ProtoV4Local) Decrypt(token string, key *SymKey, ops ...ProvidedOption) *Token {

	if !key.isValidFor(Version4, purposeLocal) {
		return &Token{claims: nil, footer: nil, err: ErrWrongKey}
	}

	opts := &optional{}
	for i := range ops {
		err := ops[i](opts)
		if err != nil {
			return &Token{claims: nil, footer: nil, err: err}
		}
	}

	plaintextClaims, footer, err := pv4.decrypt(token, key.keyMaterial, opts.assertion)

	return &Token{claims: plaintextClaims, footer: footer, err: err}

}

// decrypt implements PASETO v4.Decrypt returning claims and footer in plaintext
func (pv4 *ProtoV4Local) decrypt(token string, key []byte, assertion []byte) ([]byte, []byte, error) {

	// step 2
	const h = headerV4Local
	if !strings.HasPrefix(token, h) {
		return nil, nil, fmt.Errorf("token does not have header v4 local prefix: %w", ErrMalformedToken)
	}

	// step 3
	bodyRaw, footer, err := decodeB64ToRawBinary(token, len(h))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decode token: %w", err)
	}

	if len(bodyRaw) < nonceLenV4+macSizeV4 {
		return nil, nil, fmt.Errorf("incorrect token size: %w", ErrMalformedToken)
	}

	n := bodyRaw[:nonceLenV4]
	c := bodyRaw[nonceLenV4 : len(bodyRaw)-macSizeV4]
	t := bodyRaw[nonceLenV4+len(c):]

	// step 4
	encKey, authKey, nonce2, err := splitV4(key, n)
	if err != nil {
		return nil, nil, fmt.Errorf("splitV4 problem: %w", err)
	}

	// step 5
	preAuth := preAuthenticationEncoding([]byte(h), n, c, footer, assertion)

	// step 6
	hash, err := blake2b.New(32, authKey)
	if err != nil {
		return nil, nil, fmt.Errorf("blake2b.New hash problem: %w", err)
	}

	if _, err := hash.Write(preAuth); err != nil {
		return nil, nil, fmt.Errorf("failed to hash payload: %w", err)
	}

	t2 := hash.Sum(nil)

	// step 7
	if !hmac.Equal(t, t2) {
		return nil, nil, fmt.Errorf("invalid MAC for given ciphertext: %w", ErrInvalidSignature)
	}

	// step 8 & 9
	ciph, err := chacha20.NewUnauthenticatedCipher(encKey, nonce2)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	plaintext := make([]byte, len(c))
	ciph.XORKeyStream(plaintext, c)

	return plaintext, footer, nil
}
