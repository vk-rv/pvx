package pvx

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha512"
	"fmt"
	"golang.org/x/crypto/hkdf"
	"io"
	"strings"
)

const (
	headerV3Version      = "v3"
	headerV3PurposeLocal = "local"
	headerV3Local        = "v3.local."
	nonceLenV3           = 32
	macSize              = 48
)

// PV3Local can be used as a global reference for protocol version 3 with local purpose.
var PV3Local = NewPV3Local()

// NewPV3Local is a constructor-like sugar for protocol 3 version local purpose.
func NewPV3Local() *ProtoV3Local {
	return &ProtoV3Local{}
}

// ProtoV3Local is a protocol version 3 with local purpose.
type ProtoV3Local struct {
	testNonce []byte // for unit testing purposes
}

// Encrypt encrypts claims with provided symmetric key and authenticates footer,
// protecting it from tampering but preserving it in base64 encoded plaintext.
func (pv3 *ProtoV3Local) Encrypt(key *SymKey, claims Claims, ops ...ProvidedOption) (string, error) {

	if !key.isValidFor(Version3, purposeLocal) {
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

	return pv3.encrypt(key.keyMaterial, payload, optionalFooter, opts.assertion)
}

// encrypt is a step-by-step algorithm implemented according to RFC.
func (pv3 *ProtoV3Local) encrypt(
	key SymmetricKey,
	message []byte,
	optionalFooter []byte,
	assertion []byte) (string, error) {

	// step 1
	const header = headerV3Local

	// step 2
	nonce := make([]byte, nonceLenV3)
	_, err := rand.Read(nonce)
	if err != nil {
		return "", fmt.Errorf("rand.Read problem: %w", err)
	}

	// this is supplementary and not exposed as a public API (for testing purposes only)
	// it is about replacing random bytes with specified in advance value if we called this from test
	if pv3.testNonce != nil {
		nonce = pv3.testNonce
	}

	// step 3
	encKey, authKey, nonce2, err := splitV3(key, nonce)
	if err != nil {
		return "", fmt.Errorf("splitV3 problem: %w", err)
	}

	// step 4
	block, err := aes.NewCipher(encKey)
	if err != nil {
		return "", fmt.Errorf("failed to create cipher: %w", err)
	}

	c := make([]byte, len(message))
	cipher.NewCTR(block, nonce2).XORKeyStream(c, message)

	// step 5
	preAuth := preAuthenticationEncoding([]byte(header), nonce, c, optionalFooter, assertion)

	// step 6
	mac := hmac.New(sha512.New384, authKey)
	if _, err := mac.Write(preAuth); err != nil {
		return "", fmt.Errorf("problem while creating a signature: %w", err)
	}
	t := mac.Sum(nil)

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
		token = strings.Join([]string{headerV3Version, headerV3PurposeLocal, b64C}, ".")
	} else {
		token = strings.Join([]string{headerV3Version, headerV3PurposeLocal, b64C, b64Footer}, ".")
	}

	return token, nil

}

func splitV3(key SymmetricKey, salt []byte) (encKey []byte, authKey []byte, nonce2 []byte, err error) {
	infoEncryption := []byte("paseto-encryption-key")
	infoEncryption = append(infoEncryption, salt...)
	h := hkdf.New(sha512.New384, key, nil, infoEncryption)
	tmp := make([]byte, 48)
	if _, err := io.ReadFull(h, tmp); err != nil {
		return nil, nil, nil, fmt.Errorf("problem while reading key from hkdf: %w", err)
	}
	encKey = tmp[:32]
	nonce2 = tmp[32:]

	infoAuthentication := []byte("paseto-auth-key-for-aead")
	infoAuthentication = append(infoAuthentication, salt...)
	h = hkdf.New(sha512.New384, key, nil, infoAuthentication)
	authKey = make([]byte, 48)
	if _, err := io.ReadFull(h, authKey); err != nil {
		return nil, nil, nil, fmt.Errorf("problem while reading ak from hkdf: %w", err)
	}

	return encKey, authKey, nonce2, nil

}

// Decrypt implements PASETO v3.Decrypt returning Token struct ready for subsequent scan in case of success.
func (pv3 *ProtoV3Local) Decrypt(token string, key *SymKey, ops ...ProvidedOption) *Token {

	if !key.isValidFor(Version3, purposeLocal) {
		return &Token{claims: nil, footer: nil, err: ErrWrongKey}
	}

	opts := &optional{}
	for i := range ops {
		err := ops[i](opts)
		if err != nil {
			return &Token{claims: nil, footer: nil, err: err}
		}
	}

	plaintextClaims, footer, err := pv3.decrypt(token, key.keyMaterial, opts.assertion)

	return &Token{claims: plaintextClaims, footer: footer, err: err}

}

// decrypt implements PASETO v3.Decrypt returning claims and footer in plaintext
func (pv3 *ProtoV3Local) decrypt(token string, key []byte, assertion []byte) ([]byte, []byte, error) {

	// step 2
	const h = headerV3Local
	if !strings.HasPrefix(token, h) {
		return nil, nil, fmt.Errorf("token does not have header v3 local prefix: %w", ErrMalformedToken)
	}

	// step 3
	bodyRaw, footer, err := decodeB64ToRawBinary(token, len(h))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decode token: %w", err)
	}

	if len(bodyRaw) < nonceLenV3+macSize {
		return nil, nil, fmt.Errorf("incorrect token size: %w", ErrMalformedToken)
	}

	n := bodyRaw[:nonceLenV3]
	c := bodyRaw[nonceLenV3 : len(bodyRaw)-macSize]
	t := bodyRaw[nonceLenV3+len(c):]

	// step 4
	encKey, authKey, nonce2, err := splitV3(key, n)
	if err != nil {
		return nil, nil, fmt.Errorf("splitV3 problem: %w", err)
	}

	// step 5
	preAuth := preAuthenticationEncoding([]byte(h), n, c, footer, assertion)

	// step 6
	mac := hmac.New(sha512.New384, authKey)
	if _, err := mac.Write(preAuth); err != nil {
		return nil, nil, fmt.Errorf("failed to create a signature: %w", err)
	}
	t2 := mac.Sum(nil)

	// step 7
	if !hmac.Equal(t, t2) {
		return nil, nil, fmt.Errorf("invalid MAC for given ciphertext: %w", ErrInvalidSignature)
	}

	// step 8
	block, err := aes.NewCipher(encKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	plaintext := make([]byte, len(c))
	cipher.NewCTR(block, nonce2).XORKeyStream(plaintext, c)

	return plaintext, footer, nil
}
