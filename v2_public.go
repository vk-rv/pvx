package pvx

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"strings"
)

const (
	headerV2Public      = "v2.public."
	headerPurposePublic = "public"
)

// ErrInvalidSignature is returned when signature in invalid for provided message.
var ErrInvalidSignature = errors.New("invalid token signature")

// ProtoV2Public is a public purpose of PASETO which supports token signing and verification.
type ProtoV2Public struct{}

// NewPV2Public is a constructor-like sugar for ProtoV2Public.
func NewPV2Public() *ProtoV2Public { return &ProtoV2Public{} }

// PV2Public can be used as a global reference for protocol version 2 with public purpose.
var PV2Public = NewPV2Public()

// Sign signs claims with private key, authenticating its content but still preserving in plaintext.
func (pv2 *ProtoV2Public) Sign(privateKey ed25519.PrivateKey, claims ClaimsValidator, footer interface{}) (string, error) {
	payload, optionalFooter, err := encode(claims, footer)
	if err != nil {
		return "", err
	}
	return pv2.sign(privateKey, payload, optionalFooter)
}

// SignFooterNil signs claims with private key, authenticating its content but still preserving in plaintext.
// Does not accept footer, internally calls Sign method with footer equal to nil.
func (pv2 *ProtoV2Public) SignFooterNil(privateKey ed25519.PrivateKey, claims ClaimsValidator) (string, error) {
	return pv2.Sign(privateKey, claims, nil)
}

func (pv2 *ProtoV2Public) sign(sk ed25519.PrivateKey, message, optionalFooter []byte) (string, error) {

	if l := len(sk); l != ed25519.PrivateKeySize {
		return "", fmt.Errorf("bad private key length, need %d bytes, provided %d bytes", ed25519.PrivateKeySize, l)
	}

	const header = headerV2Public
	m2 := preAuthenticationEncoding([]byte(header), message, optionalFooter)
	sig := ed25519.Sign(sk, m2)
	messageWithSignature := append(message, sig...)
	b64MessageWithSignature := b64(messageWithSignature)
	emptyFooter := len(optionalFooter) == 0
	var b64Footer string
	if !emptyFooter {
		b64Footer = b64(optionalFooter)
	}
	var token string
	if emptyFooter {
		token = strings.Join([]string{headerVersion, headerPurposePublic, b64MessageWithSignature}, ".")
	} else {
		token = strings.Join([]string{headerVersion, headerPurposePublic, b64MessageWithSignature, b64Footer}, ".")
	}

	return token, nil
}

func (pv2 *ProtoV2Public) Verify(token string, publicKey ed25519.PublicKey) *Token {
	claims, footer, err := pv2.verify(token, publicKey)
	return &Token{claims: claims, footer: footer, err: err}
}

func (pv2 *ProtoV2Public) verify(token string, pk ed25519.PublicKey) ([]byte, []byte, error) {

	if l := len(pk); l != ed25519.PublicKeySize {
		return nil, nil, fmt.Errorf("bad public key length, need %d bytes, provided %d", ed25519.PublicKeySize, l)
	}

	const header = headerV2Public
	if !strings.HasPrefix(token, header) {
		return nil, nil, ErrMalformedToken
	}

	bodyBytes, footerBytes, err := decodeB64ToRawBinary(token, len(header))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decode token: %w", err)
	}

	if len(bodyBytes) < ed25519.SignatureSize {
		return nil, nil, fmt.Errorf("incorrect token size: %w", ErrMalformedToken)
	}

	signature, message := bodyBytes[len(bodyBytes)-ed25519.SignatureSize:], bodyBytes[:len(bodyBytes)-ed25519.SignatureSize]
	m2 := preAuthenticationEncoding([]byte(header), message, footerBytes)

	if !ed25519.Verify(pk, m2, signature) {
		return nil, nil, ErrInvalidSignature
	}

	return message, footerBytes, nil

}
