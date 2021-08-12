package pvx

import (
	"crypto/ed25519"
	"fmt"
	"strings"
)

const (
	headerV4Public = "v4.public."
)

// ProtoV4Public is a public purpose of PASETO which supports token signing and verification.
type ProtoV4Public struct{}

// NewPV4Public is a constructor-like sugar for ProtoV4Public.
func NewPV4Public() *ProtoV4Public { return &ProtoV4Public{} }

// PV4Public can be used as a global reference for protocol version 4 with public purpose.
var PV4Public = NewPV4Public()

// Sign signs claims with private key, authenticating its content but still preserving in plaintext.
func (pv4 *ProtoV4Public) Sign(sk *AsymSecretKey, claims Claims, ops ...ProvidedOption) (string, error) {

	if !sk.isValidFor(Version4, purposePublic) {
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

	return pv4.sign(sk.keyMaterial, payload, optionalFooter, opts.assertion)

}

func (pv4 *ProtoV4Public) sign(sk ed25519.PrivateKey, message, optionalFooter []byte, assertion []byte) (string, error) {

	if l := len(sk); l != ed25519.PrivateKeySize {
		return "", fmt.Errorf("bad private key length, need %d bytes, provided %d bytes", ed25519.PrivateKeySize, l)
	}

	// step 1
	const header = headerV4Public

	// step 2
	m2 := preAuthenticationEncoding([]byte(header), message, optionalFooter, assertion)

	// step 3
	sig := ed25519.Sign(sk, m2)

	// step 4
	messageWithSignature := append(message, sig...)
	b64MessageWithSignature := b64(messageWithSignature)
	emptyFooter := len(optionalFooter) == 0
	var b64Footer string
	if !emptyFooter {
		b64Footer = b64(optionalFooter)
	}
	var token string
	if emptyFooter {
		token = strings.Join([]string{headerV4Version, headerPurposePublic, b64MessageWithSignature}, ".")
	} else {
		token = strings.Join([]string{headerV4Version, headerPurposePublic, b64MessageWithSignature, b64Footer}, ".")
	}

	return token, nil
}

// Verify just verifies token returning its structure for subsequent mapping.
func (pv4 *ProtoV4Public) Verify(token string, asymmetricPublicKey *AsymPublicKey, ops ...ProvidedOption) *Token {

	if !asymmetricPublicKey.isValidFor(Version4, purposePublic) {
		return &Token{claims: nil, footer: nil, err: ErrWrongKey}
	}

	opts := &optional{}
	for i := range ops {
		err := ops[i](opts)
		if err != nil {
			return &Token{claims: nil, footer: nil, err: err}
		}
	}

	claims, footer, err := pv4.verify(token, asymmetricPublicKey.keyMaterial, opts.assertion)

	return &Token{claims: claims, footer: footer, err: err}

}

func (pv4 *ProtoV4Public) verify(token string, pk ed25519.PublicKey, assertion []byte) ([]byte, []byte, error) {

	if l := len(pk); l != ed25519.PublicKeySize {
		return nil, nil, fmt.Errorf("bad public key length, need %d bytes, provided %d", ed25519.PublicKeySize, l)
	}

	// step 2
	const header = headerV4Public
	if !strings.HasPrefix(token, header) {
		return nil, nil, ErrMalformedToken
	}

	// step 3

	bodyBytes, footerBytes, err := decodeB64ToRawBinary(token, len(header))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decode token: %w", err)
	}

	if len(bodyBytes) < ed25519.SignatureSize {
		return nil, nil, fmt.Errorf("incorrect token size: %w", ErrMalformedToken)
	}

	signature, message := bodyBytes[len(bodyBytes)-ed25519.SignatureSize:], bodyBytes[:len(bodyBytes)-ed25519.SignatureSize]

	// step 4
	m2 := preAuthenticationEncoding([]byte(header), message, footerBytes, assertion)

	// step 5
	if !ed25519.Verify(pk, m2, signature) {
		return nil, nil, ErrInvalidSignature
	}

	return message, footerBytes, nil

}
