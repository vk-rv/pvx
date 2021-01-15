package pvx

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"strings"
)

// encode performs json.Marshalling for claims and serialize footer interface (not necessary JSON) to byte slice if it is present.
func encode(claims Claims, footerObj interface{}) ([]byte, []byte, error) {

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

func b64(src []byte) string {
	b64RawURL := base64.RawURLEncoding
	dst := make([]byte, b64RawURL.EncodedLen(len(src)))
	b64RawURL.Encode(dst, src)
	return string(dst)
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
