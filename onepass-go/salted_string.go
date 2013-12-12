package onepass

import (
    "bytes"
    "encoding/base64"
)

// This type represents a string that may or may not be salted.
type SaltedString struct {
    Salt []byte
    Data []byte
    IsSalted bool
}

func NewSaltedString(b64data []byte) (*SaltedString, error) {
	// Trim any null bytes.
	b64data = bytes.Trim(b64data, "\x00")

	// Base64 decode
    decodedData := make([]byte, base64.StdEncoding.DecodedLen(len(b64data)))
    _, err := base64.StdEncoding.Decode(decodedData, b64data)
    if err != nil {
        return nil, err
    }

    if bytes.HasPrefix(decodedData, saltMarker) {
        return &SaltedString{
            Salt: decodedData[8:16],
            Data: decodedData[16:],
            IsSalted: true,
        }, nil
    } else {
        return &SaltedString{
            Salt: defaultIV,
            Data: decodedData,
            IsSalted: false,
        }, nil
    }
}
