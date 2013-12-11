package onepass

import (
    "bytes"
    "errors"
)

var (
    saltMarker = []byte("Salted__")
    defaultIV = bytes.Repeat([]byte{0}, 16)

    InvalidPassword = errors.New("invalid password")
)

