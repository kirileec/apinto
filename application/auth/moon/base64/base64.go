package base64

import (
	"encoding/base64"
)

func encode(src []byte) []byte {
	dst := make([]byte, base64.StdEncoding.EncodedLen(len(src)))
	base64.StdEncoding.Encode(dst, src)
	return dst
}

// EncodeString encodes string with BASE64 algorithm.
func EncodeString(src string) string {
	return EncodeToString([]byte(src))
}

// EncodeToString encodes bytes to string with BASE64 algorithm.
func EncodeToString(src []byte) string {
	return string(encode(src))
}

func decode(data []byte) ([]byte, error) {
	src := make([]byte, base64.StdEncoding.DecodedLen(len(data)))
	n, err := base64.StdEncoding.Decode(src, data)
	return src[:n], err
}

func DecodeString(data string) ([]byte, error) {
	return decode([]byte(data))
}
func DecodeToString(data string) (string, error) {
	b, err := DecodeString(data)
	return string(b), err
}
