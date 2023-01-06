package sha256

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
)

func Sha256ToHex(origin string, secret string) string {
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(origin))
	return hex.EncodeToString(h.Sum(nil))
}
