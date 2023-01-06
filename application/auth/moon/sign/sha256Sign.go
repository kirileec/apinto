package sign

import "github.com/eolinker/apinto/application/auth/moon/hash/sha256"

const (
	secret = "kayicloud_sign"
)

var _ Sign = (*sha256Sign)(nil)

type sha256Sign struct {
}

func (s sha256Sign) Name() string {
	return "sha256"
}

func (s sha256Sign) Sign(origin string) string {
	return sha256.Sha256ToHex(origin, secret)
}
