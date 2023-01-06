package sign

import "github.com/eolinker/apinto/application/auth/moon/hash/md5"

const (
	salt = "kayicloud_sign"
)

var _ Sign = (*md5SaltSign)(nil)

type md5SaltSign struct {
}

func (s md5SaltSign) Name() string {
	return "md5salt"
}

func (s md5SaltSign) Sign(origin string) string {
	return md5.Md5(origin + salt)
}
