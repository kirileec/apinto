package sign

import (
	"errors"
	"sync"
)

type Sign interface {
	Name() string
	Sign(origin string) string
}

var (
	SignProvider = &SignServiceProvider{}
)

type SignServiceProvider struct {
	signs map[string]Sign
	once  sync.Once
}

func (ssp *SignServiceProvider) Get(key string) (Sign, error) {
	if sign, ok := ssp.signs[key]; ok {
		return sign, nil
	} else {
		return nil, errors.New("sign method not supported")
	}
}

func (ssp *SignServiceProvider) Reg(key string, sign Sign) {
	ssp.once.Do(func() {
		ssp.signs = make(map[string]Sign)
	})
	ssp.signs[key] = sign
}

func init() {
	SignProvider.Reg("md5", &md5SaltSign{})
	SignProvider.Reg("sha256", &sha256Sign{})
}
