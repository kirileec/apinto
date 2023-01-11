package app

import (
	"github.com/eolinker/apinto/application/auth"
	"github.com/eolinker/apinto/application/auth/aksk"
	"github.com/eolinker/apinto/application/auth/apikey"
	"github.com/eolinker/apinto/application/auth/basic"
	"github.com/eolinker/apinto/application/auth/jwt"
	"github.com/eolinker/apinto/application/auth/moon"
	"github.com/eolinker/apinto/application/auth/moon_remote"
	"github.com/eolinker/apinto/drivers"
	"github.com/eolinker/apinto/drivers/app/manager"
	"github.com/eolinker/eosc/common/bean"
	"sync"

	"github.com/eolinker/eosc"
)

var name = "app"

var (
	appManager manager.IManager
	ones       sync.Once
)

// Register 注册service_http驱动工厂
func Register(register eosc.IExtenderDriverRegister) {
	register.RegisterExtenderDriver(name, NewFactory())
}

// NewFactory 创建service_http驱动工厂
func NewFactory() eosc.IExtenderDriverFactory {
	ones.Do(func() {
		apikey.Register()
		basic.Register()
		aksk.Register()
		jwt.Register()
		moon.Register()
		moon_remote.Register()
		appManager = manager.NewManager(auth.Alias(), auth.Keys())
		bean.Injection(&appManager)
	})
	return drivers.NewFactory[Config](Create)
}
