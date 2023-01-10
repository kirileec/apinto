package moon

import (
	"fmt"
	"github.com/eolinker/apinto/application"
	http_service "github.com/eolinker/eosc/eocontext/http-context"
	"github.com/eolinker/eosc/log"
)

var _ application.IAuth = (*moon)(nil)

type moon struct {
	id    string
	users application.IUserManager
}

func (a *moon) GetUser(ctx http_service.IHttpContext) (*application.UserInfo, bool) {

	token, has := application.GetToken(ctx, "x-moon-ak", "query")
	if !has || token == "" {
		log.Error("no token")
		return nil, false
	}
	url := ctx.Request().URI().RawURL()
	user, has := a.users.Get(token)

	if has {
		checkResult := NewSignVerify().Begin(url, user.Position, user.Name, user.Value).Verify()
		if checkResult != nil {
			//handle err
			log.Error(checkResult)
			return nil, true
		}
		return user, true

	}
	log.Error("no user")
	return nil, false
}

func (a *moon) ID() string {
	return a.id
}

func (a *moon) Driver() string {
	return driverName
}

func (a *moon) Check(appID string, users []application.ITransformConfig) error {
	us := make([]application.IUser, 0, len(users))
	for _, u := range users {
		v, ok := u.Config().(*User)
		if !ok {
			return fmt.Errorf("%s check error: invalid config type", driverName)
		}
		us = append(us, v)
	}
	return a.users.Check(appID, driverName, us)
}

func (a *moon) Set(app application.IApp, users []application.ITransformConfig) {
	infos := make([]*application.UserInfo, 0, len(users))
	for _, u := range users {
		v, _ := u.Config().(*User)

		infos = append(infos, &application.UserInfo{
			Name:      v.Username(),
			Value:     v.Pattern.SK,
			TokenName: v.Pattern.AppName,
			Position:  v.Pattern.SignMethod,
			App:       app,
		})
	}
	a.users.Set(app.Id(), infos)
}

func (a *moon) Del(appID string) {
	a.users.DelByAppID(appID)
}

func (a *moon) UserCount() int {
	return a.users.Count()
}
