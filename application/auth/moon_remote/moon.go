package moon_remote

import (
	"encoding/json"
	"fmt"
	"github.com/eolinker/apinto/application"
	"github.com/eolinker/apinto/application/auth/moon/base64"
	http_service "github.com/eolinker/eosc/eocontext/http-context"
	"github.com/eolinker/eosc/log"
	"gopkg.in/resty.v1"
)

var _ application.IAuth = (*moon)(nil)

type moon struct {
	id    string
	users application.IUserManager
}

type CheckGetRequest struct {
	Url        string `json:"url"`
	SignMethod string `json:"signMethod"` //签名方法默认 sha256
}
type CheckSignResult struct {
	Code int    `json:"code"`
	Msg  string `json:"msg"`
	Data bool   `json:"data"`
}

func (a *moon) GetUser(ctx http_service.IHttpContext) (*application.UserInfo, bool) {

	token, has := application.GetToken(ctx, "x-moon-ak", "query")
	if !has || token == "" {
		log.Error("no token")
		return nil, false
	}
	url := ctx.Request().URI().RawURL()
	if a.UserCount() <= 0 {
		log.Error("moon service not configured")
		return nil, false
	}
	user, has := a.users.Get("moon")
	if has {
		client := resty.New()

		body := new(CheckGetRequest)
		body.Url = base64.EncodeString(url)
		body.SignMethod = user.Position
		result := new(CheckSignResult)
		response, err := client.SetHostURL(user.Value).R().
			SetBody(body).
			Post("/api/v1/moon/checkGet")
		if err != nil {
			log.Error("moon service request failed")
			return nil, false
		}
		if response.IsSuccess() {
			bs := response.Body()
			err := json.Unmarshal(bs, result)
			if err != nil {
				log.Error("moon service request failed: unmarshal failed")
				return nil, false
			}
			if result.Data {
				return user, true
			} else {
				log.Errorf("moon service return: code: %d msg: %s", result.Code, result.Msg)
				return nil, false
			}
		} else {
			log.Errorf("moon service request failed: statusCode: %d", response.StatusCode())
			return nil, false
		}

	}
	log.Error("no user: moon")
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
			Name:     v.Username(),
			Value:    v.Pattern.ServiceUrl,
			Position: v.Pattern.SignMethod,
			App:      app,
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
