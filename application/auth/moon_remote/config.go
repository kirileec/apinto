package moon_remote

type Config struct {
	Users []*User `json:"users" label:"Moon列表"`
}

type User struct {
	Pattern Pattern `json:"pattern" label:"Moon信息"`
}

type Pattern struct {
	UserName   string `json:"userName" label:"名称"`
	ServiceUrl string `json:"serviceUrl" label:"服务地址"`
	SignMethod string `json:"signMethod" label:"签名方式" enum:"sha256,md5"`
}

func (u *User) Username() string {
	return u.Pattern.UserName
}
