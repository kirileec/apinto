package moon

type Config struct {
	Users []*User `json:"users" label:"Moon列表"`
}

type User struct {
	Pattern Pattern `json:"pattern" label:"Moon信息"`
}

type Pattern struct {
	AppName    string `json:"appName" label:"AppName"`
	AK         string `json:"ak" label:"AK"`
	SK         string `json:"sk" label:"SK"`
	SignMethod string `json:"signMethod" label:"SignMethod" enum:"sha256,md5"`
}

func (u *User) Username() string {
	return u.Pattern.AK
}
