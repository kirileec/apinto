package kerror

type CodeError interface {
	error
	Map() map[string]any
}

type withMessage struct {
	Err
	msg string
}

func (e withMessage) Error() string {
	return e.Err.Error() + ":" + e.msg
}

func (e withMessage) Map() map[string]any {
	return map[string]any{
		"code": int(e.Err),
		"msg":  e.Error(),
	}
}

type withError struct {
	Err
	err error
}

func (e withError) Error() string {
	return e.Err.Error() + ":" + e.err.Error()
}

func (e withError) Map() map[string]any {
	return map[string]any{
		"code": int(e.Err),
		"msg":  e.Error(),
	}
}

type Err int

const (
	SUCCESS         Err = 0
	FAIL            Err = -1
	ErrRequestParam Err = 400
	ErrUnAuth       Err = 401
	ErrNoPermission Err = 403
	ErrThirdParty   Err = 3000
	ErrDB           Err = 5000
)

var msgFlags = map[Err]string{
	SUCCESS:         "ok",
	FAIL:            "fail",
	ErrRequestParam: "req param err",
	ErrUnAuth:       "req is illegal",
	ErrNoPermission: "no permission to access",
	ErrThirdParty:   "call third party service fail",
	ErrDB:           "db action failed",
}

func AddErr(e Err, desc string) {
	if _, ok := msgFlags[e]; !ok {
		msgFlags[e] = desc
	}
}

func (e Err) WithMessage(msg string) error {
	return &withMessage{
		e, msg,
	}
}
func (e Err) WithError(err error) error {
	return &withError{
		e, err,
	}
}

func (e Err) Error() string {
	msg, ok := msgFlags[e]
	if ok {
		return msg
	}

	return msgFlags[FAIL]
}

func (e Err) Map() map[string]any {
	return map[string]any{
		"code": int(e),
		"msg":  e.Error(),
	}
}
