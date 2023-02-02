package moon

import (
	"fmt"
	"github.com/eolinker/apinto/application/auth/moon/datetime"
	"github.com/eolinker/apinto/application/auth/moon/kerror"
	"github.com/eolinker/apinto/application/auth/moon/query_sort"
	"github.com/eolinker/apinto/application/auth/moon/sign"
	"github.com/eolinker/eosc/log"
	"github.com/linxlib/conv"
	"github.com/pkg/errors"
	"net/url"
	"regexp"
	"strings"
	"time"
)

const (
	ErrUnSupportHashMethod kerror.Err = iota + 1001
	ErrDecodeBase64Url
	ErrParseUrl
	ErrParseQueryParam
	ErrNotValidAK
	ErrNoAKField
	ErrNoTimestampField
	ErrTimestampFormat
	ErrRequestExpired
	ErrCheckSign
	ErrExpireParam
	ErrNoAccess
	ErrDecodeBase64Body
	ErrMissingSignField
)

func init() {
	kerror.AddErr(ErrUnSupportHashMethod, "not supported hash method")
	kerror.AddErr(ErrDecodeBase64Url, "decode base64 url failed")
	kerror.AddErr(ErrParseUrl, "parse original url failed")
	kerror.AddErr(ErrParseQueryParam, "parse query param failed")
	kerror.AddErr(ErrNotValidAK, "App Key is not valid")
	kerror.AddErr(ErrNoAKField, "App Key field not exist")
	kerror.AddErr(ErrNoTimestampField, "Timestamp field not exist")
	kerror.AddErr(ErrTimestampFormat, "timestamp should be unix int (seconds)")
	kerror.AddErr(ErrRequestExpired, "request expired")
	kerror.AddErr(ErrCheckSign, "check sign failed")
	kerror.AddErr(ErrExpireParam, "param x-moon-expires not exist")
	kerror.AddErr(ErrNoAccess, "you cant sign/verify now")
	kerror.AddErr(ErrDecodeBase64Body, "decode base64 body failed")
	kerror.AddErr(ErrMissingSignField, "missing x-moon-sign field in url")
}

// SignVerify 验签加签
type SignVerify struct {
	method         string
	url            string
	signField      string
	timestampField string
	akField        string
	expireField    string
	ak             string
	sk             string
	expire         int64
}

func NewSignVerify() *SignVerify {
	return &SignVerify{
		signField:      "x-moon-sign",
		timestampField: "x-moon-timestamp",
		akField:        "x-moon-ak",
		expireField:    "x-moon-expires",
		method:         "sha256",
	}
}

// PureHash 使用特定hash算法计算哈希
//
//	@param hashMethod
//	@param src
//
//	@return string
//	@return error
func (sv *SignVerify) PureHash(hashMethod string, src string) (string, error) {
	signer, err := sign.SignProvider.Get(hashMethod)
	if err != nil {
		log.Error(err)
		return "", ErrUnSupportHashMethod.WithError(err)
	}
	return signer.Sign(src), nil
}

func (sv *SignVerify) Begin(url string, method string, ak string, sk string) *SignVerify {

	if method == "" {
		method = "sha256"
	}
	sv.expire = 30
	sv.ak = ak
	sv.method = method
	sv.url = url
	sv.sk = sk
	return sv
}

type SignResult struct {
	ak string

	Signed     string `json:"signed"`    //已签名结果
	MySign     string `json:"-"`         //由url中获取的签名值
	Sign       string `json:"sign"`      //签名值
	Timestamp  string `json:"timestamp"` //时间戳字符串
	Expire     string `json:"expire"`    //过期时间字符串（秒）
	OriginType string `json:"originType,omitempty"`
}

func (sr SignResult) CheckSign() error {
	if sr.Sign != sr.MySign {
		return ErrCheckSign
	}
	return nil
}

var urlRegex = regexp.MustCompile(`(?P<path>(/|^)[a-zA-Z\d-_/]*)/?([?&])(?P<query>.*)`)

// parseUrlOrQuery 解析原始url为 *url.URL
//
//	@param originUrl 原始url，可能为各种奇怪的样子，参考单元测试代码
//
//	@return bool true:不是完整的url false: 完整且标准的url
//	@return *url.URL 可用参数为 Path和RawQuery，RawPath可能为空
//	@return error
func (sv *SignVerify) parseUrlOrQuery(originUrl string) (bool, *url.URL, error) {
	var u = new(url.URL)
	hasQuestionMark := strings.HasPrefix(originUrl, "?")
	if !strings.Contains(originUrl, "http://") && !strings.Contains(originUrl, "https://") {
		match := urlRegex.FindStringSubmatch(originUrl)
		if match == nil { //处理特殊情况
			parse, err := url.Parse(originUrl)
			if err != nil {
				return hasQuestionMark, nil, errors.Wrap(err, originUrl)
			}
			if parse.RawQuery == "" && len(parse.Query()) <= 0 {
				q, err := url.ParseQuery(originUrl)
				if err != nil {
					return hasQuestionMark, nil, errors.Wrap(err, originUrl)
				}
				if len(q) <= 0 || q.Has(originUrl) { // example.com/path 这种url解析后 url整体就是key
					return hasQuestionMark, nil, fmt.Errorf("not contains query: %s", originUrl)
				}
				u.Path = ""
				u.RawQuery = q.Encode()
				u.RawPath = ""

				return hasQuestionMark, u, nil
			}
			return hasQuestionMark, nil, fmt.Errorf("parse url other err: %s", originUrl)
		}
		indexPath := urlRegex.SubexpIndex("path")
		path := ""
		if match != nil && indexPath > -1 {
			path = match[indexPath]
		}

		indexQuery := urlRegex.SubexpIndex("query")
		query := ""
		if match != nil && indexQuery > -1 {
			query = match[indexQuery]
		}

		//url.Parse时 Path有值 RawPath为空
		//这样是为兼容下方的情况
		u.Path = path
		u.RawQuery = query
		u.RawPath = path
		return hasQuestionMark, u, nil
	}
	var err error

	u, err = url.Parse(originUrl)
	if err != nil {
		log.Error(err)
		return hasQuestionMark, u, errors.Wrap(err, originUrl)
	}
	return hasQuestionMark, u, nil

}

// GetSign 获取签名
//
//	@param checkTimestamp 是否检查url中的时间戳字段
//
//	@return *SignResult
//	@return error
func (sv *SignVerify) GetSign(checkTimestamp bool) (*SignResult, error) {
	signer, err := sign.SignProvider.Get(sv.method)
	if err != nil {
		log.Error(err)
		return nil, ErrUnSupportHashMethod.WithError(err)
	}
	originType := "GET"
	_, u, err := sv.parseUrlOrQuery(sv.url)
	if err != nil {
		log.Error(err)
		return nil, ErrParseUrl.WithError(err)
	}
	// 解析query部分
	urlValues, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		log.Error(err)
		return nil, ErrParseQueryParam.WithError(err)
	}

	ak := urlValues.Get(sv.akField)
	if ak == "" {
		return nil, ErrNoAKField
	}

	expire := urlValues.Get(sv.expireField)
	if expire == "" {
		if checkTimestamp {
			log.Error(ErrExpireParam)
			return nil, ErrExpireParam
		}
		expire = conv.String(sv.expire)
		urlValues.Set(sv.expireField, expire)
	}

	t := urlValues.Get(sv.timestampField)
	if t == "" {
		if checkTimestamp {
			log.Error(ErrNoTimestampField)
			return nil, ErrNoTimestampField
		}
		t = datetime.NowUnixString()
		urlValues.Set(sv.timestampField, t)
	} else {
		if len(t) != 10 {
			log.Error(ErrTimestampFormat)
			return nil, ErrTimestampFormat
		}

		if time.Now().Unix()-conv.Int64(t) > conv.Int64(expire) {
			log.Error(ErrRequestExpired)
			return nil, ErrRequestExpired
		}
	}

	mysign := ""
	signed := ""
	if s := urlValues.Get(sv.signField); s != "" {
		mysign = s
		urlValues.Del(sv.signField)
	}

	if s := urlValues.Get("x-moon-signmethod"); s != "" && s != "null" {
		//mysign = s
		urlValues.Del("x-moon-signmethod")
	}
	sk := sv.sk
	toSign := sk + query_sort.UrlQueryToSortedKVString(urlValues) + sk
	signed = signer.Sign(toSign)
	urlValues.Set(sv.signField, signed)
	query := query_sort.UrlQueryToEscapeKVString(urlValues)

	u.RawQuery = query
	return &SignResult{
		ak:         ak,
		MySign:     mysign,
		Sign:       signed,
		Timestamp:  t,
		OriginType: originType,
		Expire:     conv.String(expire),
	}, nil

}

// Verify 验签
//
//	@return error
func (sv *SignVerify) Verify() error {
	a, err := sv.GetSign(true)
	if err != nil {
		log.Error(err)
		return err
	}
	err = a.CheckSign()
	if err != nil {
		log.Error(err)
		return err
	}
	return nil
}
