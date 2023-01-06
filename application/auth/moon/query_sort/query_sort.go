package query_sort

import (
	"net/url"
	"sort"
)

func UrlQueryToSortedKVString(u url.Values) (str string) {
	var keys []string
	for key := range u {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, v := range keys {
		if str != "" {
			str += "&"
		}
		str += v + "=" + u.Get(v)
	}
	return
}

func UrlQueryToEscapeKVString(u url.Values) (str string) {
	for key := range u {
		if str != "" {
			str += "&"
		}
		str += key + "=" + url.QueryEscape(u.Get(key))
	}
	return
}
