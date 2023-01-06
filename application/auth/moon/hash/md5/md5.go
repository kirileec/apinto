package md5

import (
	"crypto/md5"
	"fmt"
	"io"
)

func Md5(origin string) string {
	w := md5.New()
	io.WriteString(w, origin)
	return fmt.Sprintf("%x", w.Sum(nil))
}
