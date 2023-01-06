package datetime

import (
	"fmt"
	"time"
)

func UnixToTime(unix int64) time.Time {
	return time.Unix(unix, 0)
}

func NowUnixString() string {
	return fmt.Sprintf("%d", time.Now().Unix())
}
