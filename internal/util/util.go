package util

import (
	"time"

	"github.com/golang/protobuf/ptypes/timestamp"
)

func ConvertToTimestamp(t time.Time) *timestamp.Timestamp {
	return &timestamp.Timestamp{
		Seconds: t.Unix(),
		Nanos:   int32(t.Nanosecond()),
	}
}
