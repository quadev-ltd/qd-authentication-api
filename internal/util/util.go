package util

import (
	"time"

	"github.com/golang/protobuf/ptypes/timestamp"
)

// ConvertToTimestamp converts a time.Time to a timestamp.Timestamp
func ConvertToTimestamp(t time.Time) *timestamp.Timestamp {
	return &timestamp.Timestamp{
		Seconds: t.Unix(),
		Nanos:   int32(t.Nanosecond()),
	}
}
