package util

import (
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"
)

// ConvertToTimestamp converts a time.Time to a timestamp.Timestamp
func ConvertToTimestamp(t time.Time) *timestamppb.Timestamp {
	return &timestamppb.Timestamp{
		Seconds: t.Unix(),
		Nanos:   int32(t.Nanosecond()),
	}
}
