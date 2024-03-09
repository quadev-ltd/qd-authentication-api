package util

import "time"

// TimeProvider is an interface for getting the current time
type TimeProvider interface {
	Now() time.Time
}

// RealTimeProvider is the default time provider
type RealTimeProvider struct{}

// Now returns the current time
func (rtp RealTimeProvider) Now() time.Time {
	return time.Now()
}

// MockedTime is a fixed time for testing
var MockedTime = time.Date(2022, 01, 01, 10, 0, 0, 0, time.UTC)

// MockTimeProvider could be used in tests
type MockTimeProvider struct {
	MockNow time.Time
}

// Now returns the mocked time
func (mtp MockTimeProvider) Now() time.Time {
	return MockedTime
}
