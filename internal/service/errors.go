package service

// Error is the error type for the service
type Error struct {
	Message string
}

// Error returns the error message
func (e *Error) Error() string {
	return e.Message
}
