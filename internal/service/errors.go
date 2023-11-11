package service

// Error is the error type for the service
type Error struct {
	Message string
}

// Error returns the error message
func (e *Error) Error() string {
	return e.Message
}

// NoComplexPasswordError is the error type for the service
type NoComplexPasswordError struct {
	Message string
}

// NoComplexPasswordError returns the error message
func (e *NoComplexPasswordError) Error() string {
	return e.Message
}

// SendEmailError is the error type for the service
type SendEmailError struct {
	Message string
}

// SendEmailError returns the error message
func (e *SendEmailError) Error() string {
	return e.Message
}
