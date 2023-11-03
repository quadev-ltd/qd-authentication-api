package grpcserver

// Error is an error that occurs in the gRPC server layer
type Error struct {
	Message string
}

// Error returns the error message
func (e *Error) Error() string {
	return e.Message
}
