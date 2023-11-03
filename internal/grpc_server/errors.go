package grpc_server

type GRPCServerError struct {
	Message string
}

func (e *GRPCServerError) Error() string {
	return e.Message
}
