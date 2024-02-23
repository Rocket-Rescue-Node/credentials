package credentials

import "errors"

type Error error

var (
	MismatchError      = errors.New("credential MAC mismatch")
	MemoryError        = errors.New("memory allocation error")
	SerializationError = errors.New("error serializing HMAC protobuf body")
)
