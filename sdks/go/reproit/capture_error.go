package reproit

// ManagedError reports a local capture failure with a stable code.
type ManagedError struct {
	Code    string
	Message string
}

func (captureError *ManagedError) Error() string {
	return captureError.Message
}

func newManagedError(code, message string) *ManagedError {
	return &ManagedError{Code: code, Message: message}
}

func errSchemaInvalid() *ManagedError {
	return newManagedError("SCHEMA_INVALID", "The value does not satisfy the schema.")
}
