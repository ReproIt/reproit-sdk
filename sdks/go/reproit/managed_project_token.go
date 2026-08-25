package reproit

const managedMaxProjectTokenBytes = 1_024

// ManagedProjectToken authorizes one managed workload registration.
type ManagedProjectToken struct {
	value string
}

// NewManagedProjectToken validates and wraps one managed project token.
func NewManagedProjectToken(value string) (*ManagedProjectToken, error) {
	if value == "" || len(value) > managedMaxProjectTokenBytes {
		return nil, newManagedError("SCHEMA_INVALID", "The managed project token is invalid.")
	}
	for index := 0; index < len(value); index++ {
		if value[index] < 33 || value[index] > 126 {
			return nil, newManagedError("SCHEMA_INVALID", "The managed project token is invalid.")
		}
	}
	return &ManagedProjectToken{value: value}, nil
}

func (token *ManagedProjectToken) sdkEngineValue() string {
	if token == nil {
		return ""
	}
	return token.value
}
