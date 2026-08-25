package reproit

import (
	"bytes"
	"crypto/sha256"
	"fmt"
)

func canonicalEqual(left, right any) (bool, error) {
	leftBytes, err := CanonicalBytes(left)
	if err != nil {
		return false, err
	}
	rightBytes, err := CanonicalBytes(right)
	return bytes.Equal(leftBytes, rightBytes), err
}

func digestValue(value any) string {
	encoded, err := CanonicalBytes(value)
	if err != nil {
		return ""
	}
	return digestBytes(encoded)
}

func digestBytes(value []byte) string {
	return fmt.Sprintf("sha256:%x", sha256.Sum256(value))
}

func canonicalDigest(value any) (string, error) {
	encoded, err := CanonicalBytes(value)
	if err != nil {
		return "", errSchemaInvalid()
	}
	return digestBytes(encoded), nil
}
