package reproit

import "strings"

func validCapability(value any) bool {
	text, ok := value.(string)
	if !ok || text == "" || len(text) > 128 || text[0] < 'a' || text[0] > 'z' {
		return false
	}
	for index := 1; index < len(text); index++ {
		character := text[index]
		if (character < 'a' || character > 'z') &&
			(character < '0' || character > '9') && character != '.' && character != '-' {
			return false
		}
	}
	return true
}

func validAdapterID(value any) bool {
	if !validBoundedString(value, 128) {
		return false
	}
	adapterID := value.(string)
	if adapterID[0] < 'a' || adapterID[0] > 'z' {
		return false
	}
	for _, character := range adapterID {
		if character < 'a' || character > 'z' {
			if character < '0' || character > '9' {
				if character != '.' && character != '-' {
					return false
				}
			}
		}
	}
	return true
}

func validOperationKind(value any) bool {
	kind, ok := value.(string)
	return ok && (kind == "request-response" || kind == "stream" || kind == "delivered-work")
}

func validBoundedString(value any, maximum int) bool {
	text, ok := value.(string)
	return ok && len(text) > 0 && len(text) <= maximum
}

func validDigest(value any) bool {
	text, ok := value.(string)
	if !ok || len(text) != 71 || !strings.HasPrefix(text, "sha256:") {
		return false
	}
	for _, character := range text[7:] {
		if character < '0' || character > '9' {
			if character < 'a' || character > 'f' {
				return false
			}
		}
	}
	return true
}

func validOperationID(value any) bool {
	return validPrefixedUUIDv7(value, "op_")
}

func validPrefixedUUIDv7(value any, prefix string) bool {
	text, ok := value.(string)
	if !ok || len(text) != len(prefix)+36 || !strings.HasPrefix(text, prefix) {
		return false
	}
	uuid := text[len(prefix):]
	for index, character := range uuid {
		switch index {
		case 8, 13, 18, 23:
			if character != '-' {
				return false
			}
		case 14:
			if character != '7' {
				return false
			}
		case 19:
			if !strings.ContainsRune("89ab", character) {
				return false
			}
		default:
			if !strings.ContainsRune("0123456789abcdef", character) {
				return false
			}
		}
	}
	return true
}
