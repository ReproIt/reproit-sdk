package reproit

import (
	"bytes"
	"encoding/json"
	"io"
	"strconv"
	"unicode/utf8"
)

const maxStrictJSONDepth = 512

func parseStrictJSON(value []byte, maximumBytes int) (any, error) {
	if len(value) > maximumBytes || !utf8.Valid(value) {
		return nil, errSchemaInvalid()
	}
	decoder := json.NewDecoder(bytes.NewReader(value))
	decoder.UseNumber()
	parsed, err := decodeStrictValue(decoder, 0)
	if err != nil {
		return nil, errSchemaInvalid()
	}
	if _, err := decoder.Token(); err != io.EOF {
		return nil, errSchemaInvalid()
	}
	return parsed, nil
}

func decodeStrictValue(decoder *json.Decoder, depth int) (any, error) {
	if depth > maxStrictJSONDepth {
		return nil, errSchemaInvalid()
	}
	token, err := decoder.Token()
	if err != nil {
		return nil, errSchemaInvalid()
	}
	return decodeStrictToken(decoder, token, depth)
}

func decodeStrictToken(decoder *json.Decoder, token json.Token, depth int) (any, error) {
	delimiter, isDelimiter := token.(json.Delim)
	if !isDelimiter {
		return token, nil
	}
	switch delimiter {
	case '{':
		object := make(map[string]any)
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return nil, errSchemaInvalid()
			}
			key, ok := keyToken.(string)
			if !ok {
				return nil, errSchemaInvalid()
			}
			if _, duplicate := object[key]; duplicate {
				return nil, errSchemaInvalid()
			}
			entry, err := decodeStrictValue(decoder, depth+1)
			if err != nil {
				return nil, err
			}
			object[key] = entry
		}
		if _, err := decoder.Token(); err != nil {
			return nil, errSchemaInvalid()
		}
		return object, nil
	case '[':
		values := make([]any, 0)
		for decoder.More() {
			entry, err := decodeStrictValue(decoder, depth+1)
			if err != nil {
				return nil, err
			}
			values = append(values, entry)
		}
		if _, err := decoder.Token(); err != nil {
			return nil, errSchemaInvalid()
		}
		return values, nil
	default:
		return nil, errSchemaInvalid()
	}
}

func hasExactKeys(value map[string]any, keys ...string) bool {
	if len(value) != len(keys) {
		return false
	}
	for _, key := range keys {
		if _, present := value[key]; !present {
			return false
		}
	}
	return true
}

func anyList(value any) ([]any, bool) {
	values, ok := value.([]any)
	return values, ok
}

func integerValue(value any) (int64, bool) {
	switch number := value.(type) {
	case int:
		return int64(number), true
	case int64:
		return number, true
	case json.Number:
		parsed, err := number.Int64()
		return parsed, err == nil && strconv.FormatInt(parsed, 10) == number.String()
	default:
		return 0, false
	}
}
