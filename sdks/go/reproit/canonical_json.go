package reproit

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// CanonicalBytes encodes the bounded SDK bridge value as canonical JSON.
func CanonicalBytes(value any) ([]byte, error) {
	var output bytes.Buffer
	if err := encodeCanonical(&output, value); err != nil {
		return nil, err
	}
	return output.Bytes(), nil
}

func encodeCanonical(output *bytes.Buffer, value any) error {
	switch typed := value.(type) {
	case nil:
		output.WriteString("null")
	case bool:
		output.WriteString(strconv.FormatBool(typed))
	case string:
		encoded, _ := json.Marshal(typed)
		text := string(encoded)
		text = strings.ReplaceAll(text, `\u003c`, "<")
		text = strings.ReplaceAll(text, `\u003e`, ">")
		text = strings.ReplaceAll(text, `\u0026`, "&")
		text = strings.ReplaceAll(text, `\u2028`, " ")
		text = strings.ReplaceAll(text, `\u2029`, " ")
		output.WriteString(text)
	case json.Number:
		parsed, err := typed.Int64()
		if err != nil || strconv.FormatInt(parsed, 10) != typed.String() {
			return errors.New("The protocol value contains a non-canonical integer.")
		}
		output.WriteString(typed.String())
	case int:
		output.WriteString(strconv.Itoa(typed))
	case int64:
		output.WriteString(strconv.FormatInt(typed, 10))
	case float64:
		return errors.New("The protocol value contains a floating-point number.")
	case []any:
		output.WriteByte('[')
		for index, element := range typed {
			if index > 0 {
				output.WriteByte(',')
			}
			if err := encodeCanonical(output, element); err != nil {
				return err
			}
		}
		output.WriteByte(']')
	case []map[string]any:
		values := make([]any, len(typed))
		for index := range typed {
			values[index] = typed[index]
		}
		return encodeCanonical(output, values)
	case map[string]any:
		keys := make([]string, 0, len(typed))
		for key := range typed {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		output.WriteByte('{')
		for index, key := range keys {
			if index > 0 {
				output.WriteByte(',')
			}
			if err := encodeCanonical(output, key); err != nil {
				return err
			}
			output.WriteByte(':')
			if err := encodeCanonical(output, typed[key]); err != nil {
				return err
			}
		}
		output.WriteByte('}')
	default:
		return fmt.Errorf("The protocol value has unsupported type %T.", value)
	}
	return nil
}
