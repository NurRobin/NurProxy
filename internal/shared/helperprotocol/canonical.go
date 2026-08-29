package helperprotocol

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"reflect"
	"strconv"
	"strings"
	"unicode/utf8"
)

const (
	MaxFrameBytes    = 4 << 20
	MaxStringBytes   = 4 << 20
	MaxArrayElements = 4096
	MaxObjectFields  = 256
	MaxNestingDepth  = 32
)

func Decode[T any](data []byte) (T, error) {
	var zero T
	if len(data) == 0 || len(data) > MaxFrameBytes || !utf8.Valid(data) {
		return zero, fmt.Errorf("invalid protocol payload size or UTF-8")
	}
	if err := validateJSONStringEscapes(data); err != nil {
		return zero, err
	}
	if err := preflightJSON(data); err != nil {
		return zero, err
	}
	raw, err := decodeUntyped(data)
	if err != nil {
		return zero, err
	}
	if err := validateExactShape(raw, reflect.TypeOf(zero)); err != nil {
		return zero, err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	decoder.UseNumber()
	var out T
	if err := decoder.Decode(&out); err != nil {
		return zero, fmt.Errorf("decode protocol payload: %w", err)
	}
	if err := ensureJSONEOF(decoder); err != nil {
		return zero, err
	}
	if err := validateValue(out); err != nil {
		return zero, err
	}
	return out, nil
}

func DecodeEnvelope[T any](data []byte, expected MessageType) (Envelope[T], error) {
	envelope, err := Decode[Envelope[T]](data)
	if err != nil {
		return Envelope[T]{}, err
	}
	if !expected.Valid() || envelope.MessageType != expected {
		return Envelope[T]{}, fmt.Errorf("protocol message type does not match payload schema")
	}
	return envelope, nil
}

func CanonicalBytes(value any) ([]byte, error) {
	if err := validateValue(value); err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, fmt.Errorf("marshal canonical value: %w", err)
	}
	if len(encoded) > MaxFrameBytes || !utf8.Valid(encoded) {
		return nil, fmt.Errorf("canonical value exceeds protocol bounds")
	}
	if err := preflightJSON(encoded); err != nil {
		return nil, err
	}
	raw, err := decodeUntyped(encoded)
	if err != nil {
		return nil, err
	}
	canonical, err := json.Marshal(raw)
	if err != nil {
		return nil, fmt.Errorf("marshal canonical representation: %w", err)
	}
	return canonical, nil
}

func Digest(value any) (string, error) {
	canonical, err := CanonicalBytes(value)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(canonical)
	return hex.EncodeToString(digest[:]), nil
}

func decodeUntyped(data []byte) (any, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var raw any
	if err := decoder.Decode(&raw); err != nil {
		return nil, fmt.Errorf("decode protocol JSON: %w", err)
	}
	if err := ensureJSONEOF(decoder); err != nil {
		return nil, err
	}
	return raw, nil
}

func ensureJSONEOF(decoder *json.Decoder) error {
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return fmt.Errorf("trailing protocol value")
		}
		return fmt.Errorf("invalid trailing protocol data: %w", err)
	}
	return nil
}

func preflightJSON(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := scanJSONValue(decoder, 0); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		if err == nil {
			return fmt.Errorf("trailing protocol value")
		}
		return fmt.Errorf("invalid trailing protocol data: %w", err)
	}
	return nil
}

func scanJSONValue(decoder *json.Decoder, depth int) error {
	if depth > MaxNestingDepth {
		return fmt.Errorf("protocol JSON nesting exceeds limit")
	}
	token, err := decoder.Token()
	if err != nil {
		return fmt.Errorf("invalid protocol JSON: %w", err)
	}
	switch value := token.(type) {
	case json.Delim:
		switch value {
		case '{':
			keys := make(map[string]struct{})
			for decoder.More() {
				if len(keys) >= MaxObjectFields {
					return fmt.Errorf("protocol object exceeds field limit")
				}
				keyToken, keyErr := decoder.Token()
				if keyErr != nil {
					return fmt.Errorf("read protocol object key: %w", keyErr)
				}
				key, ok := keyToken.(string)
				if !ok || len(key) > MaxStringBytes {
					return fmt.Errorf("invalid protocol object key")
				}
				if _, duplicate := keys[key]; duplicate {
					return fmt.Errorf("duplicate protocol object key %q", key)
				}
				keys[key] = struct{}{}
				if err := scanJSONValue(decoder, depth+1); err != nil {
					return err
				}
			}
			end, endErr := decoder.Token()
			if endErr != nil || end != json.Delim('}') {
				return fmt.Errorf("unterminated protocol object")
			}
		case '[':
			count := 0
			for decoder.More() {
				count++
				if count > MaxArrayElements {
					return fmt.Errorf("protocol array exceeds element limit")
				}
				if err := scanJSONValue(decoder, depth+1); err != nil {
					return err
				}
			}
			end, endErr := decoder.Token()
			if endErr != nil || end != json.Delim(']') {
				return fmt.Errorf("unterminated protocol array")
			}
		default:
			return fmt.Errorf("unexpected protocol delimiter")
		}
	case string:
		if len(value) > MaxStringBytes {
			return fmt.Errorf("protocol string exceeds limit")
		}
	case json.Number:
		text := value.String()
		if !canonicalInteger(text) {
			return fmt.Errorf("protocol numbers must be canonical signed integers")
		}
		if _, err := strconv.ParseInt(text, 10, 64); err != nil {
			return fmt.Errorf("protocol integer outside range")
		}
	case bool, nil:
	default:
		return fmt.Errorf("unsupported protocol JSON value")
	}
	return nil
}

func canonicalInteger(value string) bool {
	if value == "0" {
		return true
	}
	if strings.HasPrefix(value, "-") {
		value = strings.TrimPrefix(value, "-")
		if value == "0" {
			return false
		}
	}
	if value == "" || value[0] < '1' || value[0] > '9' {
		return false
	}
	for i := 1; i < len(value); i++ {
		if value[i] < '0' || value[i] > '9' {
			return false
		}
	}
	return true
}

func validateJSONStringEscapes(data []byte) error {
	for i := 0; i < len(data); i++ {
		if data[i] != '"' {
			continue
		}
		i++
		for ; i < len(data); i++ {
			switch data[i] {
			case '"':
				goto nextString
			case '\\':
				i++
				if i >= len(data) {
					return fmt.Errorf("unterminated protocol string escape")
				}
				switch data[i] {
				case '"', '\\', '/', 'b', 'f', 'n', 'r', 't':
				case 'u':
					unit, end, err := parseUTF16Unit(data, i+1)
					if err != nil {
						return err
					}
					i = end - 1
					if unit >= 0xd800 && unit <= 0xdbff {
						if end+2 > len(data) || data[end] != '\\' || data[end+1] != 'u' {
							return fmt.Errorf("unpaired high surrogate in protocol string")
						}
						low, lowEnd, lowErr := parseUTF16Unit(data, end+2)
						if lowErr != nil || low < 0xdc00 || low > 0xdfff {
							return fmt.Errorf("invalid low surrogate in protocol string")
						}
						i = lowEnd - 1
					} else if unit >= 0xdc00 && unit <= 0xdfff {
						return fmt.Errorf("unpaired low surrogate in protocol string")
					}
				default:
					return fmt.Errorf("invalid protocol string escape")
				}
			default:
				if data[i] < 0x20 {
					return fmt.Errorf("control character in protocol string")
				}
			}
		}
		return fmt.Errorf("unterminated protocol string")
	nextString:
	}
	return nil
}

func parseUTF16Unit(data []byte, start int) (uint16, int, error) {
	if start+4 > len(data) {
		return 0, start, fmt.Errorf("short unicode escape in protocol string")
	}
	value, err := strconv.ParseUint(string(data[start:start+4]), 16, 16)
	if err != nil {
		return 0, start, fmt.Errorf("invalid unicode escape in protocol string")
	}
	return uint16(value), start + 4, nil
}

func validateExactShape(value any, target reflect.Type) error {
	for target != nil && target.Kind() == reflect.Pointer {
		target = target.Elem()
	}
	if target == nil || target.Kind() == reflect.Interface {
		return nil
	}
	switch target.Kind() {
	case reflect.Struct:
		object, ok := value.(map[string]any)
		if !ok {
			return fmt.Errorf("protocol value does not match object schema")
		}
		fields := make(map[string]reflect.Type)
		for i := 0; i < target.NumField(); i++ {
			field := target.Field(i)
			if field.PkgPath != "" {
				continue
			}
			name := strings.Split(field.Tag.Get("json"), ",")[0]
			if name == "-" {
				continue
			}
			if name == "" {
				name = field.Name
			}
			fields[name] = field.Type
		}
		for key, child := range object {
			fieldType, exists := fields[key]
			if !exists {
				return fmt.Errorf("unknown or case-variant protocol field %q", key)
			}
			if err := validateExactShape(child, fieldType); err != nil {
				return err
			}
		}
	case reflect.Slice, reflect.Array:
		array, ok := value.([]any)
		if !ok {
			return fmt.Errorf("protocol value does not match array schema")
		}
		for _, child := range array {
			if err := validateExactShape(child, target.Elem()); err != nil {
				return err
			}
		}
	case reflect.Map:
		object, ok := value.(map[string]any)
		if !ok || target.Key().Kind() != reflect.String {
			return fmt.Errorf("protocol value does not match map schema")
		}
		for _, child := range object {
			if err := validateExactShape(child, target.Elem()); err != nil {
				return err
			}
		}
	}
	return nil
}
