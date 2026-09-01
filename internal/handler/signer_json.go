// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"reflect"
	"strings"
	"unicode/utf8"
)

const maxSignerJSONBody = 1 << 20

// decodeSignerJSON gives public legal-response bodies one unambiguous
// interpretation: exactly one JSON value, no duplicate object keys, and no
// unknown typed fields. This prevents different parsers or evidence readers
// from disagreeing about which submitted value controlled the mutation.
func decodeSignerJSON(r *http.Request, dst any) error {
	raw, err := io.ReadAll(http.MaxBytesReader(nil, r.Body, maxSignerJSONBody))
	if err != nil {
		return err
	}
	if err := validateUniqueJSONObject(raw); err != nil {
		return err
	}
	if err := validateExactJSONFieldNames(raw, dst); err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return err
	}
	if err := requireJSONEOF(dec); err != nil {
		return err
	}
	return nil
}

// validateExactJSONFieldNames closes a subtle gap in encoding/json's
// DisallowUnknownFields mode: struct fields are matched case-insensitively, so
// `REASON` is otherwise accepted as `reason`, and `reason` plus `REASON` gets a
// last-value-wins interpretation even after an exact duplicate-name scan. The
// legal-response and automation boundaries require the spelling in each JSON
// tag exactly. Maps deliberately retain arbitrary member names and recursively
// validate only their value type.
func validateExactJSONFieldNames(raw []byte, dst any) error {
	if dst == nil {
		return errors.New("JSON destination is required")
	}
	var value any
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&value); err != nil {
		return err
	}
	target := reflect.TypeOf(dst)
	for target.Kind() == reflect.Pointer {
		target = target.Elem()
	}
	return validateExactJSONValue(value, target)
}

func validateExactJSONValue(value any, target reflect.Type) error {
	for target.Kind() == reflect.Pointer {
		if value == nil {
			return nil
		}
		target = target.Elem()
	}

	switch target.Kind() {
	case reflect.Struct:
		object, ok := value.(map[string]any)
		if !ok {
			return nil // The typed decoder reports the shape/type error.
		}
		fields := exactJSONStructFields(target)
		for name, child := range object {
			fieldType, exists := fields[name]
			if !exists {
				// Member names are attacker-controlled and these parser errors are
				// returned by public endpoints. Keep the response bounded and avoid
				// reflecting arbitrary input into logs or clients.
				return errors.New("unknown or incorrectly cased JSON field")
			}
			if err := validateExactJSONValue(child, fieldType); err != nil {
				return err
			}
		}
	case reflect.Map:
		object, ok := value.(map[string]any)
		if !ok {
			return nil
		}
		for _, child := range object {
			if err := validateExactJSONValue(child, target.Elem()); err != nil {
				return err
			}
		}
	case reflect.Slice, reflect.Array:
		array, ok := value.([]any)
		if !ok {
			return nil
		}
		for _, child := range array {
			if err := validateExactJSONValue(child, target.Elem()); err != nil {
				return err
			}
		}
	}
	return nil
}

func exactJSONStructFields(target reflect.Type) map[string]reflect.Type {
	fields := make(map[string]reflect.Type)
	for index := 0; index < target.NumField(); index++ {
		field := target.Field(index)
		if field.PkgPath != "" { // unexported
			continue
		}
		tag, tagged := field.Tag.Lookup("json")
		name := ""
		if tagged {
			name = strings.Split(tag, ",")[0]
			if name == "-" {
				continue
			}
		}
		if field.Anonymous && name == "" {
			embedded := field.Type
			for embedded.Kind() == reflect.Pointer {
				embedded = embedded.Elem()
			}
			if embedded.Kind() == reflect.Struct {
				for embeddedName, embeddedType := range exactJSONStructFields(embedded) {
					fields[embeddedName] = embeddedType
				}
				continue
			}
		}
		if name == "" {
			name = field.Name
		}
		fields[name] = field.Type
	}
	return fields
}

func validateUniqueJSONObject(raw []byte) error {
	if !utf8.Valid(raw) {
		return errors.New("request body must be valid UTF-8 JSON")
	}
	if err := validateJSONStringSurrogates(raw); err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	token, err := dec.Token()
	if err != nil {
		return err
	}
	delim, ok := token.(json.Delim)
	if !ok || delim != '{' {
		return errors.New("request body must be a JSON object")
	}
	if err := walkJSONObject(dec); err != nil {
		return err
	}
	if err := requireJSONEOF(dec); err != nil {
		return err
	}
	return nil
}

// validateJSONStringSurrogates prevents encoding/json from silently replacing
// an unpaired escaped UTF-16 surrogate with U+FFFD. That canonicalization is
// unsafe at an idempotent legal-command boundary because the persisted text no
// longer matches the caller's signed/request bytes.
func validateJSONStringSurrogates(raw []byte) error {
	inString := false
	for index := 0; index < len(raw); index++ {
		switch {
		case !inString && raw[index] == '"':
			inString = true
		case !inString:
			continue
		case raw[index] == '"':
			inString = false
		case raw[index] == '\\':
			if index+1 >= len(raw) {
				continue
			}
			if raw[index+1] != 'u' {
				index++
				continue
			}
			code, ok := decodeJSONHexQuad(raw, index+2)
			if !ok {
				return errors.New("invalid JSON Unicode escape")
			}
			index += 5
			switch {
			case code >= 0xd800 && code <= 0xdbff:
				pairStart := index + 1
				if pairStart+5 >= len(raw) || raw[pairStart] != '\\' || raw[pairStart+1] != 'u' {
					return errors.New("JSON strings must contain paired Unicode surrogate escapes")
				}
				low, valid := decodeJSONHexQuad(raw, pairStart+2)
				if !valid || low < 0xdc00 || low > 0xdfff {
					return errors.New("JSON strings must contain paired Unicode surrogate escapes")
				}
				index = pairStart + 5
			case code >= 0xdc00 && code <= 0xdfff:
				return errors.New("JSON strings must contain paired Unicode surrogate escapes")
			}
		}
	}
	return nil
}

func decodeJSONHexQuad(raw []byte, start int) (uint16, bool) {
	if start < 0 || start+4 > len(raw) {
		return 0, false
	}
	var value uint16
	for _, encoded := range raw[start : start+4] {
		value <<= 4
		switch {
		case encoded >= '0' && encoded <= '9':
			value |= uint16(encoded - '0')
		case encoded >= 'a' && encoded <= 'f':
			value |= uint16(encoded-'a') + 10
		case encoded >= 'A' && encoded <= 'F':
			value |= uint16(encoded-'A') + 10
		default:
			return 0, false
		}
	}
	return value, true
}

func walkJSONObject(dec *json.Decoder) error {
	seen := make(map[string]struct{})
	for dec.More() {
		token, err := dec.Token()
		if err != nil {
			return err
		}
		key, ok := token.(string)
		if !ok {
			return errors.New("JSON object key must be a string")
		}
		if _, duplicate := seen[key]; duplicate {
			return errors.New("duplicate JSON field")
		}
		seen[key] = struct{}{}
		if err := walkJSONValue(dec); err != nil {
			return err
		}
	}
	closing, err := dec.Token()
	if err != nil {
		return err
	}
	if closing != json.Delim('}') {
		return errors.New("invalid JSON object")
	}
	return nil
}

func walkJSONValue(dec *json.Decoder) error {
	token, err := dec.Token()
	if err != nil {
		return err
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		return walkJSONObject(dec)
	case '[':
		for dec.More() {
			if err := walkJSONValue(dec); err != nil {
				return err
			}
		}
		closing, err := dec.Token()
		if err != nil {
			return err
		}
		if closing != json.Delim(']') {
			return errors.New("invalid JSON array")
		}
		return nil
	default:
		return errors.New("invalid JSON delimiter")
	}
}

func requireJSONEOF(dec *json.Decoder) error {
	var trailing any
	err := dec.Decode(&trailing)
	if errors.Is(err, io.EOF) {
		return nil
	}
	if err != nil {
		return err
	}
	return errors.New("request body must contain exactly one JSON object")
}
