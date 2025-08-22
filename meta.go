package viracochan

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"time"
)

var (
	ErrChecksumMismatch = errors.New("checksum mismatch")
	ErrInvalidChain     = errors.New("invalid chain")
	ErrVersionConflict  = errors.New("version conflict")
)

// Meta holds versioning and integrity metadata for configurations
type Meta struct {
	Version   uint64    `json:"v"`
	Time      time.Time `json:"t"`
	PrevCS    string    `json:"prev_cs,omitempty"`
	CS        string    `json:"cs"`
	Signature string    `json:"sig,omitempty"`
}

// Config represents a configuration with metadata and arbitrary content
type Config struct {
	Meta    Meta            `json:"_meta"`
	Content json.RawMessage `json:"content"`
}

// computeChecksum computes SHA-256 hex checksum over canonical JSON
func computeChecksum(c *Config) (string, error) {
	tmp := *c
	tmp.Meta.CS = ""
	tmp.Meta.Signature = ""
	
	canonical, err := canonicalJSON(&tmp)
	if err != nil {
		return "", err
	}
	
	// Append timestamp to canonical bytes (following MVPChain pattern)
	ts := tmp.Meta.Time.UTC().Truncate(time.Microsecond).Format(time.RFC3339Nano)
	buf := make([]byte, 0, len(canonical)+len(ts))
	buf = append(buf, canonical...)
	buf = append(buf, []byte(ts)...)
	
	sum := sha256.Sum256(buf)
	return hex.EncodeToString(sum[:]), nil
}

// Validate recomputes checksum and verifies integrity
func (c *Config) Validate() error {
	cs, err := computeChecksum(c)
	if err != nil {
		return err
	}
	if cs != c.Meta.CS {
		return fmt.Errorf("%w: expected=%s computed=%s", ErrChecksumMismatch, c.Meta.CS, cs)
	}
	return nil
}

// NextOf checks that c is immediate successor of prev
func (c *Config) NextOf(prev *Config) error {
	if prev == nil {
		return errors.New("previous config is nil")
	}
	if c.Meta.Version != prev.Meta.Version+1 {
		return fmt.Errorf("version break: %d -> %d", prev.Meta.Version, c.Meta.Version)
	}
	if c.Meta.PrevCS != prev.Meta.CS {
		return fmt.Errorf("chain break: prev_cs=%s != cs=%s", c.Meta.PrevCS, prev.Meta.CS)
	}
	if c.Meta.Time.Before(prev.Meta.Time) {
		return fmt.Errorf("timestamp regression: %s < %s", c.Meta.Time, prev.Meta.Time)
	}
	if err := prev.Validate(); err != nil {
		return fmt.Errorf("previous config invalid: %w", err)
	}
	if err := c.Validate(); err != nil {
		return fmt.Errorf("current config invalid: %w", err)
	}
	return nil
}

// UpdateMeta updates metadata for new version
func (c *Config) UpdateMeta() error {
	c.Meta.Time = time.Now().UTC().Truncate(time.Microsecond)
	c.Meta.Version++
	c.Meta.PrevCS = c.Meta.CS
	c.Meta.CS = ""
	c.Meta.Signature = ""
	
	cs, err := computeChecksum(c)
	if err != nil {
		return err
	}
	c.Meta.CS = cs
	return nil
}

// MarshalJSON implements custom JSON marshaling with automatic metadata update
func (c *Config) MarshalJSON() ([]byte, error) {
	type alias Config
	return json.Marshal((*alias)(c))
}

// UnmarshalJSON implements custom JSON unmarshaling
func (c *Config) UnmarshalJSON(data []byte) error {
	type alias Config
	var tmp alias
	if err := json.Unmarshal(data, &tmp); err != nil {
		return err
	}
	
	*c = Config(tmp)
	return nil
}

// canonicalJSON produces deterministic JSON with sorted keys
func canonicalJSON(v interface{}) ([]byte, error) {
	normalized, err := normalizeValue(reflect.ValueOf(v))
	if err != nil {
		return nil, err
	}
	return json.Marshal(normalized)
}

// normalizeValue recursively normalizes for canonical JSON
func normalizeValue(v reflect.Value) (interface{}, error) {
	if !v.IsValid() {
		return nil, nil
	}
	
	for v.Kind() == reflect.Ptr || v.Kind() == reflect.Interface {
		if v.IsNil() {
			return nil, nil
		}
		v = v.Elem()
	}
	
	switch v.Kind() {
	case reflect.Bool:
		return v.Bool(), nil
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return v.Int(), nil
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return v.Uint(), nil
	case reflect.Float32, reflect.Float64:
		return v.Float(), nil
	case reflect.String:
		return v.String(), nil
	case reflect.Slice, reflect.Array:
		out := make([]interface{}, v.Len())
		for i := 0; i < v.Len(); i++ {
			nv, err := normalizeValue(v.Index(i))
			if err != nil {
				return nil, err
			}
			out[i] = nv
		}
		return out, nil
	case reflect.Map:
		if v.Type().Key().Kind() != reflect.String {
			return nil, fmt.Errorf("only string keys supported in maps")
		}
		keys := v.MapKeys()
		sorted := make([]string, 0, len(keys))
		for _, k := range keys {
			sorted = append(sorted, k.String())
		}
		sort.Strings(sorted)
		
		out := make(map[string]interface{}, len(sorted))
		for _, k := range sorted {
			kv := v.MapIndex(reflect.ValueOf(k))
			nv, err := normalizeValue(kv)
			if err != nil {
				return nil, err
			}
			out[k] = nv
		}
		return out, nil
	case reflect.Struct:
		if v.Type() == reflect.TypeOf(time.Time{}) {
			t := v.Interface().(time.Time).UTC().Truncate(time.Microsecond)
			return t.Format(time.RFC3339Nano), nil
		}
		
		out := make(map[string]interface{})
		t := v.Type()
		for i := 0; i < v.NumField(); i++ {
			f := t.Field(i)
			if f.PkgPath != "" {
				continue
			}
			tag := f.Tag.Get("json")
			if tag == "-" {
				continue
			}
			name := strings.Split(tag, ",")[0]
			if name == "" {
				name = f.Name
			}
			
			fv := v.Field(i)
			if strings.Contains(tag, "omitempty") && isZero(fv) {
				continue
			}
			
			// Special handling for json.RawMessage fields
			if fv.Type() == reflect.TypeOf(json.RawMessage{}) && fv.Len() > 0 {
				var parsed interface{}
				if err := json.Unmarshal(fv.Bytes(), &parsed); err != nil {
					return nil, err
				}
				nv, err := normalizeValue(reflect.ValueOf(parsed))
				if err != nil {
					return nil, err
				}
				out[name] = nv
			} else {
				nv, err := normalizeValue(fv)
				if err != nil {
					return nil, err
				}
				out[name] = nv
			}
		}
		return out, nil
	default:
		if v.CanInterface() {
			// Special handling for json.RawMessage
			if rm, ok := v.Interface().(json.RawMessage); ok {
				if len(rm) == 0 {
					return nil, nil
				}
				var result interface{}
				if err := json.Unmarshal(rm, &result); err != nil {
					return nil, err
				}
				return normalizeValue(reflect.ValueOf(result))
			}
			
			if m, ok := v.Interface().(json.Marshaler); ok {
				b, err := m.MarshalJSON()
				if err != nil {
					return nil, err
				}
				var result interface{}
				if err := json.Unmarshal(b, &result); err != nil {
					return nil, err
				}
				return result, nil
			}
		}
		return fmt.Sprintf("%v", v.Interface()), nil
	}
}

func isZero(v reflect.Value) bool {
	switch v.Kind() {
	case reflect.Array, reflect.Map, reflect.Slice, reflect.String:
		return v.Len() == 0
	case reflect.Bool:
		return !v.Bool()
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return v.Int() == 0
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return v.Uint() == 0
	case reflect.Float32, reflect.Float64:
		return v.Float() == 0
	case reflect.Interface, reflect.Ptr:
		return v.IsNil()
	case reflect.Struct:
		zero := reflect.Zero(v.Type()).Interface()
		return reflect.DeepEqual(v.Interface(), zero)
	}
	return false
}