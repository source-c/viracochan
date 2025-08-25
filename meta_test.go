package viracochan

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"
)

func TestConfigValidation(t *testing.T) {
	cfg := &Config{
		Content: json.RawMessage(`{"key": "value"}`),
	}

	if err := cfg.UpdateMeta(); err != nil {
		t.Fatalf("UpdateMeta failed: %v", err)
	}

	if cfg.Meta.Version != 1 {
		t.Errorf("Expected version 1, got %d", cfg.Meta.Version)
	}

	if cfg.Meta.CS == "" {
		t.Error("Checksum not set")
	}

	if err := cfg.Validate(); err != nil {
		t.Errorf("Validation failed: %v", err)
	}

	oldCS := cfg.Meta.CS
	cfg.Meta.CS = "invalid"
	if err := cfg.Validate(); err == nil {
		t.Error("Expected validation to fail with invalid checksum")
	}
	cfg.Meta.CS = oldCS
}

func TestConfigChain(t *testing.T) {
	cfg1 := &Config{
		Content: json.RawMessage(`{"version": 1}`),
	}

	if err := cfg1.UpdateMeta(); err != nil {
		t.Fatalf("UpdateMeta failed: %v", err)
	}

	cfg2 := &Config{
		Meta:    cfg1.Meta,
		Content: json.RawMessage(`{"version": 2}`),
	}

	if err := cfg2.UpdateMeta(); err != nil {
		t.Fatalf("UpdateMeta failed: %v", err)
	}

	if err := cfg2.NextOf(cfg1); err != nil {
		t.Errorf("NextOf validation failed: %v", err)
	}

	if cfg2.Meta.PrevCS != cfg1.Meta.CS {
		t.Errorf("PrevCS mismatch: expected %s, got %s", cfg1.Meta.CS, cfg2.Meta.PrevCS)
	}

	if cfg2.Meta.Version != 2 {
		t.Errorf("Expected version 2, got %d", cfg2.Meta.Version)
	}
}

func TestTimestampRegression(t *testing.T) {
	cfg1 := &Config{
		Content: json.RawMessage(`{"v": 1}`),
	}
	cfg1.UpdateMeta()

	time.Sleep(10 * time.Millisecond)

	cfg2 := &Config{
		Meta:    cfg1.Meta,
		Content: json.RawMessage(`{"v": 2}`),
	}
	cfg2.UpdateMeta()

	cfg2.Meta.Time = cfg1.Meta.Time.Add(-1 * time.Second)

	if err := cfg2.NextOf(cfg1); err == nil {
		t.Error("Expected timestamp regression error")
	}
}

func TestCanonicalJSON(t *testing.T) {
	data := map[string]interface{}{
		"z": "last",
		"a": "first",
		"m": "middle",
		"nested": map[string]interface{}{
			"y": 2,
			"x": 1,
		},
	}

	json1, err := canonicalJSON(data)
	if err != nil {
		t.Fatalf("canonicalJSON failed: %v", err)
	}

	json2, err := canonicalJSON(data)
	if err != nil {
		t.Fatalf("canonicalJSON failed: %v", err)
	}

	if string(json1) != string(json2) {
		t.Error("Canonical JSON not deterministic")
	}

	expected := `{"a":"first","m":"middle","nested":{"x":1,"y":2},"z":"last"}`
	if string(json1) != expected {
		t.Errorf("Unexpected canonical JSON:\nGot:      %s\nExpected: %s", json1, expected)
	}
}

func TestVersionChain(t *testing.T) {
	configs := make([]*Config, 10)

	for i := 0; i < 10; i++ {
		cfg := &Config{
			Content: json.RawMessage(fmt.Sprintf(`{"iteration": %d}`, i)),
		}

		if i > 0 {
			cfg.Meta = configs[i-1].Meta
		}

		if err := cfg.UpdateMeta(); err != nil {
			t.Fatalf("UpdateMeta failed at %d: %v", i, err)
		}

		configs[i] = cfg

		if i > 0 {
			if err := cfg.NextOf(configs[i-1]); err != nil {
				t.Errorf("Chain validation failed at %d: %v", i, err)
			}
		}
	}

	if configs[9].Meta.Version != 10 {
		t.Errorf("Expected version 10, got %d", configs[9].Meta.Version)
	}

	for i := 1; i < 10; i++ {
		if configs[i].Meta.PrevCS != configs[i-1].Meta.CS {
			t.Errorf("Chain break at %d", i)
		}
	}
}
