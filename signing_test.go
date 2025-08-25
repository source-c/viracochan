package viracochan

import (
	"encoding/json"
	"fmt"
	"testing"
)

func TestSigner(t *testing.T) {
	signer, err := NewSigner()
	if err != nil {
		t.Fatalf("NewSigner failed: %v", err)
	}

	if signer.PublicKey() == "" {
		t.Error("Public key not set")
	}

	if signer.privateKey == "" {
		t.Error("Private key not set")
	}
}

func TestSignAndVerify(t *testing.T) {
	signer, err := NewSigner()
	if err != nil {
		t.Fatalf("NewSigner failed: %v", err)
	}

	cfg := &Config{
		Content: json.RawMessage(`{"signed": "data"}`),
	}
	cfg.UpdateMeta()

	// Test signing
	if err := signer.Sign(cfg); err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	if cfg.Meta.Signature == "" {
		t.Error("Signature not set")
	}

	// Test verification with correct public key
	if err := signer.Verify(cfg, signer.PublicKey()); err != nil {
		t.Errorf("Verification failed with correct key: %v", err)
	}

	// Test verification with wrong public key
	wrongSigner, _ := NewSigner()
	if err := signer.Verify(cfg, wrongSigner.PublicKey()); err == nil {
		t.Error("Verification should fail with wrong public key")
	}
}

func TestSignerFromKey(t *testing.T) {
	// Create first signer to get a valid private key
	signer1, err := NewSigner()
	if err != nil {
		t.Fatalf("NewSigner failed: %v", err)
	}

	// Create second signer from the same private key
	signer2, err := NewSignerFromKey(signer1.privateKey)
	if err != nil {
		t.Fatalf("NewSignerFromKey failed: %v", err)
	}

	if signer1.PublicKey() != signer2.PublicKey() {
		t.Error("Public keys should match for same private key")
	}

	// Sign with first signer
	cfg := &Config{
		Content: json.RawMessage(`{"test": "data"}`),
	}
	cfg.UpdateMeta()
	signer1.Sign(cfg)

	// Verify with second signer
	if err := signer2.Verify(cfg, signer1.PublicKey()); err != nil {
		t.Error("Cross-signer verification failed")
	}
}

func TestSignedConfig(t *testing.T) {
	signer, err := NewSigner()
	if err != nil {
		t.Fatalf("NewSigner failed: %v", err)
	}

	cfg := &Config{
		Content: json.RawMessage(`{"initial": "value"}`),
	}
	cfg.UpdateMeta()

	signedCfg := NewSignedConfig(cfg, signer)

	// Test update and sign
	newContent := json.RawMessage(`{"updated": "value"}`)
	if err := signedCfg.Update(newContent); err != nil {
		t.Fatalf("Update failed: %v", err)
	}

	if signedCfg.Meta.Signature == "" {
		t.Error("Signature not set after update")
	}

	if signedCfg.Meta.Version != 2 {
		t.Errorf("Expected version 2 after update, got %d", signedCfg.Meta.Version)
	}

	// Test signature verification
	if err := signedCfg.VerifySignature(signer.PublicKey()); err != nil {
		t.Errorf("Signature verification failed: %v", err)
	}
}

func TestVerifyChainSignatures(t *testing.T) {
	signer, err := NewSigner()
	if err != nil {
		t.Fatalf("NewSigner failed: %v", err)
	}

	configs := make([]*Config, 5)
	for i := 0; i < 5; i++ {
		cfg := &Config{
			Content: json.RawMessage(fmt.Sprintf(`{"index": %d}`, i)),
		}

		if i > 0 {
			cfg.Meta = configs[i-1].Meta
		}

		cfg.UpdateMeta()
		signer.Sign(cfg)
		configs[i] = cfg
	}

	// Verify all signatures
	if err := VerifyChainSignatures(configs, signer.PublicKey()); err != nil {
		t.Errorf("Chain signature verification failed: %v", err)
	}

	// Corrupt one signature
	configs[2].Meta.Signature = "invalid"
	if err := VerifyChainSignatures(configs, signer.PublicKey()); err == nil {
		t.Error("Expected verification to fail with corrupted signature")
	}
}

func TestSigningWithoutChecksum(t *testing.T) {
	signer, err := NewSigner()
	if err != nil {
		t.Fatalf("NewSigner failed: %v", err)
	}

	cfg := &Config{
		Content: json.RawMessage(`{"test": "data"}`),
	}
	// Don't call UpdateMeta, so CS is empty

	if err := signer.Sign(cfg); err == nil {
		t.Error("Expected error signing config without checksum")
	}
}

func TestVerifyWithoutSignature(t *testing.T) {
	signer, err := NewSigner()
	if err != nil {
		t.Fatalf("NewSigner failed: %v", err)
	}

	cfg := &Config{
		Content: json.RawMessage(`{"test": "data"}`),
	}
	cfg.UpdateMeta()
	// Don't sign it

	if err := signer.Verify(cfg, signer.PublicKey()); err == nil {
		t.Error("Expected error verifying config without signature")
	}
}

func TestSignatureTampering(t *testing.T) {
	signer, err := NewSigner()
	if err != nil {
		t.Fatalf("NewSigner failed: %v", err)
	}

	cfg := &Config{
		Content: json.RawMessage(`{"original": "content"}`),
	}
	cfg.UpdateMeta()
	signer.Sign(cfg)

	originalSig := cfg.Meta.Signature

	// Tamper with content after signing
	cfg.Content = json.RawMessage(`{"tampered": "content"}`)

	// Verification should fail
	if err := signer.Verify(cfg, signer.PublicKey()); err == nil {
		t.Error("Verification should fail after content tampering")
	}

	// Restore original content but change version
	cfg.Content = json.RawMessage(`{"original": "content"}`)
	cfg.Meta.Version = 999
	cfg.Meta.Signature = originalSig

	// Verification should still fail
	if err := signer.Verify(cfg, signer.PublicKey()); err == nil {
		t.Error("Verification should fail after version tampering")
	}
}
