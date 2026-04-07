package viracochan

import (
	"encoding/json"
	"errors"
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
	if err := cfg.UpdateMeta(); err != nil {
		t.Fatalf("UpdateMeta failed: %v", err)
	}

	if err := signer.Sign(cfg); err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	if cfg.Meta.Signature == "" {
		t.Error("Signature not set")
	}
	if cfg.Meta.SigAlg != SignatureAlgorithmV2 {
		t.Errorf("Expected sig_alg %q, got %q", SignatureAlgorithmV2, cfg.Meta.SigAlg)
	}

	if err := signer.Verify(cfg, signer.PublicKey()); err != nil {
		t.Errorf("Verification failed with correct key: %v", err)
	}

	wrongSigner, _ := NewSigner()
	if err := signer.Verify(cfg, wrongSigner.PublicKey()); err == nil {
		t.Error("Verification should fail with wrong public key")
	}
}

func TestSigningHashIsDeterministic(t *testing.T) {
	cfg := &Config{
		Content: json.RawMessage(`{"signed": "data"}`),
	}
	if err := cfg.UpdateMeta(); err != nil {
		t.Fatalf("UpdateMeta failed: %v", err)
	}

	hash1 := makeSigningHashV2(cfg)
	hash2 := makeSigningHashV2(cfg)
	if hash1 != hash2 {
		t.Fatal("signing hash is not deterministic for the same config")
	}
}

func TestVerifyRejectsLegacySignatures(t *testing.T) {
	signer, err := NewSigner()
	if err != nil {
		t.Fatalf("NewSigner failed: %v", err)
	}

	cfg := &Config{
		Content: json.RawMessage(`{"legacy": true}`),
	}
	if err := cfg.UpdateMeta(); err != nil {
		t.Fatalf("UpdateMeta failed: %v", err)
	}
	if err := signLegacyFixture(cfg, signer); err != nil {
		t.Fatalf("Legacy signing failed: %v", err)
	}

	if err := signer.Verify(cfg, signer.PublicKey()); err == nil {
		t.Fatal("expected legacy signature to be rejected")
	} else if !errors.Is(err, ErrUnsupportedSignatureAlgorithm) {
		t.Fatalf("expected unsupported signature algorithm error, got %v", err)
	}
}

func TestSignerFromKey(t *testing.T) {
	signer1, err := NewSigner()
	if err != nil {
		t.Fatalf("NewSigner failed: %v", err)
	}

	signer2, err := NewSignerFromKey(signer1.privateKey)
	if err != nil {
		t.Fatalf("NewSignerFromKey failed: %v", err)
	}

	if signer1.PublicKey() != signer2.PublicKey() {
		t.Error("Public keys should match for same private key")
	}

	cfg := &Config{
		Content: json.RawMessage(`{"test": "data"}`),
	}
	if err := cfg.UpdateMeta(); err != nil {
		t.Fatalf("UpdateMeta failed: %v", err)
	}
	if err := signer1.Sign(cfg); err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

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
	if err := cfg.UpdateMeta(); err != nil {
		t.Fatalf("UpdateMeta failed: %v", err)
	}

	signedCfg := NewSignedConfig(cfg, signer)
	newContent := json.RawMessage(`{"updated": "value"}`)
	if err := signedCfg.Update(newContent); err != nil {
		t.Fatalf("Update failed: %v", err)
	}

	if signedCfg.Meta.Signature == "" {
		t.Error("Signature not set after update")
	}
	if signedCfg.Meta.SigAlg != SignatureAlgorithmV2 {
		t.Errorf("Expected sig_alg %q, got %q", SignatureAlgorithmV2, signedCfg.Meta.SigAlg)
	}
	if signedCfg.Meta.Version != 2 {
		t.Errorf("Expected version 2 after update, got %d", signedCfg.Meta.Version)
	}

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

		if err := cfg.UpdateMeta(); err != nil {
			t.Fatalf("UpdateMeta failed: %v", err)
		}
		if err := signer.Sign(cfg); err != nil {
			t.Fatalf("Sign failed: %v", err)
		}
		configs[i] = cfg
	}

	if err := VerifyChainSignatures(configs, signer.PublicKey()); err != nil {
		t.Errorf("Chain signature verification failed: %v", err)
	}

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
	if err := cfg.UpdateMeta(); err != nil {
		t.Fatalf("UpdateMeta failed: %v", err)
	}

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
	if err := cfg.UpdateMeta(); err != nil {
		t.Fatalf("UpdateMeta failed: %v", err)
	}
	if err := signer.Sign(cfg); err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	originalSig := cfg.Meta.Signature

	cfg.Content = json.RawMessage(`{"tampered": "content"}`)
	if err := signer.Verify(cfg, signer.PublicKey()); err == nil {
		t.Error("Verification should fail after content tampering")
	}

	cfg.Content = json.RawMessage(`{"original": "content"}`)
	cfg.Meta.Version = 999
	cfg.Meta.Signature = originalSig
	cfg.Meta.SigAlg = SignatureAlgorithmV2

	if err := signer.Verify(cfg, signer.PublicKey()); err == nil {
		t.Error("Verification should fail after version tampering")
	}
}

// signLegacyFixture simulates a legacy v0.1.x signed config by setting a
// non-empty signature with no algorithm tag. The actual cryptographic value
// does not matter: migration only checks that the signature field is non-empty
// and that SigAlg is absent, then re-signs with the v2 format. The old nostr
// event signature was unverifiable at rest (see MigrateLegacyConfig).
func signLegacyFixture(cfg *Config, _ *Signer) error {
	cfg.Meta.Signature = "legacy00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
	cfg.Meta.SigAlg = ""
	return nil
}
