package viracochan

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/nbd-wtf/go-nostr"
)

// Signer provides cryptographic signing capabilities
type Signer struct {
	privateKey string
	publicKey  string
}

// NewSigner creates new signer with generated keypair
func NewSigner() (*Signer, error) {
	sk := nostr.GeneratePrivateKey()
	pk, err := nostr.GetPublicKey(sk)
	if err != nil {
		return nil, err
	}
	
	return &Signer{
		privateKey: sk,
		publicKey:  pk,
	}, nil
}

// NewSignerFromKey creates signer from existing private key
func NewSignerFromKey(privateKey string) (*Signer, error) {
	pk, err := nostr.GetPublicKey(privateKey)
	if err != nil {
		return nil, err
	}
	
	return &Signer{
		privateKey: privateKey,
		publicKey:  pk,
	}, nil
}

// PublicKey returns the public key
func (s *Signer) PublicKey() string {
	return s.publicKey
}

// Sign signs a config's checksum
func (s *Signer) Sign(cfg *Config) error {
	if cfg.Meta.CS == "" {
		return errors.New("config must have checksum before signing")
	}
	
	message := s.makeSigningMessage(cfg)
	sig, err := s.signMessage(message)
	if err != nil {
		return err
	}
	
	cfg.Meta.Signature = sig
	return nil
}

// Verify verifies a config's signature
func (s *Signer) Verify(cfg *Config, publicKey string) error {
	if cfg.Meta.Signature == "" {
		return errors.New("config has no signature")
	}
	
	message := s.makeSigningMessage(cfg)
	return s.verifyMessage(message, cfg.Meta.Signature, publicKey)
}

// makeSigningMessage creates canonical message for signing
func (s *Signer) makeSigningMessage(cfg *Config) string {
	// Include content hash in signing to detect tampering
	contentHash := sha256.Sum256(cfg.Content)
	return fmt.Sprintf("viracochan:v1:%s:%d:%s:%s", 
		cfg.Meta.CS,
		cfg.Meta.Version,
		cfg.Meta.Time.UTC().Format(time.RFC3339Nano),
		hex.EncodeToString(contentHash[:]))
}

// signMessage signs a message using Nostr-style signing
func (s *Signer) signMessage(message string) (string, error) {
	hash := sha256.Sum256([]byte(message))
	hashHex := hex.EncodeToString(hash[:])
	
	event := nostr.Event{
		PubKey:    s.publicKey,
		CreatedAt: nostr.Now(),
		Kind:      1,
		Tags:      nostr.Tags{},
		Content:   hashHex,
	}
	
	err := event.Sign(s.privateKey)
	if err != nil {
		return "", err
	}
	
	return event.Sig, nil
}

// verifyMessage verifies a message signature
func (s *Signer) verifyMessage(message, signature, publicKey string) error {
	hash := sha256.Sum256([]byte(message))
	hashHex := hex.EncodeToString(hash[:])
	
	event := nostr.Event{
		PubKey:    publicKey,
		CreatedAt: nostr.Now(),
		Kind:      1,
		Tags:      nostr.Tags{},
		Content:   hashHex,
		Sig:       signature,
	}
	
	ok, err := event.CheckSignature()
	if err != nil {
		return err
	}
	if !ok {
		return errors.New("invalid signature")
	}
	
	return nil
}

// SignedConfig extends Config with signature verification
type SignedConfig struct {
	*Config
	signer *Signer
}

// NewSignedConfig creates new signed configuration
func NewSignedConfig(cfg *Config, signer *Signer) *SignedConfig {
	return &SignedConfig{
		Config: cfg,
		signer: signer,
	}
}

// Update updates config and signs it
func (sc *SignedConfig) Update(content json.RawMessage) error {
	sc.Content = content
	
	if err := sc.UpdateMeta(); err != nil {
		return err
	}
	
	if sc.signer != nil {
		return sc.signer.Sign(sc.Config)
	}
	
	return nil
}

// VerifySignature verifies the config's signature
func (sc *SignedConfig) VerifySignature(publicKey string) error {
	if sc.signer == nil {
		return errors.New("no signer available")
	}
	return sc.signer.Verify(sc.Config, publicKey)
}

// VerifyChainSignatures verifies all signatures in a config chain
func VerifyChainSignatures(configs []*Config, publicKey string) error {
	signer := &Signer{}
	
	for i, cfg := range configs {
		if cfg.Meta.Signature == "" {
			continue
		}
		
		if err := signer.Verify(cfg, publicKey); err != nil {
			return fmt.Errorf("signature verification failed at index %d: %w", i, err)
		}
	}
	
	return nil
}