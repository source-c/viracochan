package viracochan

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
)

const (
	// SignatureAlgorithmV2 identifies the native v0.2.0 signature format.
	SignatureAlgorithmV2 = "vc-schnorr-secp256k1-v2"
)

var (
	ErrUnsupportedSignatureAlgorithm = errors.New("unsupported signature algorithm")
)

// Signer provides cryptographic signing capabilities.
type Signer struct {
	privateKey string
	publicKey  string
}

// NewSigner creates new signer with generated keypair.
func NewSigner() (*Signer, error) {
	privateKey, err := btcec.NewPrivateKey()
	if err != nil {
		return nil, err
	}

	return &Signer{
		privateKey: hex.EncodeToString(privateKey.Serialize()),
		publicKey:  hex.EncodeToString(schnorr.SerializePubKey(privateKey.PubKey())),
	}, nil
}

// NewSignerFromKey creates signer from existing private key.
func NewSignerFromKey(privateKey string) (*Signer, error) {
	priv, err := decodePrivateKey(privateKey)
	if err != nil {
		return nil, err
	}

	return &Signer{
		privateKey: hex.EncodeToString(priv.Serialize()),
		publicKey:  hex.EncodeToString(schnorr.SerializePubKey(priv.PubKey())),
	}, nil
}

// PublicKey returns the public key.
func (s *Signer) PublicKey() string {
	return s.publicKey
}

// Sign signs a config using the native v0.2.0 signature format.
func (s *Signer) Sign(cfg *Config) error {
	if cfg.Meta.CS == "" {
		return errors.New("config must have checksum before signing")
	}

	hash := makeSigningHashV2(cfg)
	sig, err := s.signHash(hash[:])
	if err != nil {
		return err
	}

	cfg.Meta.Signature = sig
	cfg.Meta.SigAlg = SignatureAlgorithmV2
	return nil
}

// Verify verifies a config's signature.
func (s *Signer) Verify(cfg *Config, publicKey string) error {
	if cfg.Meta.Signature == "" {
		return errors.New("config has no signature")
	}
	if cfg.Meta.SigAlg != SignatureAlgorithmV2 {
		return fmt.Errorf("%w: %q", ErrUnsupportedSignatureAlgorithm, cfg.Meta.SigAlg)
	}

	hash := makeSigningHashV2(cfg)
	return verifyHash(hash[:], cfg.Meta.Signature, publicKey)
}

func makeSigningPayloadV2(cfg *Config) []byte {
	contentHash := sha256.Sum256(cfg.Content)
	return []byte(fmt.Sprintf("viracochan:sig:v2:%s:%d:%s:%s",
		cfg.Meta.CS,
		cfg.Meta.Version,
		cfg.Meta.Time.UTC().Format(time.RFC3339Nano),
		hex.EncodeToString(contentHash[:])))
}

func makeSigningHashV2(cfg *Config) [32]byte {
	return sha256.Sum256(makeSigningPayloadV2(cfg))
}

func (s *Signer) signHash(hash []byte) (string, error) {
	priv, err := decodePrivateKey(s.privateKey)
	if err != nil {
		return "", err
	}

	sig, err := schnorr.Sign(priv, hash)
	if err != nil {
		return "", err
	}

	return hex.EncodeToString(sig.Serialize()), nil
}

func verifyHash(hash []byte, signature, publicKey string) error {
	pubKeyBytes, err := hex.DecodeString(publicKey)
	if err != nil {
		return fmt.Errorf("invalid public key: %w", err)
	}

	pubKey, err := schnorr.ParsePubKey(pubKeyBytes)
	if err != nil {
		return fmt.Errorf("invalid public key: %w", err)
	}

	sigBytes, err := hex.DecodeString(signature)
	if err != nil {
		return fmt.Errorf("invalid signature: %w", err)
	}

	sig, err := schnorr.ParseSignature(sigBytes)
	if err != nil {
		return fmt.Errorf("invalid signature: %w", err)
	}

	if !sig.Verify(hash, pubKey) {
		return errors.New("invalid signature")
	}

	return nil
}

func decodePrivateKey(privateKey string) (*btcec.PrivateKey, error) {
	privateKeyBytes, err := hex.DecodeString(privateKey)
	if err != nil {
		return nil, fmt.Errorf("invalid private key: %w", err)
	}
	if len(privateKeyBytes) != btcec.PrivKeyBytesLen {
		return nil, fmt.Errorf("invalid private key length: got %d, want %d", len(privateKeyBytes), btcec.PrivKeyBytesLen)
	}

	priv, _ := btcec.PrivKeyFromBytes(privateKeyBytes)
	return priv, nil
}

// SignedConfig extends Config with signature verification.
type SignedConfig struct {
	*Config
	signer *Signer
}

// NewSignedConfig creates new signed configuration.
func NewSignedConfig(cfg *Config, signer *Signer) *SignedConfig {
	return &SignedConfig{
		Config: cfg,
		signer: signer,
	}
}

// Update updates config and signs it.
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

// VerifySignature verifies the config's signature.
func (sc *SignedConfig) VerifySignature(publicKey string) error {
	if sc.signer == nil {
		return errors.New("no signer available")
	}
	return sc.signer.Verify(sc.Config, publicKey)
}

// VerifyChainSignatures verifies all signatures in a config chain.
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
