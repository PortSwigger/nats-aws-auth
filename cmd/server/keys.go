// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 nats-aws-auth contributors

package main

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"
)

// ==========================================
// Type Definitions
// ==========================================

// StoredKey is a signing key loaded from a KeyStore.
type StoredKey struct {
	PublicKey string
	Reference string
	KeyPair   nkeys.KeyPair
	Signer    jwt.SignFn
}

// KeyStore loads and creates the persistent signing keys used by the service.
type KeyStore interface {
	Get(ctx context.Context, prefix nkeys.PrefixByte, name string) (*StoredKey, error)
	GetOrCreate(ctx context.Context, prefix nkeys.PrefixByte, name string) (*StoredKey, bool, error)
	Name() string
}

type kmsKeyStore struct {
	client *kms.Client
}

type directoryKeyStore struct {
	dir string
}

// LocalKey holds information about a locally generated key
type LocalKey struct {
	Seed      string // nkey seed (private key)
	PublicKey string // nkey-formatted public key
	KeyPair   nkeys.KeyPair
}

// dummyKeyPair implements nkeys.KeyPair interface for KMS-backed keys
type dummyKeyPair struct {
	pubKey string
}

func (d *dummyKeyPair) Seed() ([]byte, error) {
	return nil, fmt.Errorf("seed not available - key is stored in KMS")
}

func (d *dummyKeyPair) PublicKey() (string, error) {
	return d.pubKey, nil
}

func (d *dummyKeyPair) PrivateKey() ([]byte, error) {
	return nil, fmt.Errorf("private key not available - key is stored in KMS")
}

func (d *dummyKeyPair) Sign(input []byte) ([]byte, error) {
	return nil, fmt.Errorf("direct signing not available - use SignFn with KMS")
}

func (d *dummyKeyPair) Verify(input []byte, sig []byte) error {
	return fmt.Errorf("verify not implemented for dummy keypair")
}

func (d *dummyKeyPair) Wipe() {}

func (d *dummyKeyPair) Open(input []byte, sender string) ([]byte, error) {
	return nil, fmt.Errorf("open not available - key is stored in KMS")
}

func (d *dummyKeyPair) Seal(input []byte, recipient string) ([]byte, error) {
	return nil, fmt.Errorf("seal not available - key is stored in KMS")
}

func (d *dummyKeyPair) SealWithRand(input []byte, recipient string, rr io.Reader) ([]byte, error) {
	return nil, fmt.Errorf("seal not available - key is stored in KMS")
}

// ==========================================
// AWS and KMS Functions
// ==========================================

func loadAWSConfig(ctx context.Context, region string) (aws.Config, error) {
	if region != "" {
		return config.LoadDefaultConfig(ctx, config.WithRegion(region))
	}
	return config.LoadDefaultConfig(ctx)
}

func newKeyStore(ctx context.Context, storage, region, keyDir string) (KeyStore, error) {
	switch storage {
	case "kms":
		cfg, err := loadAWSConfig(ctx, region)
		if err != nil {
			return nil, fmt.Errorf("load AWS config: %w", err)
		}
		return &kmsKeyStore{client: kms.NewFromConfig(cfg)}, nil
	case "directory":
		if keyDir == "" {
			return nil, fmt.Errorf("--key-dir is required when --key-storage=directory")
		}
		return &directoryKeyStore{dir: keyDir}, nil
	default:
		return nil, fmt.Errorf("unsupported key storage %q (expected \"kms\" or \"directory\")", storage)
	}
}

func (s *kmsKeyStore) Name() string {
	return "AWS KMS"
}

func (s *kmsKeyStore) Get(ctx context.Context, prefix nkeys.PrefixByte, name string) (*StoredKey, error) {
	aliasName := name
	if !strings.HasPrefix(aliasName, "alias/") {
		aliasName = "alias/" + aliasName
	}
	return getExistingKMSKey(ctx, s.client, aliasName, prefix)
}

func (s *kmsKeyStore) GetOrCreate(ctx context.Context, prefix nkeys.PrefixByte, name string) (*StoredKey, bool, error) {
	return getOrCreateKMSKey(ctx, s.client, prefix, name)
}

// createKMSSigner creates a SignFn that signs using AWS KMS
func createKMSSigner(ctx context.Context, client *kms.Client, keyID string) jwt.SignFn {
	return func(pub string, data []byte) ([]byte, error) {
		// KMS has a 4096 byte limit for raw message signing with Ed25519
		if len(data) > 4096 {
			return nil, fmt.Errorf("message size (%d bytes) exceeds KMS limit of 4096 bytes", len(data))
		}

		signOutput, err := client.Sign(ctx, &kms.SignInput{
			KeyId:            aws.String(keyID),
			Message:          data,
			MessageType:      types.MessageTypeRaw,
			SigningAlgorithm: "ED25519_SHA_512",
		})
		if err != nil {
			return nil, fmt.Errorf("KMS sign failed: %w", err)
		}

		return signOutput.Signature, nil
	}
}

func extractEd25519PublicKey(derBytes []byte) ([]byte, error) {
	pubKeyInterface, err := x509.ParsePKIXPublicKey(derBytes)
	if err != nil {
		block, _ := pem.Decode(derBytes)
		if block != nil {
			pubKeyInterface, err = x509.ParsePKIXPublicKey(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("failed to parse public key: %w", err)
			}
		} else {
			return nil, fmt.Errorf("failed to parse public key: %w", err)
		}
	}

	switch pubKey := pubKeyInterface.(type) {
	case ed25519.PublicKey:
		if len(pubKey) != 32 {
			return nil, fmt.Errorf("invalid Ed25519 public key length: %d (expected 32)", len(pubKey))
		}
		return []byte(pubKey), nil
	default:
		return nil, fmt.Errorf("unexpected public key type: %T", pubKeyInterface)
	}
}

// getOrCreateKMSKey checks if a KMS key with the given alias exists and is the correct type.
// If it exists and is valid, it returns the existing key. Otherwise, it creates a new one.
func getOrCreateKMSKey(ctx context.Context, client *kms.Client, prefix nkeys.PrefixByte, alias string) (*StoredKey, bool, error) {
	aliasName := alias
	if !strings.HasPrefix(aliasName, "alias/") {
		aliasName = "alias/" + aliasName
	}

	// Try to get the existing key by alias
	existingKey, err := getExistingKMSKey(ctx, client, aliasName, prefix)
	if err == nil && existingKey != nil {
		// Key exists and is valid
		return existingKey, true, nil
	}

	// Key doesn't exist or is invalid, create a new one
	newKey, err := createKMSKey(ctx, client, prefix, aliasName)
	if err != nil {
		return nil, false, err
	}

	return newKey, false, nil
}

// getExistingKMSKey attempts to retrieve an existing KMS key by alias and validates its type
func getExistingKMSKey(ctx context.Context, client *kms.Client, aliasName string, prefix nkeys.PrefixByte) (*StoredKey, error) {
	// Try to describe the key using the alias
	describeOutput, err := client.DescribeKey(ctx, &kms.DescribeKeyInput{
		KeyId: aws.String(aliasName),
	})
	if err != nil {
		// Key doesn't exist
		return nil, err
	}

	keyMetadata := describeOutput.KeyMetadata

	// Verify the key is enabled
	if keyMetadata.KeyState != types.KeyStateEnabled {
		return nil, fmt.Errorf("key %s exists but is not enabled (state: %s)", aliasName, keyMetadata.KeyState)
	}

	// Verify it's an Ed25519 key
	if keyMetadata.KeySpec != types.KeySpecEccNistEdwards25519 {
		return nil, fmt.Errorf("key %s exists but is not Ed25519 (spec: %s)", aliasName, keyMetadata.KeySpec)
	}

	// Verify it's a sign/verify key
	if keyMetadata.KeyUsage != types.KeyUsageTypeSignVerify {
		return nil, fmt.Errorf("key %s exists but is not for signing (usage: %s)", aliasName, keyMetadata.KeyUsage)
	}

	keyID := *keyMetadata.KeyId

	// Get the public key
	getPublicKeyOutput, err := client.GetPublicKey(ctx, &kms.GetPublicKeyInput{
		KeyId: aws.String(keyID),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get public key from KMS: %w", err)
	}

	// Extract the raw Ed25519 public key
	rawPubKey, err := extractEd25519PublicKey(getPublicKeyOutput.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to extract Ed25519 public key: %w", err)
	}

	// Encode the public key in nkey format
	nkeyPublic, err := nkeys.Encode(prefix, rawPubKey)
	if err != nil {
		return nil, fmt.Errorf("failed to encode public key in nkey format: %w", err)
	}

	return &StoredKey{
		Reference: keyID,
		PublicKey: string(nkeyPublic),
		KeyPair:   &dummyKeyPair{pubKey: string(nkeyPublic)},
		Signer:    createKMSSigner(ctx, client, keyID),
	}, nil
}

// createKMSKey creates a new KMS key with the given alias
func createKMSKey(ctx context.Context, client *kms.Client, prefix nkeys.PrefixByte, aliasName string) (*StoredKey, error) {
	// Create the KMS asymmetric key with Ed25519
	createKeyInput := &kms.CreateKeyInput{
		KeySpec:     "ECC_NIST_EDWARDS25519",
		KeyUsage:    types.KeyUsageTypeSignVerify,
		Description: aws.String(fmt.Sprintf("NATS %s key", prefix.String())),
	}

	createKeyOutput, err := client.CreateKey(ctx, createKeyInput)
	if err != nil {
		return nil, fmt.Errorf("failed to create KMS key: %w", err)
	}

	keyID := *createKeyOutput.KeyMetadata.KeyId

	// Create alias if provided
	if aliasName != "" {
		if !strings.HasPrefix(aliasName, "alias/") {
			aliasName = "alias/" + aliasName
		}
		_, err = client.CreateAlias(ctx, &kms.CreateAliasInput{
			AliasName:   aws.String(aliasName),
			TargetKeyId: aws.String(keyID),
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to create alias %s: %v\n", aliasName, err)
		}
	}

	// Get the public key from KMS
	getPublicKeyOutput, err := client.GetPublicKey(ctx, &kms.GetPublicKeyInput{
		KeyId: aws.String(keyID),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get public key from KMS: %w", err)
	}

	// Extract the raw Ed25519 public key
	rawPubKey, err := extractEd25519PublicKey(getPublicKeyOutput.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to extract Ed25519 public key: %w", err)
	}

	// Encode the public key in nkey format
	nkeyPublic, err := nkeys.Encode(prefix, rawPubKey)
	if err != nil {
		return nil, fmt.Errorf("failed to encode public key in nkey format: %w", err)
	}

	return &StoredKey{
		Reference: keyID,
		PublicKey: string(nkeyPublic),
		KeyPair:   &dummyKeyPair{pubKey: string(nkeyPublic)},
		Signer:    createKMSSigner(ctx, client, keyID),
	}, nil
}

func (s *directoryKeyStore) Name() string {
	return "local directory"
}

func (s *directoryKeyStore) Get(ctx context.Context, prefix nkeys.PrefixByte, name string) (*StoredKey, error) {
	_ = ctx

	path, err := s.keyPath(name)
	if err != nil {
		return nil, err
	}
	seed, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read key %q: %w", name, err)
	}

	return storedKeyFromSeed(prefix, name, seed)
}

func (s *directoryKeyStore) GetOrCreate(ctx context.Context, prefix nkeys.PrefixByte, name string) (*StoredKey, bool, error) {
	key, err := s.Get(ctx, prefix, name)
	if err == nil {
		return key, true, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, false, err
	}

	path, err := s.keyPath(name)
	if err != nil {
		return nil, false, err
	}
	if err := os.MkdirAll(s.dir, 0700); err != nil {
		return nil, false, fmt.Errorf("create key directory: %w", err)
	}

	localKey, err := createLocalKey(prefix)
	if err != nil {
		return nil, false, err
	}

	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if os.IsExist(err) {
		key, loadErr := s.Get(ctx, prefix, name)
		return key, true, loadErr
	}
	if err != nil {
		return nil, false, fmt.Errorf("create key %q: %w", name, err)
	}

	seed := []byte(localKey.Seed + "\n")
	if _, err := file.Write(seed); err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return nil, false, fmt.Errorf("write key %q: %w", name, err)
	}
	if err := file.Close(); err != nil {
		_ = os.Remove(path)
		return nil, false, fmt.Errorf("close key %q: %w", name, err)
	}

	return storedKeyFromLocalKey(name, localKey), false, nil
}

func (s *directoryKeyStore) keyPath(name string) (string, error) {
	name = strings.TrimPrefix(name, "alias/")
	if name == "" || filepath.Base(name) != name || name == "." {
		return "", fmt.Errorf("invalid key name %q", name)
	}
	return filepath.Join(s.dir, name+".nk"), nil
}

func storedKeyFromSeed(prefix nkeys.PrefixByte, name string, seed []byte) (*StoredKey, error) {
	seed = []byte(strings.TrimSpace(string(seed)))
	actualPrefix, _, err := nkeys.DecodeSeed(seed)
	if err != nil {
		return nil, fmt.Errorf("decode key %q: %w", name, err)
	}
	if actualPrefix != prefix {
		return nil, fmt.Errorf("key %q has prefix %s, expected %s", name, actualPrefix, prefix)
	}

	keyPair, err := nkeys.FromSeed(seed)
	if err != nil {
		return nil, fmt.Errorf("load key %q: %w", name, err)
	}
	publicKey, err := keyPair.PublicKey()
	if err != nil {
		return nil, fmt.Errorf("get public key for %q: %w", name, err)
	}

	return &StoredKey{
		PublicKey: publicKey,
		Reference: name,
		KeyPair:   keyPair,
		Signer: func(_ string, data []byte) ([]byte, error) {
			return keyPair.Sign(data)
		},
	}, nil
}

func storedKeyFromLocalKey(name string, key *LocalKey) *StoredKey {
	return &StoredKey{
		PublicKey: key.PublicKey,
		Reference: name,
		KeyPair:   key.KeyPair,
		Signer: func(_ string, data []byte) ([]byte, error) {
			return key.KeyPair.Sign(data)
		},
	}
}

func createLocalKey(prefix nkeys.PrefixByte) (*LocalKey, error) {
	var kp nkeys.KeyPair
	var err error

	switch prefix {
	case nkeys.PrefixByteAccount:
		kp, err = nkeys.CreateAccount()
	case nkeys.PrefixByteUser:
		kp, err = nkeys.CreateUser()
	case nkeys.PrefixByteOperator:
		kp, err = nkeys.CreateOperator()
	default:
		return nil, fmt.Errorf("unsupported key prefix: %v", prefix)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to create keypair: %w", err)
	}

	seed, err := kp.Seed()
	if err != nil {
		return nil, fmt.Errorf("failed to get seed: %w", err)
	}

	pubKey, err := kp.PublicKey()
	if err != nil {
		return nil, fmt.Errorf("failed to get public key: %w", err)
	}

	return &LocalKey{
		Seed:      string(seed),
		PublicKey: pubKey,
		KeyPair:   kp,
	}, nil
}
