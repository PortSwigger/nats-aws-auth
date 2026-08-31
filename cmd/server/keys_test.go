// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 nats-aws-auth contributors

package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"
)

func TestDirectoryKeyStoreCreatesAndReusesKey(t *testing.T) {
	t.Parallel()

	keyDir := filepath.Join(t.TempDir(), "keys")
	store := &directoryKeyStore{dir: keyDir}

	created, existed, err := store.GetOrCreate(context.Background(), nkeys.PrefixByteOperator, "nats-operator")
	if err != nil {
		t.Fatalf("create key: %v", err)
	}
	if existed {
		t.Fatal("new key unexpectedly reported as existing")
	}

	keyPath := filepath.Join(keyDir, "nats-operator.nk")
	info, err := os.Stat(keyPath)
	if err != nil {
		t.Fatalf("stat key: %v", err)
	}
	if got := info.Mode().Perm(); got != 0600 {
		t.Fatalf("key permissions: got %04o, want 0600", got)
	}

	loaded, existed, err := store.GetOrCreate(context.Background(), nkeys.PrefixByteOperator, "nats-operator")
	if err != nil {
		t.Fatalf("reuse key: %v", err)
	}
	if !existed {
		t.Fatal("persisted key unexpectedly reported as new")
	}
	if loaded.PublicKey != created.PublicKey {
		t.Fatalf("public key changed: got %q, want %q", loaded.PublicKey, created.PublicKey)
	}

	token, err := createOperatorJWT(loaded.PublicKey, "test", "", loaded.Signer)
	if err != nil {
		t.Fatalf("sign with loaded key: %v", err)
	}
	claims, err := jwt.DecodeOperatorClaims(token)
	if err != nil {
		t.Fatalf("decode signed operator JWT: %v", err)
	}
	if claims.Subject != loaded.PublicKey {
		t.Fatalf("JWT subject: got %q, want %q", claims.Subject, loaded.PublicKey)
	}
}

func TestDirectoryKeyStoreRejectsWrongKeyType(t *testing.T) {
	t.Parallel()

	store := &directoryKeyStore{dir: t.TempDir()}
	accountKey, _, err := store.GetOrCreate(context.Background(), nkeys.PrefixByteAccount, "shared")
	if err != nil {
		t.Fatalf("create account key: %v", err)
	}

	_, err = store.Get(context.Background(), nkeys.PrefixByteOperator, "shared")
	if err == nil {
		t.Fatalf("loaded account key %q as an operator key", accountKey.PublicKey)
	}
}

func TestDirectoryKeyStoreRejectsPathTraversal(t *testing.T) {
	t.Parallel()

	store := &directoryKeyStore{dir: t.TempDir()}
	_, _, err := store.GetOrCreate(context.Background(), nkeys.PrefixByteAccount, "../outside")
	if err == nil {
		t.Fatal("path traversal key name was accepted")
	}
}

func TestNewKeyStoreRejectsUnknownStorage(t *testing.T) {
	t.Parallel()

	_, err := newKeyStore(context.Background(), "unknown", "", "")
	if err == nil {
		t.Fatal("unknown key storage was accepted")
	}
}
