// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 nats-aws-auth contributors

package main

import (
	"context"
	"fmt"
	"os"

	flag "github.com/spf13/pflag"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func main() {
	// Common flags
	var generate = flag.Bool("generate", false, "Generate a config file for nats-server in --output and exit")
	var generateCreds = flag.Bool("generate-credentials", false, "Generate NACK credentials file and exit")
	var region = flag.String("region", "", "AWS region (uses AWS config/environment if not specified)")
	var keyStorage = flag.String("key-storage", "kms", "persistent key storage: 'kms' or 'directory'")
	var keyDir = flag.String("key-dir", "./keys", "directory containing persistent keys when --key-storage=directory")
	var aliasPrefix = flag.String("alias-prefix", "nats", "prefix for persistent key names")

	// Config generation mode flags
	var operatorName = flag.String("operator-name", "KMS-Operator", "operator name for generated configuration")
	var sysAccountName = flag.String("sys-account", "SYS", "system account name")
	var outputDir = flag.String("output", ".", "output directory for generated files")
	var appAccountKeyAlias = flag.String("app-account-key-alias", "", "persistent key name for the APP account (e.g. 'nats-app-account'). When set, uses a stable APP account identity")

	// Auth service mode flags
	var authAccountName = flag.String("auth-account-name", "AUTH", "name of the AUTH account")
	var appAccountName = flag.String("app-account-name", "APP", "name of the APP account for authorized users")
	var natsURL = flag.String("url", "localhost:4222", "NATS server URL")

	// Auth backend flags
	var authBackend = flag.String("auth-backend", "allow-all", "auth backend: 'k8s-oidc' or 'allow-all'")
	var jwksURL = flag.String("jwks-url", "https://kubernetes.default.svc/openid/v1/jwks", "JWKS endpoint URL for k8s-oidc backend")
	var jwksPath = flag.String("jwks-path", "", "JWKS file path (for testing, mutually exclusive with --jwks-url)")
	var jwtIssuer = flag.String("jwt-issuer", "", "expected JWT issuer for k8s-oidc backend")
	var jwtAudience = flag.String("jwt-audience", "nats", "expected JWT audience for k8s-oidc backend")

	// Logging flags
	var debug = flag.Bool("debug", false, "enable debug logging")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [OPTIONS]\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "This is a service that implements the callout authentication mechanism for NATS.\n")
		fmt.Fprintf(os.Stderr, "Please see the README for more information: https://github.com/portswigger/nats-aws-auth\n\n")
		flag.PrintDefaults()
	}

	flag.Parse()

	// Initialize logger
	logger := initLogger(*debug)
	defer func() {
		_ = logger.Sync()
	}()

	ctx := context.Background()
	keyStore, err := newKeyStore(ctx, *keyStorage, *region, *keyDir)
	if err != nil {
		logger.Fatal("Failed to initialize key storage", zap.Error(err))
	}

	if *generate {
		runGenerate(ctx, logger, keyStore, *operatorName, *sysAccountName, *authAccountName, *outputDir, *aliasPrefix)
	} else if *generateCreds {
		if *appAccountKeyAlias == "" {
			logger.Fatal("--app-account-key-alias is required for --generate-credentials")
		}
		runGenerateCredentials(ctx, logger, keyStore, *appAccountKeyAlias, *outputDir)
	} else {
		authorizer := initAuthorizer(ctx, *authBackend, *jwksURL, *jwksPath, *jwtIssuer, *jwtAudience, logger)
		runAuthService(ctx, keyStore, *authAccountName, *appAccountName, *natsURL, *aliasPrefix, *appAccountKeyAlias, authorizer, logger)
	}
}

func initLogger(debug bool) *zap.Logger {
	config := zap.NewProductionConfig()
	config.Encoding = "console"
	config.EncoderConfig.TimeKey = "time"
	config.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	config.EncoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder

	if debug {
		config.Level = zap.NewAtomicLevelAt(zap.DebugLevel)
	} else {
		config.Level = zap.NewAtomicLevelAt(zap.InfoLevel)
	}

	logger, err := config.Build()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to initialize logger: %v\n", err)
		os.Exit(1)
	}

	return logger
}
