package auth

import (
	"errors"
	"fmt"
	"strings"

	"github.com/BurntSushi/toml"
	jwtpkg "github.com/portswigger/nats-aws-auth/internal/jwt"
)

var ErrMissingConfigToken = errors.New("authentication token is missing")

// Permission maps a token subject to explicitly allowed NATS subjects.
type Permission struct {
	Subject string   `toml:"subject"`
	Pub     []string `toml:"allowed-pub-subjects"`
	Sub     []string `toml:"allowed-sub-subjects"`
}

type Config struct {
	Permissions                     []Permission `toml:"permission"`
	LegacyServiceAccountPermissions bool         `toml:"legacy-serviceaccount-permissions"`
}

// LoadConfig rejects unknown keys and ambiguous subject mappings at startup.
func LoadConfig(path string) (*Config, error) {
	var config Config
	metadata, err := toml.DecodeFile(path, &config)
	if err != nil {
		return nil, fmt.Errorf("load permissions config: %w", err)
	}
	if keys := metadata.Undecoded(); len(keys) > 0 {
		return nil, fmt.Errorf("unknown permissions config keys: %v", keys)
	}
	seen := map[string]bool{}
	for _, permission := range config.Permissions {
		if strings.TrimSpace(permission.Subject) == "" {
			return nil, fmt.Errorf("permission subject must not be empty")
		}
		if seen[permission.Subject] {
			return nil, fmt.Errorf("duplicate permission subject %q", permission.Subject)
		}
		seen[permission.Subject] = true
		for _, subjects := range [][]string{permission.Pub, permission.Sub} {
			for _, subject := range subjects {
				if !validSubject(subject) {
					return nil, fmt.Errorf("invalid subject %q for subject %q", subject, permission.Subject)
				}
			}
		}
	}
	return &config, nil
}

func validSubject(subject string) bool {
	if subject == "" || strings.ContainsAny(subject, " \t\r\n") {
		return false
	}
	parts := strings.Split(subject, ".")
	for i, part := range parts {
		if part == "" {
			return false
		}
		if strings.ContainsAny(part, "*>") && part != "*" && !(part == ">" && i == len(parts)-1) {
			return false
		}
	}
	return true
}

// SubjectPermissionsProvider resolves permissions from the validated token subject.
type SubjectPermissionsProvider interface {
	PermissionsForSubject(subject string) (Permissions, bool)
}

func (c *Config) PermissionsForSubject(subject string) (Permissions, bool) {
	for _, permission := range c.Permissions {
		if permission.Subject == subject {
			return Permissions{Pub: append([]string{}, permission.Pub...), Sub: append([]string{}, permission.Sub...)}, true
		}
	}
	return Permissions{}, false
}

type ConfigAuthorizer struct {
	validator      JWTValidator
	permissions    SubjectPermissionsProvider
	legacy         PermissionsProvider
	legacyAudience string
}

func NewConfigAuthorizer(validator JWTValidator, permissions SubjectPermissionsProvider, legacy PermissionsProvider, legacyAudience string) *ConfigAuthorizer {
	return &ConfigAuthorizer{validator: validator, permissions: permissions, legacy: legacy, legacyAudience: legacyAudience}
}

func (a *ConfigAuthorizer) Authorize(token string) (bool, string, Permissions, error) {
	if token == "" {
		return false, "", Permissions{}, ErrMissingConfigToken
	}
	claims, err := a.validator.Validate(token)
	if err != nil {
		return false, "", Permissions{}, fmt.Errorf("token validation failed: %w", err)
	}
	return a.authorizeClaims(claims)
}

func (a *ConfigAuthorizer) authorizeClaims(claims *jwtpkg.Claims) (bool, string, Permissions, error) {
	namespace, serviceAccount, err := jwtpkg.ParseServiceAccountSubject(claims.Subject)
	if err != nil {
		return false, "", Permissions{}, err
	}
	namespaceSubject := namespace + ".>"
	perms := Permissions{
		Pub: []string{namespaceSubject},
		Sub: []string{"_INBOX.>", fmt.Sprintf("_INBOX_%s_%s.>", namespace, serviceAccount), namespaceSubject},
	}
	configured, _ := a.permissions.PermissionsForSubject(claims.Subject)
	perms.Pub = mergeSubjects(perms.Pub, configured.Pub)
	perms.Sub = mergeSubjects(perms.Sub, configured.Sub)
	for _, audience := range claims.Audience {
		if audience != a.legacyAudience {
			continue
		}
		pub, sub, legacyFound := a.legacy.GetPermissions(namespace, serviceAccount)
		if legacyFound {
			perms.Pub = mergeSubjects(perms.Pub, pub)
			perms.Sub = mergeSubjects(perms.Sub, sub)
		}
		break
	}
	return true, fmt.Sprintf("%s:%s", namespace, serviceAccount), perms, nil
}

// NoServiceAccountPermissions disables legacy ServiceAccount permissions.
type NoServiceAccountPermissions struct{}

func (NoServiceAccountPermissions) GetPermissions(namespace, name string) ([]string, []string, bool) {
	return nil, nil, false
}

func mergeSubjects(existing, additional []string) []string {
	result := append([]string{}, existing...)
	seen := make(map[string]bool, len(existing))
	for _, subject := range existing {
		seen[subject] = true
	}
	for _, subject := range additional {
		if !seen[subject] {
			result = append(result, subject)
			seen[subject] = true
		}
	}
	return result
}
