package auth

import (
	"errors"
	"fmt"
)

var ErrMissingToken = errors.New("authentication token is missing")

// K8sOIDCAuthorizer validates K8s service account JWTs and looks up permissions.
type K8sOIDCAuthorizer struct {
	validator    JWTValidator
	permProvider PermissionsProvider
}

// NewK8sOIDCAuthorizer creates a new K8s OIDC authorizer.
func NewK8sOIDCAuthorizer(validator JWTValidator, permProvider PermissionsProvider) *K8sOIDCAuthorizer {
	return &K8sOIDCAuthorizer{
		validator:    validator,
		permProvider: permProvider,
	}
}

// Authorize validates the K8s SA JWT and returns permissions from the cache.
func (a *K8sOIDCAuthorizer) Authorize(token string) (bool, string, Permissions, error) {
	if token == "" {
		return false, "", Permissions{}, ErrMissingToken
	}

	claims, err := a.validator.Validate(token)
	if err != nil {
		return false, "", Permissions{}, fmt.Errorf("token validation failed: %w", err)
	}

	pub, sub, found := a.permProvider.GetPermissions(claims.Namespace, claims.ServiceAccount)
	if !found {
		return false, "", Permissions{}, fmt.Errorf(
			"service account %q in namespace %q is not present in the permissions cache",
			claims.ServiceAccount,
			claims.Namespace,
		)
	}

	userName := fmt.Sprintf("%s:%s", claims.Namespace, claims.ServiceAccount)
	return true, userName, Permissions{Pub: pub, Sub: sub}, nil
}
