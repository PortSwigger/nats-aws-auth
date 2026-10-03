package main

import (
	"github.com/portswigger/nats-aws-auth/internal/auth"
	"testing"
)

func TestConvertPermissionsEmptyListsDenyAll(t *testing.T) {
	permissions := convertPermissions(auth.Permissions{})
	if len(permissions.Permissions.Pub.Deny) != 1 || permissions.Permissions.Pub.Deny[0] != ">" || len(permissions.Permissions.Sub.Deny) != 1 || permissions.Permissions.Sub.Deny[0] != ">" {
		t.Fatalf("empty permissions must deny all: %+v", permissions)
	}
}
