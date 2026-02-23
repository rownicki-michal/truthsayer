package proxy

import (
	"fmt"
	"log"

	"golang.org/x/crypto/ssh"
)

// AuthConfig holds credentials for clients authenticating to the bastion.
//
// Users is a map of username → plaintext password loaded from config.yaml.
//
// Example config.yaml:
//
//	auth:
//	  users:
//	    alice: "password123"
//	    bob:   "password456"
//
// TODO (Phase 4): Replace plaintext comparison with bcrypt.
// TODO (Phase 4): Replace static users with LDAP/OIDC via internal/identity.Provider.
type AuthConfig struct {
	Users map[string]string // username -> plaintext password
}

// Authenticator verifies inbound client credentials against AuthConfig.
// It is passed to ssh.ServerConfig as the PasswordCallback.
//
// Each failed attempt is logged without revealing whether the user exists,
// preventing user enumeration attacks.
type Authenticator struct {
	users map[string]string
}

// NewAuthenticator creates an Authenticator from the given AuthConfig.
// Returns an error if the config contains no users — an empty allowlist
// would silently reject every connection which is likely a misconfiguration.
func NewAuthenticator(cfg AuthConfig) (*Authenticator, error) {
	if len(cfg.Users) == 0 {
		return nil, fmt.Errorf("auth config contains no users — every connection would be rejected")
	}
	return &Authenticator{users: cfg.Users}, nil
}

// Callback returns an ssh.ServerConfig-compatible PasswordCallback function.
//
// Usage:
//
//	serverConfig.PasswordCallback = auth.Callback()
func (a *Authenticator) Callback() func(ssh.ConnMetadata, []byte) (*ssh.Permissions, error) {
	return func(meta ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
		return a.verify(meta, password)
	}
}

// verify checks the supplied credentials against the user map.
// Returns nil Permissions on success (no extensions needed yet).
// Returns an opaque error on failure — never reveals whether the user exists.
func (a *Authenticator) verify(meta ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
	expected, ok := a.users[meta.User()]
	if !ok || expected != string(password) {
		log.Printf("[AUTH] Access denied for user %q from %s", meta.User(), meta.RemoteAddr())
		return nil, fmt.Errorf("access denied")
	}

	log.Printf("[AUTH] Authenticated user %q from %s", meta.User(), meta.RemoteAddr())
	return nil, nil
}
