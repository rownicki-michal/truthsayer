package proxy

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

// =============================================================================
// mockConnMeta — implements ssh.ConnMetadata for unit tests
// =============================================================================

type mockConnMeta struct {
	user string
	addr string
}

func (m *mockConnMeta) User() string { return m.user }
func (m *mockConnMeta) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP(m.addr), Port: 12345}
}
func (m *mockConnMeta) LocalAddr() net.Addr   { return &net.TCPAddr{} }
func (m *mockConnMeta) SessionID() []byte     { return nil }
func (m *mockConnMeta) ClientVersion() []byte { return nil }
func (m *mockConnMeta) ServerVersion() []byte { return nil }

func meta(user string) ssh.ConnMetadata {
	return &mockConnMeta{user: user, addr: "127.0.0.1"}
}

// =============================================================================
// NewAuthenticator
// =============================================================================

func TestNewAuthenticator_FailsWithNilUsers(t *testing.T) {
	_, err := NewAuthenticator(AuthConfig{Users: nil})
	assert.Error(t, err)
}

func TestNewAuthenticator_FailsWithEmptyUsers(t *testing.T) {
	_, err := NewAuthenticator(AuthConfig{Users: map[string]string{}})
	assert.Error(t, err)
}

func TestNewAuthenticator_SucceedsWithValidUsers(t *testing.T) {
	auth, err := NewAuthenticator(AuthConfig{Users: map[string]string{"alice": "pass"}})
	require.NoError(t, err)
	assert.NotNil(t, auth)
}

// =============================================================================
// Callback — valid credentials
// =============================================================================

func TestCallback_AcceptsValidCredentials(t *testing.T) {
	auth, err := NewAuthenticator(AuthConfig{Users: map[string]string{"alice": "secret"}})
	require.NoError(t, err)

	perms, err := auth.Callback()(meta("alice"), []byte("secret"))
	assert.NoError(t, err)
	assert.Nil(t, perms)
}

func TestCallback_AcceptsMultipleUsers(t *testing.T) {
	users := map[string]string{
		"alice": "alicepass",
		"bob":   "bobpass",
		"carol": "carolpass",
	}
	auth, err := NewAuthenticator(AuthConfig{Users: users})
	require.NoError(t, err)

	for user, pass := range users {
		t.Run(user, func(t *testing.T) {
			_, err := auth.Callback()(meta(user), []byte(pass))
			assert.NoError(t, err)
		})
	}
}

// =============================================================================
// Callback — invalid credentials
// =============================================================================

func TestCallback_RejectsWrongPassword(t *testing.T) {
	auth, _ := NewAuthenticator(AuthConfig{Users: map[string]string{"alice": "secret"}})

	_, err := auth.Callback()(meta("alice"), []byte("wrong"))
	assert.Error(t, err)
}

func TestCallback_RejectsUnknownUser(t *testing.T) {
	auth, _ := NewAuthenticator(AuthConfig{Users: map[string]string{"alice": "secret"}})

	_, err := auth.Callback()(meta("nobody"), []byte("secret"))
	assert.Error(t, err)
}

func TestCallback_RejectsEmptyPassword(t *testing.T) {
	auth, _ := NewAuthenticator(AuthConfig{Users: map[string]string{"alice": "secret"}})

	_, err := auth.Callback()(meta("alice"), []byte(""))
	assert.Error(t, err)
}

func TestCallback_RejectsCaseSensitiveUsername(t *testing.T) {
	auth, _ := NewAuthenticator(AuthConfig{Users: map[string]string{"alice": "secret"}})

	_, err := auth.Callback()(meta("Alice"), []byte("secret"))
	assert.Error(t, err)
}

func TestCallback_RejectsCaseSensitivePassword(t *testing.T) {
	auth, _ := NewAuthenticator(AuthConfig{Users: map[string]string{"alice": "Secret"}})

	_, err := auth.Callback()(meta("alice"), []byte("secret"))
	assert.Error(t, err)
}

func TestCallback_UserCannotUseOthersPassword(t *testing.T) {
	auth, _ := NewAuthenticator(AuthConfig{Users: map[string]string{
		"alice": "alicepass",
		"bob":   "bobpass",
	}})

	_, err := auth.Callback()(meta("alice"), []byte("bobpass"))
	assert.Error(t, err)
}

// =============================================================================
// User enumeration protection
// =============================================================================

func TestCallback_ErrorIsOpaqueForWrongPassword(t *testing.T) {
	auth, _ := NewAuthenticator(AuthConfig{Users: map[string]string{"alice": "secret"}})
	cb := auth.Callback()

	_, errWrongPass := cb(meta("alice"), []byte("wrong"))
	_, errUnknownUser := cb(meta("nobody"), []byte("secret"))

	// Both cases must return identical error messages — attacker cannot
	// determine whether a username exists by observing the error.
	require.Error(t, errWrongPass)
	require.Error(t, errUnknownUser)
	assert.Equal(t, errWrongPass.Error(), errUnknownUser.Error())
}
