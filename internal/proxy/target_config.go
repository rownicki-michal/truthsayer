package proxy

import "golang.org/x/crypto/ssh"

// TargetConfig holds connection parameters for the target SSH server.
//
// It is a pure data-transfer object — no methods, no logic.
// Used by TargetClient (client.go) to establish the outbound SSH connection,
// and stored in SSHServer (server.go) so it can be passed to Dial() per connection.
//
// Authentication methods are evaluated in priority order by buildAuthMethods
// in client.go. Configure only the methods appropriate for your environment.
type TargetConfig struct {
	// Addr is the target server address, e.g. "10.0.0.1:22".
	Addr string

	// User is the username used to authenticate with the target server.
	// Typically a shared service account, e.g. "deploy" or "bastion".
	User string

	// Password authenticates the bastion to the target using a password.
	// Development and testing only — never use in production.
	// The password is visible in RAM during the SSH handshake.
	Password string

	// PrivateKey is a static SSH key held by the bastion.
	// Must be present in the target's authorized_keys.
	// Load from Vault or an encrypted secret store — never from a plain file.
	PrivateKey ssh.Signer

	// CertSigner is a short-lived certificate issued by the bastion CA (Phase 4).
	// Target servers trust the CA public key instead of per-user keys.
	// Eliminates the need to manage authorized_keys on every target server.
	CertSigner ssh.Signer

	// AgentForwarding enables use of the client's SSH agent for authenticating
	// to the target. The client's private key never leaves their machine —
	// the bastion only forwards signing requests to the agent.
	// Most secure option when clients connect with agent forwarding enabled.
	AgentForwarding bool
}
