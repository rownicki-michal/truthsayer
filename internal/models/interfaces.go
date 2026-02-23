package models

import (
	"io"

	"golang.org/x/crypto/ssh"
)

// SSHBridge defines the bridge between an inbound and an outbound SSH connection.
type SSHBridge interface {
	// ProxyRequests forwards structural SSH requests (pty-req, shell).
	ProxyRequests(clientReqs, targetReqs <-chan *ssh.Request)
	// Pipe forwards raw data streams (stdin/stdout).
	Pipe()
}

// Recorder defines the contract for the audit module.
type Recorder interface {
	io.WriteCloser
	Record(data []byte) error
}

// PolicyEngine defines the contract for the security enforcement module.
type PolicyEngine interface {
	Verify(input []byte) (bool, error)
}
