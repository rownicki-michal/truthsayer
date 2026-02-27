package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"golang.org/x/crypto/ssh"

	"truthsayer/internal/config"
	"truthsayer/internal/proxy"
)

func main() {
	configPath := flag.String("config", "config.yaml", "path to config file")
	flag.Parse()

	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("[BOOT] Failed to load config from %q: %v", *configPath, err)
	}

	hostKey, err := loadOrGenerateHostKey(cfg.Server.HostKeyPath)
	if err != nil {
		log.Fatalf("[BOOT] Failed to load host key: %v", err)
	}

	auth := proxy.AuthConfig{
		Users: cfg.Auth.Users,
	}

	target := proxy.TargetConfig{
		Addr: cfg.Target.DefaultAddr,
		User: cfg.Target.DefaultUser,
	}

	limits := proxy.LimitsConfig{
		MaxConnections:     cfg.Limits.MaxConnections,
		MaxChannelsPerConn: cfg.Limits.MaxChannelsPerConn,
	}

	addr := fmt.Sprintf("%s:%d", cfg.Server.Host, cfg.Server.Port)
	srv, err := proxy.NewSSHServer(addr, hostKey, auth, target, limits, cfg.Security, cfg.Audit)
	if err != nil {
		log.Fatalf("[BOOT] Failed to create server: %v", err)
	}

	ctx, cancel := signal.NotifyContext(context.Background(),
		os.Interrupt, syscall.SIGTERM)
	defer cancel()

	log.Printf("[BOOT] Truthsayer bastion starting on %s", addr)
	log.Printf("[BOOT] Target: %s (user: %s)", cfg.Target.DefaultAddr, cfg.Target.DefaultUser)
	log.Printf("[BOOT] Session timeout: %ds", cfg.Security.SessionTimeout)

	if err := srv.Start(ctx); err != nil {
		log.Fatalf("[BOOT] Server error: %v", err)
	}

	log.Println("[BOOT] Truthsayer stopped cleanly.")
}

func loadOrGenerateHostKey(path string) (ssh.Signer, error) {
	data, err := os.ReadFile(path)
	if err == nil {
		signer, err := ssh.ParsePrivateKey(data)
		if err != nil {
			return nil, fmt.Errorf("parse host key from %q: %w", path, err)
		}
		log.Printf("[BOOT] Loaded host key from %q", path)
		return signer, nil
	}

	if !os.IsNotExist(err) {
		return nil, fmt.Errorf("read host key file %q: %w", path, err)
	}

	log.Printf("[BOOT] Host key file %q not found — generating ephemeral RSA key (dev only)", path)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("generate ephemeral host key: %w", err)
	}
	return ssh.NewSignerFromKey(key)
}
