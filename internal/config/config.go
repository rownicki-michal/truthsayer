package config

import (
	"fmt"
	"strings"

	"errors"
	"os"

	"github.com/spf13/viper"
)

// Config holds all application settings loaded from file and environment variables.
// Struct tags are used by the Viper mapstructure decoder.
type Config struct {
	Server   Server   `mapstructure:"server"`
	Target   Target   `mapstructure:"target"`
	Auth     Auth     `mapstructure:"auth"`
	Limits   Limits   `mapstructure:"limits"`
	Security Security `mapstructure:"security"`
	Audit    Audit    `mapstructure:"audit"`
}

type Server struct {
	Port        int    `mapstructure:"port"`
	Host        string `mapstructure:"host"`
	HostKeyPath string `mapstructure:"host_key_path"`
}

type Target struct {
	DefaultAddr string `mapstructure:"default_addr"`
	DefaultUser string `mapstructure:"default_user"`
}

// Auth holds credentials for clients connecting to the bastion.
// TODO (Phase 4): Replace with LDAP/OIDC via internal/identity.
type Auth struct {
	Users map[string]string `mapstructure:"users"` // username -> password
}

// Limits controls maximum concurrency for connections and channels.
type Limits struct {
	MaxConnections     int `mapstructure:"max_connections"`
	MaxChannelsPerConn int `mapstructure:"max_channels_per_conn"`
}

// Security holds command filtering configuration.
type Security struct {
	Blacklist      []string `mapstructure:"blacklist"`
	SessionTimeout int      `mapstructure:"session_timeout"`

	// OnBlock controls what happens when a command is blocked by the filter.
	// "message"    — session continues, client receives an error message (default)
	// "disconnect" — session is terminated immediately
	OnBlock string `mapstructure:"on_block"`
}

type Audit struct {
	StoragePath string `mapstructure:"storage_path"`
	LogLevel    string `mapstructure:"log_level"`
}

// Load reads configuration from a file and allows environment variables to override any value.
func Load(configPath string) (*Config, error) {
	v := viper.New()

	v.SetConfigFile(configPath)
	v.SetConfigType("yaml")

	v.AutomaticEnv()
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))

	v.BindEnv("server.port", "TRUTHSAYER_PORT")
	v.BindEnv("server.host", "TRUTHSAYER_HOST")
	v.BindEnv("server.host_key_path", "TRUTHSAYER_HOST_KEY")
	v.BindEnv("target.default_addr", "TARGET_ADDR")
	v.BindEnv("target.default_user", "TARGET_USER")
	v.BindEnv("audit.storage_path", "AUDIT_STORAGE")
	v.BindEnv("audit.log_level", "LOG_LEVEL")

	setDefaults(v)

	if err := v.ReadInConfig(); err != nil {
		if !isNotFound(err) {
			return nil, fmt.Errorf("failed to read config file: %w", err)
		}
	}

	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	return &cfg, nil
}

// isNotFound returns true when err indicates the config file does not exist.
func isNotFound(err error) bool {
	if _, ok := err.(viper.ConfigFileNotFoundError); ok {
		return true
	}
	var pathErr *os.PathError
	return errors.As(err, &pathErr) && os.IsNotExist(pathErr)
}

// setDefaults defines baseline values for all configuration parameters.
func setDefaults(v *viper.Viper) {
	v.SetDefault("server.port", 2222)
	v.SetDefault("server.host", "0.0.0.0")
	v.SetDefault("server.host_key_path", "host_key")
	v.SetDefault("target.default_addr", "127.0.0.1:22")
	v.SetDefault("limits.max_connections", 100)
	v.SetDefault("limits.max_channels_per_conn", 10)
	v.SetDefault("security.session_timeout", 3600)
	v.SetDefault("security.on_block", "message")
	v.SetDefault("audit.storage_path", "./logs/sessions")
	v.SetDefault("audit.log_level", "info")
	v.SetDefault("auth.users", map[string]string{})
}
