package config

import (
	"fmt"
	"strings"

	"github.com/spf13/viper"
)

// Config holds all application settings loaded from file and environment variables.
// Struct tags are used by the Viper mapstructure decoder.
type Config struct {
	Server   `mapstructure:"server"`
	Target   `mapstructure:"target"`
	Security `mapstructure:"security"`
	Audit    `mapstructure:"audit"`
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

type Security struct {
	Blacklist      []string `mapstructure:"blacklist"`
	SessionTimeout int      `mapstructure:"session_timeout"`
}

type Audit struct {
	StoragePath string `mapstructure:"storage_path"`
	LogLevel    string `mapstructure:"log_level"`
}

// Load reads configuration from a file and allows environment variables to override any value.
func Load(configPath string) (*Config, error) {
	v := viper.New()

	// 1. Set config file parameters.
	v.SetConfigFile(configPath)
	v.SetConfigType("yaml")

	// 2. Enable automatic environment variable binding.
	v.AutomaticEnv()
	// Replace dots with underscores in env key names (e.g. server.port → SERVER_PORT).
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))

	// 3. Bind explicit environment variable names.
	v.BindEnv("server.port", "TRUTHSAYER_PORT")
	v.BindEnv("server.host", "TRUTHSAYER_HOST")
	v.BindEnv("server.host_key_path", "TRUTHSAYER_HOST_KEY")
	v.BindEnv("target.default_addr", "TARGET_ADDR")
	v.BindEnv("target.default_user", "TARGET_USER")
	v.BindEnv("audit.storage_path", "AUDIT_STORAGE")
	v.BindEnv("audit.log_level", "LOG_LEVEL")

	// 4. Apply default values.
	setDefaults(v)

	// 5. Read the config file. If missing, fall back to env vars and defaults.
	if err := v.ReadInConfig(); err != nil {
		// Ignore "file not found" — containers may rely entirely on env vars.
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return nil, fmt.Errorf("failed to read config file: %w", err)
		}
	}

	var cfg Config
	// Unmarshal Viper values into the Config struct.
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	return &cfg, nil
}

// setDefaults defines baseline values for all configuration parameters.
func setDefaults(v *viper.Viper) {
	v.SetDefault("server.port", 2222)
	v.SetDefault("server.host", "0.0.0.0")
	v.SetDefault("server.host_key_path", "host_key")
	v.SetDefault("target.default_addr", "127.0.0.1:22")
	v.SetDefault("security.session_timeout", 3600)
	v.SetDefault("audit.storage_path", "./logs/sessions")
	v.SetDefault("audit.log_level", "info")
}
