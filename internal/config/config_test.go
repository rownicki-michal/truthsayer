package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoad(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	t.Run("loads default values when file does not exist", func(t *testing.T) {
		os.Clearenv()

		// Non-existent file — setDefaults() values must apply.
		cfg, err := Load("config.yaml.")

		require.NoError(t, err)
		assert.Equal(t, 2222, cfg.Server.Port)
		assert.Equal(t, "0.0.0.0", cfg.Server.Host)
		assert.Equal(t, "info", cfg.Audit.LogLevel)
	})

	t.Run("loads values from YAML file", func(t *testing.T) {
		os.Clearenv()

		yamlContent := `
server:
  port: 8080
  host: "127.0.0.1"
audit:
  log_level: "debug"
`
		err := os.WriteFile(configPath, []byte(yamlContent), 0644)
		require.NoError(t, err)

		cfg, err := Load(configPath)

		require.NoError(t, err)
		assert.Equal(t, 8080, cfg.Server.Port)
		assert.Equal(t, "127.0.0.1", cfg.Server.Host)
		assert.Equal(t, "debug", cfg.Audit.LogLevel)
	})

	t.Run("environment variables override file values", func(t *testing.T) {
		os.Clearenv()

		yamlContent := `
server:
  port: 8080
`
		err := os.WriteFile(configPath, []byte(yamlContent), 0644)
		require.NoError(t, err)

		os.Setenv("TRUTHSAYER_PORT", "9999")
		os.Setenv("LOG_LEVEL", "warn")

		cfg, err := Load(configPath)

		require.NoError(t, err)
		// Env port (9999) must win over file port (8080).
		assert.Equal(t, 9999, cfg.Server.Port)
		// Env log level must win over the default.
		assert.Equal(t, "warn", cfg.Audit.LogLevel)
	})

	t.Run("returns error on invalid YAML", func(t *testing.T) {
		os.Clearenv()

		err := os.WriteFile(configPath, []byte("server: port: [invalid yaml"), 0644)
		require.NoError(t, err)

		_, err = Load(configPath)
		assert.Error(t, err)
	})
}
