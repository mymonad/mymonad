// internal/config/config.go
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	toml "github.com/pelletier/go-toml/v2"
)

// Paths holds XDG-compliant paths for MyMonad.
type Paths struct {
	ConfigDir    string // ~/.config/mymonad
	DataDir      string // ~/.local/share/mymonad
	IngestSocket string // ~/.local/share/mymonad/ingest.sock
	AgentSocket  string // ~/.local/share/mymonad/agent.sock
	IdentityPath string // ~/.local/share/mymonad/identity.key
	MonadPath    string // ~/.local/share/mymonad/monad.bin
	PeersCache   string // ~/.local/share/mymonad/peers.json
}

// ExpandPath expands ~ to the user's home directory.
// Returns the path unchanged if it doesn't start with ~.
// Panics if home directory cannot be determined when ~ expansion is needed.
func ExpandPath(path string) string {
	if path == "~" {
		home, err := os.UserHomeDir()
		if err != nil {
			panic(fmt.Sprintf("failed to get home directory: %v", err))
		}
		return home
	}
	if strings.HasPrefix(path, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			panic(fmt.Sprintf("failed to get home directory: %v", err))
		}
		return filepath.Join(home, path[2:])
	}
	return path
}

// DefaultPaths returns the default XDG-compliant paths.
// Panics if the user's home directory cannot be determined.
func DefaultPaths() Paths {
	home, err := os.UserHomeDir()
	if err != nil {
		panic(fmt.Sprintf("failed to get home directory: %v", err))
	}
	configDir := filepath.Join(home, ".config", "mymonad")
	dataDir := filepath.Join(home, ".local", "share", "mymonad")

	return Paths{
		ConfigDir:    configDir,
		DataDir:      dataDir,
		IngestSocket: filepath.Join(dataDir, "ingest.sock"),
		AgentSocket:  filepath.Join(dataDir, "agent.sock"),
		IdentityPath: filepath.Join(dataDir, "identity.key"),
		MonadPath:    filepath.Join(dataDir, "monad.bin"),
		PeersCache:   filepath.Join(dataDir, "peers.json"),
	}
}

// EnsureDirectories creates config and data directories if they don't exist.
func (p Paths) EnsureDirectories() error {
	if err := os.MkdirAll(p.ConfigDir, 0700); err != nil {
		return err
	}
	return os.MkdirAll(p.DataDir, 0700)
}

// IngestConfig holds configuration for mymonad-ingest.
type IngestConfig struct {
	Watch   WatchConfig   `toml:"watch"`
	Ollama  OllamaConfig  `toml:"ollama"`
	Storage StorageConfig `toml:"storage"`
}

// WatchConfig holds file watching settings.
type WatchConfig struct {
	Directories  []string `toml:"directories"`
	Extensions   []string `toml:"extensions"`
	IgnoreHidden bool     `toml:"ignore_hidden"`
}

// OllamaConfig holds Ollama API settings.
type OllamaConfig struct {
	URL            string `toml:"url"`
	Model          string `toml:"model"`
	TimeoutSeconds int    `toml:"timeout_seconds"`
}

// StorageConfig holds storage paths.
type StorageConfig struct {
	MonadPath string `toml:"monad_path"`
}

// AgentConfig holds configuration for mymonad-agent.
type AgentConfig struct {
	Network   NetworkConfig   `toml:"network"`
	Discovery DiscoveryConfig `toml:"discovery"`
	Protocol  ProtocolConfig  `toml:"protocol"`
	Storage   AgentStorage    `toml:"storage"`
}

// NetworkConfig holds P2P network settings.
type NetworkConfig struct {
	Port       int    `toml:"port"`
	ExternalIP string `toml:"external_ip"`
}

// DiscoveryConfig holds peer discovery settings.
type DiscoveryConfig struct {
	DNSSeeds    []string `toml:"dns_seeds"`
	Bootstrap   []string `toml:"bootstrap"`
	MDNSEnabled bool     `toml:"mdns_enabled"`
}

// ProtocolConfig holds protocol parameters.
type ProtocolConfig struct {
	SimilarityThreshold float64 `toml:"similarity_threshold"`
	ChallengeDifficulty int     `toml:"challenge_difficulty"`
}

// AgentStorage holds agent storage paths.
type AgentStorage struct {
	IdentityPath string `toml:"identity_path"`
	PeersCache   string `toml:"peers_cache"`
}

// DefaultIngestConfig returns an IngestConfig with sensible defaults.
func DefaultIngestConfig() IngestConfig {
	paths := DefaultPaths()
	return IngestConfig{
		Watch: WatchConfig{
			Directories:  []string{},
			Extensions:   []string{".txt", ".md"},
			IgnoreHidden: true,
		},
		Ollama: OllamaConfig{
			URL:            "http://localhost:11434",
			Model:          "nomic-embed-text",
			TimeoutSeconds: 30,
		},
		Storage: StorageConfig{
			MonadPath: paths.MonadPath,
		},
	}
}

// DefaultAgentConfig returns an AgentConfig with sensible defaults.
func DefaultAgentConfig() AgentConfig {
	paths := DefaultPaths()
	return AgentConfig{
		Network: NetworkConfig{
			Port: 4001,
		},
		Discovery: DiscoveryConfig{
			DNSSeeds:    []string{},
			Bootstrap:   []string{},
			MDNSEnabled: true,
		},
		Protocol: ProtocolConfig{
			SimilarityThreshold: 0.85,
			ChallengeDifficulty: 16,
		},
		Storage: AgentStorage{
			IdentityPath: paths.IdentityPath,
			PeersCache:   paths.PeersCache,
		},
	}
}

// LoadIngestConfig loads an IngestConfig from a TOML file.
// Paths with ~ are expanded to the user's home directory.
func LoadIngestConfig(path string) (*IngestConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	cfg := DefaultIngestConfig()
	if err := toml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse TOML: %w", err)
	}

	// Expand paths in directories
	for i, dir := range cfg.Watch.Directories {
		cfg.Watch.Directories[i] = ExpandPath(dir)
	}

	// Expand storage path
	cfg.Storage.MonadPath = ExpandPath(cfg.Storage.MonadPath)

	return &cfg, nil
}

// LoadAgentConfig loads an AgentConfig from a TOML file.
// Paths with ~ are expanded to the user's home directory.
func LoadAgentConfig(path string) (*AgentConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	cfg := DefaultAgentConfig()
	if err := toml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse TOML: %w", err)
	}

	// Expand storage paths
	cfg.Storage.IdentityPath = ExpandPath(cfg.Storage.IdentityPath)
	cfg.Storage.PeersCache = ExpandPath(cfg.Storage.PeersCache)

	return &cfg, nil
}
