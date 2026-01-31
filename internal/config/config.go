// internal/config/config.go
package config

import (
	"os"
	"path/filepath"
	"strings"
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
func ExpandPath(path string) string {
	if path == "~" {
		home, _ := os.UserHomeDir()
		return home
	}
	if strings.HasPrefix(path, "~/") {
		home, _ := os.UserHomeDir()
		return filepath.Join(home, path[2:])
	}
	return path
}

// DefaultPaths returns the default XDG-compliant paths.
func DefaultPaths() Paths {
	home, _ := os.UserHomeDir()
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
