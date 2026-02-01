package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/mymonad/mymonad/internal/config"
)

func main() {
	// Define command-line flags
	configPath := flag.String("config", "", "Path to TOML configuration file")
	port := flag.Int("port", 0, "P2P listen port (default: 4001, 0 for random)")
	bootstrap := flag.String("bootstrap", "", "Comma-separated list of bootstrap multiaddrs")
	dnsSeeds := flag.String("dns-seeds", "", "Comma-separated list of DNSADDR DNS names")
	mdns := flag.Bool("mdns", true, "Enable mDNS local peer discovery")
	ingestSocket := flag.String("ingest-socket", "", "Path to ingest daemon socket")
	socketPath := flag.String("socket", "", "Unix socket path for IPC (default: ~/.local/share/mymonad/agent.sock)")
	logLevel := flag.String("log-level", "info", "Log level: debug, info, warn, error")

	flag.Parse()

	// Set up logger based on log level
	var level slog.Level
	switch strings.ToLower(*logLevel) {
	case "debug":
		level = slog.LevelDebug
	case "info":
		level = slog.LevelInfo
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		level = slog.LevelInfo
	}

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: level,
	}))
	slog.SetDefault(logger)

	// Parse bootstrap and DNS seeds
	var bootstrapAddrs []string
	if *bootstrap != "" {
		bootstrapAddrs = strings.Split(*bootstrap, ",")
		for i, addr := range bootstrapAddrs {
			bootstrapAddrs[i] = strings.TrimSpace(addr)
		}
	}

	var dnsSeedsList []string
	if *dnsSeeds != "" {
		dnsSeedsList = strings.Split(*dnsSeeds, ",")
		for i, seed := range dnsSeedsList {
			dnsSeedsList[i] = strings.TrimSpace(seed)
		}
	}

	// Build configuration
	cfg, err := buildConfig(*configPath, *port, bootstrapAddrs, dnsSeedsList, *mdns, *ingestSocket, *socketPath)
	if err != nil {
		logger.Error("failed to build configuration", "error", err)
		os.Exit(1)
	}

	// Ensure directories exist
	paths := config.DefaultPaths()
	if err := paths.EnsureDirectories(); err != nil {
		logger.Error("failed to create directories", "error", err)
		os.Exit(1)
	}

	// Create daemon
	daemon, err := NewDaemon(cfg)
	if err != nil {
		logger.Error("failed to create daemon", "error", err)
		os.Exit(1)
	}

	// Set up signal handling
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		sig := <-sigCh
		logger.Info("received signal, shutting down", "signal", sig.String())
		cancel()
	}()

	// Run daemon
	logger.Info("starting mymonad-agent daemon",
		"port", cfg.Port,
		"socket", cfg.SocketPath,
		"mdns", cfg.MDNSEnabled,
		"bootstrap", cfg.Bootstrap,
		"dns_seeds", cfg.DNSSeeds,
	)

	if err := daemon.Run(ctx); err != nil && err != context.Canceled {
		logger.Error("daemon error", "error", err)
		os.Exit(1)
	}

	logger.Info("daemon stopped gracefully")
}

// buildConfig creates a DaemonConfig from file and/or flags.
// Flags override file settings.
func buildConfig(configPath string, port int, bootstrap, dnsSeeds []string, mdns bool, ingestSocket, socketPath string) (DaemonConfig, error) {
	var cfg DaemonConfig

	// Load from file if provided
	if configPath != "" {
		fileCfg, err := config.LoadAgentConfig(configPath)
		if err != nil {
			return cfg, fmt.Errorf("failed to load config file: %w", err)
		}

		// Map config file to DaemonConfig
		paths := config.DefaultPaths()
		cfg = DaemonConfig{
			SocketPath:          paths.AgentSocket,
			IdentityPath:        fileCfg.Storage.IdentityPath,
			Port:                fileCfg.Network.Port,
			DNSSeeds:            fileCfg.Discovery.DNSSeeds,
			Bootstrap:           fileCfg.Discovery.Bootstrap,
			MDNSEnabled:         fileCfg.Discovery.MDNSEnabled,
			SimilarityThreshold: fileCfg.Protocol.SimilarityThreshold,
			ChallengeDifficulty: fileCfg.Protocol.ChallengeDifficulty,
			IngestSocket:        paths.IngestSocket,
		}
	} else {
		// Start with defaults
		cfg = DefaultDaemonConfig()
	}

	// Override with flags (only if explicitly set)
	if port != 0 {
		cfg.Port = port
	}

	if len(bootstrap) > 0 {
		cfg.Bootstrap = bootstrap
	}

	if len(dnsSeeds) > 0 {
		cfg.DNSSeeds = dnsSeeds
	}

	// mdns flag - check if it was explicitly set to false
	// Since the default is true and flag.Bool returns true by default,
	// we only override if the flag was explicitly provided
	if !mdns {
		cfg.MDNSEnabled = false
	}

	if ingestSocket != "" {
		cfg.IngestSocket = ingestSocket
	}

	if socketPath != "" {
		cfg.SocketPath = socketPath
	}

	// Validate final config
	if err := cfg.Validate(); err != nil {
		return cfg, fmt.Errorf("invalid configuration: %w", err)
	}

	return cfg, nil
}
