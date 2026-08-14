package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/scttfrdmn/oauth2-pam/internal/ipc"
	"github.com/scttfrdmn/oauth2-pam/pkg/auth"
	"github.com/scttfrdmn/oauth2-pam/pkg/config"
)

var (
	version   = "dev"
	buildDate = "unknown"
	gitCommit = "unknown"
)

var (
	configPath = flag.String("config", "/etc/oauth2-pam/broker.yaml", "Path to configuration file")
	// The flag overrides server.log_level, and only when it is actually given —
	// see the call after LoadConfig. Its default is what the startup lines before
	// the config has been read are logged at.
	logLevel = flag.String("log-level", "info", "Log level (debug, info, warn, error); overrides server.log_level")

	showVersion = flag.Bool("version", false, "Show version information")
)

func main() {
	flag.Parse()

	if *showVersion {
		fmt.Printf("oauth2-pam-broker version %s\n", version)
		fmt.Printf("  Build date: %s\n", buildDate)
		fmt.Printf("  Git commit: %s\n", gitCommit)
		os.Exit(0)
	}

	setupLogging(*logLevel)

	log.Info().
		Str("version", version).
		Str("config", *configPath).
		Msg("Starting oauth2-pam Authentication Broker")

	// Load and validate configuration
	cfg, err := config.LoadConfig(*configPath)
	if err != nil {
		log.Fatal().Err(err).Str("config", *configPath).Msg("Failed to load configuration")
	}
	if err := cfg.Validate(); err != nil {
		log.Fatal().Err(err).Msg("Invalid configuration")
	}

	// server.log_level applies from here on. It could not be applied earlier —
	// nothing knows what it says until the config has been read — so the lines
	// above are at the flag's default, and the flag wins outright when it was given
	// on the command line: --log-level=debug is for one run of a broker whose
	// config says info, and it would be no use if the config could take it back.
	// Until v0.4.0 there was no override to speak of, because server.log_level was
	// read by nothing and the flag was the only input.
	if !flagWasGiven("log-level") && cfg.Server.LogLevel != "" {
		setupLogging(cfg.Server.LogLevel)
	}

	// Where each secret came from, never the secret. An operator who has just
	// moved a secret into a systemd credential or a file needs to see that the
	// broker actually read it from there and is not still using an inline copy.
	for _, p := range cfg.Providers {
		log.Info().
			Str("provider", p.Name).
			Str("client_secret_from", string(p.SecretSource())).
			Msg("Provider configured")
	}

	// Create broker
	broker, err := auth.NewBroker(cfg)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to create authentication broker")
	}

	// Create IPC server
	ipcServer, err := ipc.NewServer(cfg.Server.SocketPath, broker, cfg)
	if err != nil {
		log.Fatal().Err(err).Str("socket", cfg.Server.SocketPath).Msg("Failed to create IPC server")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := broker.Start(ctx); err != nil {
		log.Fatal().Err(err).Msg("Failed to start broker")
	}
	if err := ipcServer.Start(ctx); err != nil {
		log.Fatal().Err(err).Msg("Failed to start IPC server")
	}

	log.Info().
		Str("socket", cfg.Server.SocketPath).
		Msg("oauth2-pam broker ready")

	// Wait for shutdown signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	log.Info().Msg("Shutdown signal received, draining...")
	cancel()

	done := make(chan struct{})
	go func() {
		defer close(done)
		if err := ipcServer.Stop(); err != nil {
			log.Error().Err(err).Msg("Error stopping IPC server")
		}
		if err := broker.Stop(); err != nil {
			log.Error().Err(err).Msg("Error stopping broker")
		}
	}()

	select {
	case <-done:
		log.Info().Msg("Graceful shutdown complete")
	case <-time.After(30 * time.Second):
		log.Warn().Msg("Shutdown timeout exceeded, forcing exit")
	}
}

// flagWasGiven reports whether the named flag appeared on the command line, as
// opposed to sitting at its default. flag.Visit walks only what was set, which is
// the difference between "the operator asked for info" and "nobody said".
func flagWasGiven(name string) bool {
	given := false
	flag.Visit(func(f *flag.Flag) {
		if f.Name == name {
			given = true
		}
	})
	return given
}

func setupLogging(level string) {
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix

	lvl, err := zerolog.ParseLevel(level)
	if err != nil {
		log.Fatal().Err(err).Str("level", level).Msg("Invalid log level")
	}
	zerolog.SetGlobalLevel(lvl)

	if os.Getenv("OAUTH2_PAM_DEV") == "true" {
		log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})
	}
}
