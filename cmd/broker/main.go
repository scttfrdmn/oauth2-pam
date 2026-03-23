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
	configPath  = flag.String("config", "/etc/oauth2-pam/broker.yaml", "Path to configuration file")
	logLevel    = flag.String("log-level", "info", "Log level (debug, info, warn, error)")
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
