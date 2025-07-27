package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/goravel/framework/facades"

	"goravel/bootstrap"
)

func main() {
	// This bootstraps the framework and gets it ready for use.
	bootstrap.Boot()

	// Create a buffered channel to listen for OS signals
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	// Start http server by facades.Route().
	go func() {
		if err := facades.Route().Run(); err != nil {
			facades.Log().Errorf("Route Run error: %v", err)
		}
	}()

	// Listen for the OS signal
	go func() {
		<-quit
		facades.Log().Info("Received shutdown signal, initiating graceful shutdown...")

		// Create a context with timeout for graceful shutdown
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		// Attempt graceful shutdown
		if err := facades.Route().Shutdown(); err != nil {
			facades.Log().Errorf("Route Shutdown error: %v", err)
		} else {
			facades.Log().Info("Server shutdown completed successfully")
		}

		// Wait for context timeout or completion
		select {
		case <-ctx.Done():
			if ctx.Err() == context.DeadlineExceeded {
				facades.Log().Warning("Graceful shutdown timed out, forcing exit")
			}
		default:
			// Shutdown completed within timeout
		}

		os.Exit(0)
	}()

	select {}
}
