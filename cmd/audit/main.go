package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/kubekitty/kubekitty/pkg/config"
	"github.com/kubekitty/kubekitty/pkg/runner"
	"github.com/kubekitty/kubekitty/pkg/ui"
)

func main() {
	// Set up context with cancellation
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle interrupt signals
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-signalChan
		ui.PrintWarning("Received interrupt signal. Gracefully shutting down...")
		cancel()
		// Give some time for cleanup before forced exit
		time.Sleep(2 * time.Second)
		os.Exit(1)
	}()

	if err := run(ctx); err != nil {
		ui.PrintError("Fatal error", err)
		os.Exit(1)
	}
}

func run(ctx context.Context) error {
	startTime := time.Now()

	// Print welcome banner
	ui.PrintStartupBanner()

	// Parse configuration
	cfg, err := config.ParseConfig()
	if err != nil {
		return fmt.Errorf("failed to parse configuration: %v", err)
	}

	// Set up logging
	if cfg.Debug {
		ui.PrintDebug("Debug mode enabled")
		log.SetFlags(log.LstdFlags | log.Lshortfile)
	}

	// Validate configuration
	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("invalid configuration: %v", err)
	}

	// Initialize the audit runner
	auditRunner, err := runner.NewAuditRunner(cfg)
	if err != nil {
		return fmt.Errorf("failed to initialize audit runner: %v", err)
	}

	// Show initialization success
	ui.PrintSuccess("Successfully initialized audit runner")

	// Create progress indicator
	progress := ui.NewProgressIndicator("Running security audit...")
	progress.Start()

	// Run the audit
	report, err := auditRunner.Run(ctx)
	progress.Stop() // Ensure progress indicator is stopped

	if err != nil {
		return fmt.Errorf("audit run failed: %v", err)
	}

	// Write the report
	if err := runner.WriteReport(report, cfg); err != nil {
		return fmt.Errorf("failed to write report: %v", err)
	}

	// Print summary
	ui.PrintSummary(report)

	// Show completion message with duration
	duration := time.Since(startTime).Round(time.Second)
	ui.PrintSuccess(fmt.Sprintf("Audit completed successfully in %s!", duration))

	return nil
}
