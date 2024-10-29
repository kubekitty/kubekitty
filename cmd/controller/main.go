// cmd/controller/main.go
package main

import (
	"context"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/klog/v2"

	"github.com/kubekitty/kubekitty/pkg/config"
	"github.com/kubekitty/kubekitty/pkg/controller"
)

func main() {
	var (
		kubeconfig string
		rulesDir   string
		logLevel   string
	)

	// Define flags
	flag.StringVar(&kubeconfig, "kubeconfig", "", "Path to kubeconfig file")
	flag.StringVar(&rulesDir, "rules-dir", "/etc/kubekitty/rules", "Directory containing security rules")
	flag.StringVar(&logLevel, "log-level", "info", "Log level (debug, info, warn, error)")
	klog.InitFlags(nil)

	flag.Parse()

	// Configure logging based on log level
	switch logLevel {
	case "debug":
		slog.SetLogLoggerLevel(slog.LevelDebug)
	case "info":
		slog.SetLogLoggerLevel(slog.LevelInfo)
	case "warn":
		slog.SetLogLoggerLevel(slog.LevelWarn)
	case "error":
		slog.SetLogLoggerLevel(slog.LevelError)
	default:
		slog.SetLogLoggerLevel(slog.LevelInfo)
	}

	// Set up signals for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-signalChan
		klog.Info("Received shutdown signal")
		cancel()
	}()

	// Create the kubernetes client config
	var kubeConfig *rest.Config
	var err error

	if kubeconfig == "" {
		kubeConfig, err = rest.InClusterConfig()
	} else {
		kubeConfig, err = clientcmd.BuildConfigFromFlags("", kubeconfig)
	}
	if err != nil {
		klog.Fatalf("Error building kubeconfig: %v", err)
	}

	// Create the kubernetes clientset
	clientset, err := kubernetes.NewForConfig(kubeConfig)
	if err != nil {
		klog.Fatalf("Error building kubernetes clientset: %v", err)
	}

	// Create audit configuration
	cfg := &config.AuditConfig{
		Clientset:   clientset,
		RulesDir:    rulesDir,
		AuditScopes: []string{"pods", "rbac", "network"},
		MinSeverity: "LOW",
	}

	// Create and start the controller
	controller, err := controller.NewSecurityController(cfg)
	if err != nil {
		klog.Fatalf("Error creating controller: %v", err)
	}

	klog.Infof("Starting controller with rules directory: %s", rulesDir)

	// Run the controller
	if err := controller.Run(ctx, 2); err != nil {
		klog.Fatalf("Error running controller: %v", err)
	}

	// Wait for shutdown
	<-ctx.Done()
	klog.Info("Shutting down gracefully...")
	time.Sleep(2 * time.Second) // Give time for cleanup
}
