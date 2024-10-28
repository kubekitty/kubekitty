package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/afshin-deriv/k8s-auditor/pkg/auditors"
	"github.com/afshin-deriv/k8s-auditor/pkg/types"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/homedir"
)

type Config struct {
	Kubeconfig    string
	Namespace     string
	OutputFile    string
	Debug         bool
	MinSeverity   string
	Format        string
	IncludeSystem bool
}

func parseFlags() *Config {
	cfg := &Config{}

	// Set up kubeconfig flag
	if home := homedir.HomeDir(); home != "" {
		flag.StringVar(&cfg.Kubeconfig, "kubeconfig", filepath.Join(home, ".kube", "config"),
			"(optional) absolute path to the kubeconfig file")
	} else {
		flag.StringVar(&cfg.Kubeconfig, "kubeconfig", "", "absolute path to the kubeconfig file")
	}

	// Other configuration flags
	flag.StringVar(&cfg.Namespace, "namespace", "", "namespace to audit (default: all namespaces)")
	flag.StringVar(&cfg.OutputFile, "output", "audit-report.json", "output file for audit results")
	flag.StringVar(&cfg.MinSeverity, "min-severity", "LOW", "minimum severity to report (LOW, MEDIUM, HIGH, CRITICAL)")
	flag.StringVar(&cfg.Format, "format", "json", "output format (json, yaml)")
	flag.BoolVar(&cfg.Debug, "debug", false, "enable debug logging")
	flag.BoolVar(&cfg.IncludeSystem, "include-system", false, "include system namespaces in audit")

	flag.Parse()
	return cfg
}

func initializeClient(cfg *Config) (*kubernetes.Clientset, error) {
	// Build configuration from kubeconfig file
	config, err := clientcmd.BuildConfigFromFlags("", cfg.Kubeconfig)
	if err != nil {
		return nil, fmt.Errorf("error building kubeconfig: %v", err)
	}

	// Create the clientset
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("error creating kubernetes client: %v", err)
	}

	return clientset, nil
}

func runAudits(ctx context.Context, auditors []auditors.Auditor) types.AuditReport {
	report := types.AuditReport{
		Timestamp:   time.Now().UTC().Format(time.RFC3339),
		Findings:    []types.Finding{},
		AuditedBy:   "k8s-auditor",
		AuditedAt:   time.Now().UTC(),
		TotalIssues: 0,
		Summary:     make(map[string]int),
	}

	// Run each auditor
	for _, auditor := range auditors {
		log.Printf("Running %s...", auditor.Name())

		findings, err := auditor.Audit(ctx)
		if err != nil {
			log.Printf("Error running %s: %v", auditor.Name(), err)
			continue
		}

		// Add findings to report
		report.Findings = append(report.Findings, findings...)

		// Update summary
		for _, finding := range findings {
			report.Summary[finding.Severity]++
			report.TotalIssues++
		}

		log.Printf("Completed %s - found %d issues", auditor.Name(), len(findings))
	}

	return report
}

func writeReport(report types.AuditReport, outputFile string) error {
	// Create summary
	summary := fmt.Sprintf("\nAudit Summary:\n"+
		"Total Issues: %d\n"+
		"Critical: %d\n"+
		"High: %d\n"+
		"Medium: %d\n"+
		"Low: %d\n",
		report.TotalIssues,
		report.Summary["CRITICAL"],
		report.Summary["HIGH"],
		report.Summary["MEDIUM"],
		report.Summary["LOW"])

	// Print summary to console
	fmt.Println(summary)

	// Marshal report to JSON
	reportJSON, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("error marshaling report: %v", err)
	}

	// Write to file
	if err := os.WriteFile(outputFile, reportJSON, 0644); err != nil {
		return fmt.Errorf("error writing report to file: %v", err)
	}

	log.Printf("Report written to %s", outputFile)
	return nil
}

// Helper function to filter findings by severity
func filterFindingsBySeverity(findings []types.Finding, minSeverity string) []types.Finding {
	severityLevel := map[string]int{
		"LOW":      0,
		"MEDIUM":   1,
		"HIGH":     2,
		"CRITICAL": 3,
	}

	minLevel := severityLevel[minSeverity]
	var filtered []types.Finding

	for _, finding := range findings {
		if severityLevel[finding.Severity] >= minLevel {
			filtered = append(filtered, finding)
		}
	}

	return filtered
}

func main() {
	// Parse command line flags
	cfg := parseFlags()

	// Enable debug logging if requested
	if cfg.Debug {
		log.SetFlags(log.LstdFlags | log.Lshortfile)
	}

	// Initialize Kubernetes client
	client, err := initializeClient(cfg)
	if err != nil {
		log.Fatalf("Error initializing Kubernetes client: %v", err)
	}

	// Create audit context
	ctx := context.Background()

	// Create base auditor configuration
	baseAuditor := auditors.BaseAuditor{
		Client:    client,
		Namespace: cfg.Namespace,
	}

	// Initialize auditors
	auditorsToRun := []auditors.Auditor{
		auditors.NewPodAuditor(baseAuditor),
		auditors.NewRBACauditor(baseAuditor),
		auditors.NewNetworkAuditor(baseAuditor),
	}

	log.Printf("Starting security audit...")
	if cfg.Namespace != "" {
		log.Printf("Auditing namespace: %s", cfg.Namespace)
	} else {
		log.Printf("Auditing all namespaces")
	}

	// Run audits
	report := runAudits(ctx, auditorsToRun)

	// Filter findings by minimum severity if specified
	if cfg.MinSeverity != "" {
		report.Findings = filterFindingsBySeverity(report.Findings, cfg.MinSeverity)
	}

	// Write report
	if err := writeReport(report, cfg.OutputFile); err != nil {
		log.Fatalf("Error writing report: %v", err)
	}
}
