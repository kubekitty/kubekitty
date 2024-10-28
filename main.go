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
	"github.com/fatih/color"
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

// Define colored output functions
var (
	success    = color.New(color.FgGreen, color.Bold).SprintfFunc()
	info       = color.New(color.FgCyan, color.Bold).SprintfFunc()
	warning    = color.New(color.FgYellow, color.Bold).SprintfFunc()
	errorColor = color.New(color.FgRed, color.Bold).SprintfFunc()

	// Severity colors
	criticalColor = color.New(color.BgRed, color.FgWhite, color.Bold).SprintfFunc()
	highColor     = color.New(color.FgRed, color.Bold).SprintfFunc()
	mediumColor   = color.New(color.FgYellow, color.Bold).SprintfFunc()
	lowColor      = color.New(color.FgBlue, color.Bold).SprintfFunc()
)

// emojis for different message types
const (
	rocket    = "🚀"
	warning_  = "⚠️ "
	check     = "✅"
	cross     = "❌"
	lock      = "🔒"
	magnifier = "🔍"
	folder    = "📁"
	gear      = "⚙️ "
	chart     = "📊"
	shield    = "🛡️ "
	time_     = "⏱️ "
)

func printStartupBanner() {
	fmt.Printf(`
%s Welcome to Kubernetes Security Auditor %s
%s A comprehensive security analysis tool for your clusters %s
________________________________________________

`, lock, lock, shield, shield)
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

	fmt.Printf("\n%s Starting security audit...\n", rocket)

	for _, auditor := range auditors {
		fmt.Printf("\n%s Running %s\n", magnifier, info(auditor.Name()))

		findings, err := auditor.Audit(ctx)
		if err != nil {
			fmt.Printf("%s Error running %s: %v\n", cross, errorColor(auditor.Name()), err)
			continue
		}

		report.Findings = append(report.Findings, findings...)

		for _, finding := range findings {
			report.Summary[finding.Severity]++
			report.TotalIssues++
		}

		fmt.Printf("%s Completed %s - found %s issues\n",
			check,
			info(auditor.Name()),
			warning("%d", len(findings)))
	}

	return report
}

func printFindingSummary(finding types.Finding) {
	var severityColor func(string, ...interface{}) string
	var emoji string

	switch finding.Severity {
	case "CRITICAL":
		severityColor = criticalColor
		emoji = "🚨"
	case "HIGH":
		severityColor = highColor
		emoji = "⚠️"
	case "MEDIUM":
		severityColor = mediumColor
		emoji = "⚡"
	case "LOW":
		severityColor = lowColor
		emoji = "ℹ️"
	}

	fmt.Printf("\n%s %s: %s\n",
		emoji,
		severityColor(finding.Severity),
		warning(finding.Description))
	fmt.Printf("   %s Resource: %s\n", gear, info(finding.Resource))
	if finding.Namespace != "" {
		fmt.Printf("   %s Namespace: %s\n", folder, info(finding.Namespace))
	}
	fmt.Printf("   %s Suggestion: %s\n", magnifier, finding.Suggestion)

	if len(finding.Metadata) > 0 {
		fmt.Printf("   %s Additional Info:\n", info("ℹ️"))
		for k, v := range finding.Metadata {
			fmt.Printf("      • %s: %s\n", k, v)
		}
	}
}

func writeReport(report types.AuditReport, outputFile string) error {
	// Create colorful summary
	summaryStr := fmt.Sprintf(`
%s Audit Summary %s
%s Total Issues: %d

Severity Breakdown:
%s Critical: %d
%s High:     %d
%s Medium:   %d
%s Low:      %d

`,
		chart, time_,
		warning_, report.TotalIssues,
		criticalColor("■"), report.Summary["CRITICAL"],
		highColor("■"), report.Summary["HIGH"],
		mediumColor("■"), report.Summary["MEDIUM"],
		lowColor("■"), report.Summary["LOW"])

	fmt.Println(summaryStr)

	// Marshal report to JSON
	reportJSON, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("%s error marshaling report: %v", cross, err)
	}

	// Write to file
	if err := os.WriteFile(outputFile, reportJSON, 0644); err != nil {
		return fmt.Errorf("%s error writing report to file: %v", cross, err)
	}

	fmt.Printf("%s Report written to: %s\n", folder, info(outputFile))
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
	printStartupBanner()

	cfg := parseFlags()

	if cfg.Debug {
		fmt.Printf("%s Debug mode enabled\n", gear)
		log.SetFlags(log.LstdFlags | log.Lshortfile)
	}

	client, err := initializeClient(cfg)
	if err != nil {
		fmt.Printf("%s %s\n", cross, errorColor("Error initializing Kubernetes client: %v", err))
		os.Exit(1)
	}

	fmt.Printf("%s Successfully connected to Kubernetes cluster\n", check)

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

	if cfg.Namespace != "" {
		fmt.Printf("%s Auditing namespace: %s\n", folder, info(cfg.Namespace))
	} else {
		fmt.Printf("%s Auditing all namespaces\n", folder)
	}

	// Run audits
	report := runAudits(context.Background(), auditorsToRun)

	// Filter findings by minimum severity if specified
	if cfg.MinSeverity != "" {
		fmt.Printf("\n%s Filtering findings by minimum severity: %s\n",
			magnifier,
			warning(cfg.MinSeverity))
		report.Findings = filterFindingsBySeverity(report.Findings, cfg.MinSeverity)
	}

	// Write report
	if err := writeReport(report, cfg.OutputFile); err != nil {
		fmt.Printf("%s %s\n", cross, error(err))
		os.Exit(1)
	}
	// Print detailed findings if requested
	if cfg.Debug {
		fmt.Printf("\n%s Detailed Findings:\n", magnifier)
		for _, finding := range report.Findings {
			printFindingSummary(finding)
		}
	}

	fmt.Printf("\n%s Audit completed successfully! %s\n", rocket, check)

}
