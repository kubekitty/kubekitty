package runner

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/kubekitty/kubekitty/pkg/auditors"
	"github.com/kubekitty/kubekitty/pkg/config"
	"github.com/kubekitty/kubekitty/pkg/rules"
	"github.com/kubekitty/kubekitty/pkg/types"
	"github.com/kubekitty/kubekitty/pkg/ui"
	"gopkg.in/yaml.v2"
)

// AuditRunner coordinates the security audit process
type AuditRunner struct {
	config      *config.AuditConfig
	rulesEngine *rules.RulesEngine
	auditors    []auditors.Auditor
}

// NewAuditRunner creates a new audit runner instance
func NewAuditRunner(cfg *config.AuditConfig) (*AuditRunner, error) {
	// Initialize rules engine
	rulesEngine, err := rules.NewRulesEngine(cfg.RuleFiles)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize rules engine: %v", err)
	}

	// Create base auditor
	baseAuditor := auditors.BaseAuditor{
		Client:      cfg.Clientset,
		Namespace:   cfg.Namespace,
		RulesEngine: rulesEngine,
	}

	// Initialize all auditors
	var auditorsToRun []auditors.Auditor

	// Add auditors based on configuration
	if shouldRunAuditor("pod", cfg.AuditScopes) {
		auditorsToRun = append(auditorsToRun, auditors.NewPodAuditor(baseAuditor))
	}
	if shouldRunAuditor("rbac", cfg.AuditScopes) {
		auditorsToRun = append(auditorsToRun, auditors.NewRBACauditor(baseAuditor))
	}
	if shouldRunAuditor("network", cfg.AuditScopes) {
		auditorsToRun = append(auditorsToRun, auditors.NewNetworkAuditor(baseAuditor))
	}

	return &AuditRunner{
		config:      cfg,
		rulesEngine: rulesEngine,
		auditors:    auditorsToRun,
	}, nil
}

// Run executes the security audit
func (r *AuditRunner) Run(ctx context.Context) (types.AuditReport, error) {
	report := types.AuditReport{
		Timestamp:   time.Now().UTC().Format(time.RFC3339),
		AuditedBy:   "kubekitty",
		AuditedAt:   time.Now().UTC(),
		Findings:    []types.Finding{},
		TotalIssues: 0,
		Summary:     make(map[string]int),
	}

	ui.PrintProgress("Starting security audit...")

	// Run each auditor
	for _, auditor := range r.auditors {
		select {
		case <-ctx.Done():
			return report, ctx.Err()
		default:
			ui.PrintAuditStart(auditor.Name())

			findings, err := auditor.Audit(ctx)
			if err != nil {
				ui.PrintError(fmt.Sprintf("Error in %s", auditor.Name()), err)
				continue
			}

			// Filter findings by minimum severity
			findings = filterFindingsBySeverity(findings, r.config.MinSeverity)

			// Update report
			report.Findings = append(report.Findings, findings...)
			for _, finding := range findings {
				report.Summary[finding.Severity]++
				report.TotalIssues++
			}

			ui.PrintAuditComplete(auditor.Name(), len(findings))
		}
	}

	return report, nil
}

// WriteReport writes the audit report to a file
func WriteReport(report types.AuditReport, cfg *config.AuditConfig) error {
	var data []byte
	var err error

	switch cfg.ReportFormat {
	case "json":
		data, err = json.MarshalIndent(report, "", "  ")
	case "yaml":
		data, err = yaml.Marshal(report)
	default:
		return fmt.Errorf("unsupported report format: %s", cfg.ReportFormat)
	}

	if err != nil {
		return fmt.Errorf("failed to marshal report: %v", err)
	}

	if err := os.WriteFile(cfg.OutputFile, data, 0644); err != nil {
		return fmt.Errorf("failed to write report to file: %v", err)
	}

	ui.PrintReportLocation(cfg.OutputFile)
	return nil
}

// Helper functions

// shouldRunAuditor checks if an auditor should be run based on configuration
func shouldRunAuditor(auditorName string, auditScopes []string) bool {
	if len(auditScopes) == 0 {
		return true
	}
	for _, scope := range auditScopes {
		if scope == auditorName {
			return true
		}
	}
	return false
}

// filterFindingsBySeverity filters findings based on minimum severity
func filterFindingsBySeverity(findings []types.Finding, minSeverity string) []types.Finding {
	if minSeverity == "" {
		return findings
	}

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
