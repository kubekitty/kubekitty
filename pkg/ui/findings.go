package ui

import (
	"fmt"

	"github.com/afshin-deriv/kubekitty/pkg/types"
)

// PrintFinding prints a single finding with appropriate formatting
func PrintFinding(finding types.Finding) {
	severityColor := ColorForSeverity(finding.Severity)
	emoji := EmojiForSeverity(finding.Severity)

	fmt.Printf("\n%s %s: %s\n",
		emoji,
		severityColor(finding.Severity),
		warning(finding.Description))

	if finding.Resource != "" {
		fmt.Printf("   %s Resource: %s\n", GearEmoji, info(finding.Resource))
	}

	if finding.Namespace != "" {
		fmt.Printf("   %s Namespace: %s\n", FolderEmoji, info(finding.Namespace))
	}

	if finding.Suggestion != "" {
		fmt.Printf("   %s Suggestion: %s\n", MagnifierEmoji, finding.Suggestion)
	}

	if len(finding.Metadata) > 0 {
		fmt.Printf("   %s Additional Info:\n", info("ℹ️"))
		for k, v := range finding.Metadata {
			fmt.Printf("      • %s: %s\n", k, v)
		}
	}
}

// PrintSummary prints the audit summary
func PrintSummary(report types.AuditReport) {
	summaryStr := fmt.Sprintf(`
%s Audit Summary %s
%s Total Issues: %d

Severity Breakdown:
%s Critical: %d
%s High:     %d
%s Medium:   %d
%s Low:      %d

`,
		ChartEmoji, TimeEmoji,
		WarningEmoji, report.TotalIssues,
		criticalColor("■"), report.Summary["CRITICAL"],
		highColor("■"), report.Summary["HIGH"],
		mediumColor("■"), report.Summary["MEDIUM"],
		lowColor("■"), report.Summary["LOW"])

	fmt.Print(summaryStr)
}

// PrintAuditStart prints the start of an audit section
func PrintAuditStart(auditorName string) {
	fmt.Printf("\n%s Running %s\n", MagnifierEmoji, info(auditorName))
}

// PrintAuditComplete prints the completion of an audit section
func PrintAuditComplete(auditorName string, findingsCount int) {
	fmt.Printf("%s Completed %s - found %s issues\n",
		CheckEmoji,
		info(auditorName),
		warning("%d", findingsCount))
}

// PrintReportLocation prints where the report was saved
func PrintReportLocation(filepath string) {
	fmt.Printf("%s Report written to: %s\n", FolderEmoji, info(filepath))
}
