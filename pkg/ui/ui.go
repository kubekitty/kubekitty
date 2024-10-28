package ui

import (
	"fmt"

	"github.com/fatih/color"
)

// Color definitions
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

// Emoji constants
const (
	RocketEmoji    = "🚀"
	WarningEmoji   = "⚠️"
	CheckEmoji     = "✅"
	CrossEmoji     = "❌"
	LockEmoji      = "🔒"
	MagnifierEmoji = "🔍"
	FolderEmoji    = "📁"
	GearEmoji      = "⚙️"
	ChartEmoji     = "📊"
	ShieldEmoji    = "🛡️"
	TimeEmoji      = "⏱️"
)

// PrintStartupBanner prints the application startup banner
func PrintStartupBanner() {
	fmt.Printf(`
%s Kubernetes Security Auditor %s
%s A comprehensive security analysis tool for your clusters %s
________________________________________________

`, LockEmoji, LockEmoji, ShieldEmoji, ShieldEmoji)
}

// PrintProgress prints a progress message
func PrintProgress(message string) {
	fmt.Printf("%s %s\n", MagnifierEmoji, info(message))
}

// PrintError prints an error message
func PrintError(message string, err error) {
	fmt.Printf("%s %s: %v\n", CrossEmoji, errorColor(message), err)
}

// PrintSuccess prints a success message
func PrintSuccess(message string) {
	fmt.Printf("%s %s\n", CheckEmoji, success(message))
}

// PrintWarning prints a warning message
func PrintWarning(message string) {
	fmt.Printf("%s %s\n", WarningEmoji, warning(message))
}

// PrintDebug prints a debug message
func PrintDebug(message string) {
	fmt.Printf("%s %s\n", GearEmoji, info(message))
}

// ColorForSeverity returns the appropriate color function for a severity level
func ColorForSeverity(severity string) func(string, ...interface{}) string {
	switch severity {
	case "CRITICAL":
		return criticalColor
	case "HIGH":
		return highColor
	case "MEDIUM":
		return mediumColor
	case "LOW":
		return lowColor
	default:
		return info
	}
}

// EmojiForSeverity returns the appropriate emoji for a severity level
func EmojiForSeverity(severity string) string {
	switch severity {
	case "CRITICAL":
		return "🚨"
	case "HIGH":
		return WarningEmoji
	case "MEDIUM":
		return "⚡"
	case "LOW":
		return "ℹ️"
	default:
		return MagnifierEmoji
	}
}
