package types

import "time"

type Finding struct {
	Severity    string            `json:"severity"`
	Category    string            `json:"category"`
	Resource    string            `json:"resource"`
	Namespace   string            `json:"namespace,omitempty"`
	Description string            `json:"description"`
	Suggestion  string            `json:"suggestion"`
	Metadata    map[string]string `json:"metadata,omitempty"`
}

type AuditReport struct {
	Timestamp   string         `json:"timestamp"`
	AuditedBy   string         `json:"auditedBy"`
	AuditedAt   time.Time      `json:"auditedAt"`
	Findings    []Finding      `json:"findings"`
	TotalIssues int            `json:"totalIssues"`
	Summary     map[string]int `json:"summary"`
}
