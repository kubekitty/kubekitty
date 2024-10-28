package report

import (
	"encoding/json"

	"github.com/afshin-deriv/k8s-auditor/pkg/types"
)

type Formatter interface {
	Format(report types.AuditReport) ([]byte, error)
}

type JSONFormatter struct{}

func (f *JSONFormatter) Format(report types.AuditReport) ([]byte, error) {
	return json.MarshalIndent(report, "", "  ")
}
