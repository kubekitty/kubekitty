package report

import (
	"bytes"
	"encoding/json"
	"fmt"
	"text/template"

	"github.com/afshin-deriv/kubekitty/pkg/types"
	"gopkg.in/yaml.v2"
)

// ReportFormatter handles report formatting
type ReportFormatter interface {
	Format(report types.AuditReport) ([]byte, error)
}

// JSONFormatter formats reports as JSON
type JSONFormatter struct {
	PrettyPrint bool
}

func (f *JSONFormatter) Format(report types.AuditReport) ([]byte, error) {
	if f.PrettyPrint {
		return json.MarshalIndent(report, "", "  ")
	}
	return json.Marshal(report)
}

// YAMLFormatter formats reports as YAML
type YAMLFormatter struct{}

func (f *YAMLFormatter) Format(report types.AuditReport) ([]byte, error) {
	return yaml.Marshal(report)
}

// HTMLFormatter formats reports as HTML
type HTMLFormatter struct {
	Template string
}

func (f *HTMLFormatter) Format(report types.AuditReport) ([]byte, error) {
	tmpl, err := template.New("report").Parse(f.Template)
	if err != nil {
		return nil, err
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, report); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

// GetFormatter returns the appropriate formatter based on format string
func GetFormatter(format string, prettyPrint bool) (ReportFormatter, error) {
	switch format {
	case "json":
		return &JSONFormatter{PrettyPrint: prettyPrint}, nil
	case "yaml":
		return &YAMLFormatter{}, nil
	case "html":
		return &HTMLFormatter{Template: defaultHTMLTemplate}, nil
	default:
		return nil, fmt.Errorf("unsupported format: %s", format)
	}
}

// Default HTML template for report formatting
const defaultHTMLTemplate = `
<!DOCTYPE html>
<html>
<head>
    <title>Security Audit Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .finding { margin: 20px 0; padding: 15px; border: 1px solid #ddd; }
        .CRITICAL { background-color: #ffebee; }
        .HIGH { background-color: #fff3e0; }
        .MEDIUM { background-color: #fff8e1; }
        .LOW { background-color: #e3f2fd; }
    </style>
</head>
<body>
    <h1>Kubernetes Security Audit Report</h1>
    <p>Generated: {{.Timestamp}}</p>
    <h2>Summary</h2>
    <ul>
        <li>Total Issues: {{.TotalIssues}}</li>
        <li>Critical: {{index .Summary "CRITICAL"}}</li>
        <li>High: {{index .Summary "HIGH"}}</li>
        <li>Medium: {{index .Summary "MEDIUM"}}</li>
        <li>Low: {{index .Summary "LOW"}}</li>
    </ul>
    <h2>Findings</h2>
    {{range .Findings}}
    <div class="finding {{.Severity}}">
        <h3>{{.Severity}}: {{.Description}}</h3>
        <p><strong>Category:</strong> {{.Category}}</p>
        <p><strong>Resource:</strong> {{.Resource}}</p>
        {{if .Namespace}}<p><strong>Namespace:</strong> {{.Namespace}}</p>{{end}}
        <p><strong>Suggestion:</strong> {{.Suggestion}}</p>
        {{if .Metadata}}
        <div class="metadata">
            <h4>Additional Information:</h4>
            <ul>
            {{range $key, $value := .Metadata}}
                <li><strong>{{$key}}:</strong> {{$value}}</li>
            {{end}}
            </ul>
        </div>
        {{end}}
    </div>
    {{end}}
</body>
</html>
`
