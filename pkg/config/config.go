package config

import (
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

type AuditConfig struct {
	Clientset     *kubernetes.Clientset
	RestConfig    *rest.Config
	Namespace     string
	OutputFile    string
	Debug         bool
	AuditScopes   []string
	SkipScopes    []string
	MinSeverity   string
	ReportFormat  string
	IncludeSystem bool
}
