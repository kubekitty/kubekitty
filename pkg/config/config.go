package config

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v2"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/homedir"
)

// AuditConfig holds all configuration for the security auditor
type AuditConfig struct {
	// Kubernetes clients
	Clientset  *kubernetes.Clientset
	RestConfig *rest.Config

	// Audit scope configuration
	Namespace     string
	AuditScopes   []string
	SkipScopes    []string
	IncludeSystem bool

	// Output configuration
	OutputFile   string
	ReportFormat string
	MinSeverity  string
	Debug        bool

	// Rules configuration
	RulesDir  string
	RuleFiles map[string]string
}

// Rule represents a single security rule definition
type Rule struct {
	Name        string            `yaml:"name"`
	Description string            `yaml:"description"`
	Category    string            `yaml:"category"`
	Severity    string            `yaml:"severity"`
	Condition   string            `yaml:"condition"`
	Suggestion  string            `yaml:"suggestion"`
	Metadata    map[string]string `yaml:"metadata,omitempty"`
}

// RuleConfig represents the structure of a rules YAML file
type RuleConfig struct {
	Rules []Rule `yaml:"rules"`
}

// ConfigOptions holds the command-line options
type ConfigOptions struct {
	KubeconfigPath string
	Namespace      string
	OutputFile     string
	Debug          bool
	MinSeverity    string
	ReportFormat   string
	IncludeSystem  bool
	RulesDir       string
}

func ParseConfig() (*AuditConfig, error) {
	cfg := &AuditConfig{}

	// Set up kubeconfig flag
	var kubeconfig string
	if home := homedir.HomeDir(); home != "" {
		flag.StringVar(&kubeconfig, "kubeconfig", filepath.Join(home, ".kube", "config"),
			"path to the kubeconfig file")
	} else {
		flag.StringVar(&kubeconfig, "kubeconfig", "", "path to the kubeconfig file")
	}

	// Set up other flags
	flag.StringVar(&cfg.Namespace, "namespace", "", "namespace to audit (default: all namespaces)")
	flag.StringVar(&cfg.OutputFile, "output", "audit-report.json", "output file for audit results")
	flag.StringVar(&cfg.MinSeverity, "min-severity", "LOW", "minimum severity to report (LOW, MEDIUM, HIGH, CRITICAL)")
	flag.StringVar(&cfg.ReportFormat, "format", "json", "output format (json, yaml)")

	// Rules directory configuration
	defaultRulesDir := filepath.Join(".", "rules") // Use relative path
	flag.StringVar(&cfg.RulesDir, "rules-dir", defaultRulesDir, "directory containing rule files")

	flag.BoolVar(&cfg.Debug, "debug", false, "enable debug logging")
	flag.BoolVar(&cfg.IncludeSystem, "include-system", false, "include system namespaces in audit")

	flag.Parse()

	// Set default scopes
	cfg.AuditScopes = getDefaultAuditScopes()
	cfg.SkipScopes = getDefaultSkipScopes()

	// Initialize Kubernetes client
	config, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		return nil, fmt.Errorf("error building kubeconfig: %v", err)
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("error creating kubernetes client: %v", err)
	}

	cfg.Clientset = clientset
	cfg.RestConfig = config

	// Verify and load rule files
	if err := verifyRulesDirectory(cfg.RulesDir); err != nil {
		return nil, fmt.Errorf("rules directory error: %v", err)
	}

	ruleFiles, err := loadRuleFiles(cfg.RulesDir)
	if err != nil {
		return nil, fmt.Errorf("error loading rule files: %v", err)
	}
	cfg.RuleFiles = ruleFiles

	// Validate the configuration
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid configuration: %v", err)
	}

	return cfg, nil
}

// verifyRulesDirectory checks if the rules directory exists and contains required files
func verifyRulesDirectory(rulesDir string) error {
	// Resolve absolute path
	absPath, err := filepath.Abs(rulesDir)
	if err != nil {
		return fmt.Errorf("failed to resolve rules directory path: %v", err)
	}

	// Check if directory exists
	info, err := os.Stat(absPath)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("rules directory does not exist: %s", absPath)
		}
		return fmt.Errorf("error accessing rules directory: %v", err)
	}

	if !info.IsDir() {
		return fmt.Errorf("rules path is not a directory: %s", absPath)
	}

	// Check for required rule files
	requiredFiles := []string{"network.yaml", "pods.yaml", "rbac.yaml"}
	for _, file := range requiredFiles {
		filePath := filepath.Join(absPath, file)
		if _, err := os.Stat(filePath); err != nil {
			if os.IsNotExist(err) {
				return fmt.Errorf("required rule file missing: %s", file)
			}
			return fmt.Errorf("error checking rule file %s: %v", file, err)
		}
	}

	return nil
}

func loadRuleFiles(rulesDir string) (map[string]string, error) {
	ruleFiles := make(map[string]string)

	// Get absolute path
	absPath, err := filepath.Abs(rulesDir)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve rules directory path: %v", err)
	}

	// Walk through the rules directory
	err = filepath.Walk(absPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Skip directories and non-yaml files
		if info.IsDir() || filepath.Ext(path) != ".yaml" {
			return nil
		}

		// Get the category from the filename (without extension)
		baseName := filepath.Base(path)
		category := baseName[:len(baseName)-len(".yaml")]
		ruleFiles[category] = path

		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("error walking rules directory: %v", err)
	}

	// Ensure we found at least some rule files
	if len(ruleFiles) == 0 {
		return nil, fmt.Errorf("no rule files found in directory: %s", rulesDir)
	}

	return ruleFiles, nil
}

// parseFlags parses command-line flags and returns ConfigOptions
func parseFlags() ConfigOptions {
	opts := ConfigOptions{}

	// Set up kubeconfig flag
	if home := homedir.HomeDir(); home != "" {
		flag.StringVar(&opts.KubeconfigPath, "kubeconfig",
			filepath.Join(home, ".kube", "config"),
			"path to the kubeconfig file")
	} else {
		flag.StringVar(&opts.KubeconfigPath, "kubeconfig", "",
			"path to the kubeconfig file")
	}

	// Set up other flags
	flag.StringVar(&opts.Namespace, "namespace", "",
		"namespace to audit (default: all namespaces)")
	flag.StringVar(&opts.OutputFile, "output", "audit-report.json",
		"output file for audit results")
	flag.StringVar(&opts.MinSeverity, "min-severity", "LOW",
		"minimum severity to report (LOW, MEDIUM, HIGH, CRITICAL)")
	flag.StringVar(&opts.ReportFormat, "format", "json",
		"output format (json, yaml)")
	flag.StringVar(&opts.RulesDir, "rules-dir", "rules",
		"directory containing rule files")
	flag.BoolVar(&opts.Debug, "debug", false,
		"enable debug logging")
	flag.BoolVar(&opts.IncludeSystem, "include-system", false,
		"include system namespaces in audit")

	flag.Parse()
	return opts
}

// initializeKubernetesClient creates the Kubernetes client configuration
func initializeKubernetesClient(kubeconfigPath string) (*rest.Config, *kubernetes.Clientset, error) {
	var config *rest.Config
	var err error

	// Try to build config from kubeconfig file
	if kubeconfigPath != "" {
		config, err = clientcmd.BuildConfigFromFlags("", kubeconfigPath)
	} else {
		// If no kubeconfig is provided, try in-cluster config
		config, err = rest.InClusterConfig()
	}

	if err != nil {
		return nil, nil, fmt.Errorf("failed to create config: %v", err)
	}

	// Create the clientset
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create client set: %v", err)
	}

	return config, clientset, nil
}

// LoadRules loads rules from a specific file
func LoadRules(filename string) ([]Rule, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("error reading rule file: %v", err)
	}

	var config RuleConfig
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("error unmarshaling rules: %v", err)
	}

	return config.Rules, nil
}

// getDefaultAuditScopes returns the default audit scopes
func getDefaultAuditScopes() []string {
	return []string{
		"pods",
		"networkpolicies",
		"rbac",
		"secrets",
		"serviceaccounts",
	}
}

// getDefaultSkipScopes returns the default scopes to skip
func getDefaultSkipScopes() []string {
	return []string{
		"kube-system",
		"kube-public",
		"kube-node-lease",
	}
}

// Validate validates the configuration
func (c *AuditConfig) Validate() error {
	// Validate severity level
	validSeverities := map[string]bool{
		"LOW":      true,
		"MEDIUM":   true,
		"HIGH":     true,
		"CRITICAL": true,
	}
	if !validSeverities[c.MinSeverity] {
		return fmt.Errorf("invalid severity level: %s", c.MinSeverity)
	}

	// Validate report format
	validFormats := map[string]bool{
		"json": true,
		"yaml": true,
	}
	if !validFormats[c.ReportFormat] {
		return fmt.Errorf("invalid report format: %s", c.ReportFormat)
	}

	// Validate rules directory
	if _, err := os.Stat(c.RulesDir); os.IsNotExist(err) {
		return fmt.Errorf("rules directory does not exist: %s", c.RulesDir)
	}

	return nil
}
