package config

import (
	"fmt"
	"path/filepath"
)

// getRuleFiles returns a map of rule category to rule file paths
func getRuleFiles(rulesDir string) (map[string]string, error) {
	ruleFiles := make(map[string]string)

	// Define default rule files
	defaultRules := map[string]string{
		"pod":     filepath.Join(rulesDir, "pod.yaml"),
		"rbac":    filepath.Join(rulesDir, "rbac.yaml"),
		"network": filepath.Join(rulesDir, "network.yaml"),
	}

	// Ensure rule files exist
	for category, path := range defaultRules {
		if _, err := filepath.Abs(path); err != nil {
			return nil, fmt.Errorf("invalid rule file path for %s: %v", category, err)
		}
		ruleFiles[category] = path
	}

	return ruleFiles, nil
}
