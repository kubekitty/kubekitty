// Rules Engine
package rules

import (
	"fmt"
	"io/ioutil"

	"github.com/afshin-deriv/kubekitty/pkg/types"
	"gopkg.in/yaml.v2"
	"k8s.io/apimachinery/pkg/runtime"
)

type Rule struct {
	Name        string            `yaml:"name"`
	Description string            `yaml:"description"`
	Category    string            `yaml:"category"`
	Severity    string            `yaml:"severity"`
	Condition   string            `yaml:"condition"`
	Suggestion  string            `yaml:"suggestion"`
	Metadata    map[string]string `yaml:"metadata,omitempty"`
}

type RuleSet struct {
	Rules []Rule `yaml:"rules"`
}

// RulesEngine handles loading and evaluating security rules
type RulesEngine struct {
	rules map[string][]Rule
}

// NewRulesEngine creates a new rules engine instance
func NewRulesEngine(ruleFiles map[string]string) (*RulesEngine, error) {
	engine := &RulesEngine{
		rules: make(map[string][]Rule),
	}

	for category, filename := range ruleFiles {
		rules, err := loadRulesFromFile(filename)
		if err != nil {
			return nil, fmt.Errorf("error loading rules for %s: %v", category, err)
		}
		engine.rules[category] = rules
	}

	return engine, nil
}

// loadRulesFromFile loads rules from a YAML file
func loadRulesFromFile(filename string) ([]Rule, error) {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	var ruleSet RuleSet
	if err := yaml.Unmarshal(data, &ruleSet); err != nil {
		return nil, err
	}

	return ruleSet.Rules, nil
}

// EvaluateRules evaluates all rules for a given category against a Kubernetes object
func (e *RulesEngine) EvaluateRules(category string, obj runtime.Object) []types.Finding {
	var findings []types.Finding

	rules, exists := e.rules[category]
	if !exists {
		return findings
	}

	for _, rule := range rules {
		if finding := evaluateRule(rule, obj); finding != nil {
			findings = append(findings, *finding)
		}
	}

	return findings
}

// evaluateRule evaluates a single rule against a Kubernetes object
func evaluateRule(rule Rule, obj runtime.Object) *types.Finding {
	// Evaluate the rule condition
	if isViolated := evaluateCondition(rule.Condition, obj); isViolated {
		return &types.Finding{
			Severity:    rule.Severity,
			Category:    rule.Category,
			Description: rule.Description,
			Suggestion:  rule.Suggestion,
			Metadata:    rule.Metadata,
			Resource:    getResourceInfo(obj),
		}
	}
	return nil
}

// evaluateCondition evaluates the rule condition against the object
func evaluateCondition(condition string, obj runtime.Object) bool {
	// Implement your condition evaluation logic here
	// This could use a simple expression evaluator or custom logic
	// For now, returning true as a placeholder
	return true
}

// getResourceInfo extracts resource information from a Kubernetes object
func getResourceInfo(obj runtime.Object) string {
	// Implement logic to get resource name/type
	return "resource"
}
