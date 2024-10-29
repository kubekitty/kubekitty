package auditors

import (
	"context"
	"fmt"

	"github.com/kubekitty/kubekitty/pkg/types"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// NetworkAuditor performs security audits on network-related resources
type NetworkAuditor struct {
	BaseAuditor
}

// NewNetworkAuditor creates a new network auditor instance
func NewNetworkAuditor(base BaseAuditor) *NetworkAuditor {
	return &NetworkAuditor{
		BaseAuditor: base,
	}
}

func (a *NetworkAuditor) Name() string {
	return "Network Security Auditor"
}

// Audit performs the network security audit
func (a *NetworkAuditor) Audit(ctx context.Context) ([]types.Finding, error) {
	var findings []types.Finding

	// Get namespaces to audit
	namespaces, err := a.getNamespaces(ctx)
	if err != nil {
		return nil, fmt.Errorf("error getting namespaces: %v", err)
	}

	// Audit each namespace
	for _, ns := range namespaces {
		if a.shouldSkipNamespace(ns) {
			continue
		}

		// Audit NetworkPolicies
		netpolFindings, err := a.auditNetworkPolicies(ctx, ns)
		if err != nil {
			return nil, fmt.Errorf("error auditing network policies in namespace %s: %v", ns, err)
		}
		findings = append(findings, netpolFindings...)

		// Audit Services
		svcFindings, err := a.auditServices(ctx, ns)
		if err != nil {
			return nil, fmt.Errorf("error auditing services in namespace %s: %v", ns, err)
		}
		findings = append(findings, svcFindings...)

		// Audit Ingress resources
		ingressFindings, err := a.auditIngress(ctx, ns)
		if err != nil {
			return nil, fmt.Errorf("error auditing ingress in namespace %s: %v", ns, err)
		}
		findings = append(findings, ingressFindings...)
	}

	return findings, nil
}

func (a *NetworkAuditor) auditNetworkPolicies(ctx context.Context, namespace string) ([]types.Finding, error) {
	var findings []types.Finding

	// Get network policies
	policies, err := a.Client.NetworkingV1().NetworkPolicies(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}

	// Check for missing network policies (this check is hard to express in YAML)
	if len(policies.Items) == 0 {
		findings = append(findings, types.Finding{
			Severity:    "HIGH",
			Category:    "Network",
			Resource:    fmt.Sprintf("Namespace/%s", namespace),
			Namespace:   namespace,
			Description: "No NetworkPolicy defined in namespace",
			Suggestion:  "Define NetworkPolicy to control ingress/egress traffic",
			Metadata: map[string]string{
				"risk":        "Unrestricted network access",
				"impact":      "Pods can communicate without restrictions",
				"remediation": "Define default deny policy and explicit allow rules",
			},
		})
		return findings, nil
	}

	// Evaluate each policy against rules
	for _, policy := range policies.Items {
		ruleFindings := a.RulesEngine.EvaluateRules("network", &policy)
		for i := range ruleFindings {
			ruleFindings[i].Resource = fmt.Sprintf("NetworkPolicy/%s", policy.Name)
			ruleFindings[i].Namespace = namespace
		}
		findings = append(findings, ruleFindings...)
	}

	return findings, nil
}

func (a *NetworkAuditor) auditServices(ctx context.Context, namespace string) ([]types.Finding, error) {
	services, err := a.Client.CoreV1().Services(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}

	var findings []types.Finding
	for _, svc := range services.Items {
		ruleFindings := a.RulesEngine.EvaluateRules("network", &svc)
		for i := range ruleFindings {
			ruleFindings[i].Resource = fmt.Sprintf("Service/%s", svc.Name)
			ruleFindings[i].Namespace = namespace
		}
		findings = append(findings, ruleFindings...)
	}

	return findings, nil
}

func (a *NetworkAuditor) auditIngress(ctx context.Context, namespace string) ([]types.Finding, error) {
	ingresses, err := a.Client.NetworkingV1().Ingresses(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}

	var findings []types.Finding
	for _, ing := range ingresses.Items {
		ruleFindings := a.RulesEngine.EvaluateRules("network", &ing)
		for i := range ruleFindings {
			ruleFindings[i].Resource = fmt.Sprintf("Ingress/%s", ing.Name)
			ruleFindings[i].Namespace = namespace
		}
		findings = append(findings, ruleFindings...)
	}

	return findings, nil
}
