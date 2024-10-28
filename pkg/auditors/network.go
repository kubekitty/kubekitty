package auditors

import (
	"context"
	"fmt"
	"strings"

	"github.com/afshin-deriv/k8s-auditor/pkg/types"
	v1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type NetworkAuditor struct {
	BaseAuditor
}

func NewNetworkAuditor(base BaseAuditor) *NetworkAuditor {
	return &NetworkAuditor{
		BaseAuditor: base,
	}
}

func (a *NetworkAuditor) Name() string {
	return "Network Security Auditor"
}

func (a *NetworkAuditor) Audit(ctx context.Context) ([]types.Finding, error) {
	var findings []types.Finding

	// Check network policies
	netpolFindings, err := a.auditNetworkPolicies(ctx)
	if err != nil {
		return nil, fmt.Errorf("error auditing network policies: %v", err)
	}
	findings = append(findings, netpolFindings...)

	// Check service exposures
	svcFindings, err := a.auditServices(ctx)
	if err != nil {
		return nil, fmt.Errorf("error auditing services: %v", err)
	}
	findings = append(findings, svcFindings...)

	// Check ingress configurations
	ingressFindings, err := a.auditIngress(ctx)
	if err != nil {
		return nil, fmt.Errorf("error auditing ingress: %v", err)
	}
	findings = append(findings, ingressFindings...)

	return findings, nil
}

func (a *NetworkAuditor) auditNetworkPolicies(ctx context.Context) ([]types.Finding, error) {
	var findings []types.Finding

	// Get all namespaces if not specified
	namespaces := []string{a.Namespace}
	if a.Namespace == "" {
		nsList, err := a.Client.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
		if err != nil {
			return nil, err
		}
		namespaces = []string{}
		for _, ns := range nsList.Items {
			namespaces = append(namespaces, ns.Name)
		}
	}

	for _, ns := range namespaces {
		// Check if namespace has any network policies
		policies, err := a.Client.NetworkingV1().NetworkPolicies(ns).List(ctx, metav1.ListOptions{})
		if err != nil {
			continue
		}

		// Check for missing network policies
		if len(policies.Items) == 0 {
			findings = append(findings, types.Finding{
				Severity:    "HIGH",
				Category:    "Network",
				Resource:    fmt.Sprintf("Namespace/%s", ns),
				Namespace:   ns,
				Description: "Namespace has no NetworkPolicy defined",
				Suggestion:  "Define NetworkPolicy to control ingress/egress traffic",
			})
			continue
		}

		// Analyze each network policy
		for _, policy := range policies.Items {
			findings = append(findings, a.checkNetworkPolicy(policy)...)
		}
	}

	return findings, nil
}

func (a *NetworkAuditor) checkNetworkPolicy(policy networkingv1.NetworkPolicy) []types.Finding {
	var findings []types.Finding

	// Check for overly permissive ingress rules
	if policy.Spec.Ingress != nil {
		for i, rule := range policy.Spec.Ingress {
			if len(rule.From) == 0 {
				findings = append(findings, types.Finding{
					Severity:    "HIGH",
					Category:    "Network",
					Resource:    fmt.Sprintf("NetworkPolicy/%s", policy.Name),
					Namespace:   policy.Namespace,
					Description: fmt.Sprintf("NetworkPolicy ingress rule %d allows traffic from any source", i),
					Suggestion:  "Specify allowed sources in ingress rules",
					Metadata: map[string]string{
						"rule": fmt.Sprintf("ingress[%d]", i),
					},
				})
			}
		}
	}

	// Check for overly permissive egress rules
	if policy.Spec.Egress != nil {
		for i, rule := range policy.Spec.Egress {
			if len(rule.To) == 0 {
				findings = append(findings, types.Finding{
					Severity:    "MEDIUM",
					Category:    "Network",
					Resource:    fmt.Sprintf("NetworkPolicy/%s", policy.Name),
					Namespace:   policy.Namespace,
					Description: fmt.Sprintf("NetworkPolicy egress rule %d allows traffic to any destination", i),
					Suggestion:  "Specify allowed destinations in egress rules",
					Metadata: map[string]string{
						"rule": fmt.Sprintf("egress[%d]", i),
					},
				})
			}
		}
	}

	return findings
}

func (a *NetworkAuditor) auditServices(ctx context.Context) ([]types.Finding, error) {
	var findings []types.Finding

	services, err := a.Client.CoreV1().Services(a.Namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}

	for _, svc := range services.Items {
		findings = append(findings, a.checkService(svc)...)
	}

	return findings, nil
}

func (a *NetworkAuditor) checkService(svc v1.Service) []types.Finding {
	var findings []types.Finding

	// Check for LoadBalancer services
	if svc.Spec.Type == v1.ServiceTypeLoadBalancer {
		findings = append(findings, types.Finding{
			Severity:    "MEDIUM",
			Category:    "Network",
			Resource:    fmt.Sprintf("Service/%s", svc.Name),
			Namespace:   svc.Namespace,
			Description: "Service is exposed via LoadBalancer",
			Suggestion:  "Consider using Ingress or internal load balancing if possible",
			Metadata: map[string]string{
				"type": string(svc.Spec.Type),
			},
		})
	}

	// Check for NodePort services
	if svc.Spec.Type == v1.ServiceTypeNodePort {
		findings = append(findings, types.Finding{
			Severity:    "MEDIUM",
			Category:    "Network",
			Resource:    fmt.Sprintf("Service/%s", svc.Name),
			Namespace:   svc.Namespace,
			Description: "Service is exposed via NodePort",
			Suggestion:  "Consider using Ingress or ClusterIP if possible",
			Metadata: map[string]string{
				"type": string(svc.Spec.Type),
			},
		})
	}

	// Check for sensitive ports
	sensitivePorts := map[int32]string{
		22:    "SSH",
		3306:  "MySQL",
		5432:  "PostgreSQL",
		6379:  "Redis",
		27017: "MongoDB",
		9200:  "Elasticsearch",
	}

	for _, port := range svc.Spec.Ports {
		if portName, isSensitive := sensitivePorts[port.Port]; isSensitive {
			findings = append(findings, types.Finding{
				Severity:    "HIGH",
				Category:    "Network",
				Resource:    fmt.Sprintf("Service/%s", svc.Name),
				Namespace:   svc.Namespace,
				Description: fmt.Sprintf("Service exposes sensitive %s port %d", portName, port.Port),
				Suggestion:  "Avoid exposing sensitive ports directly. Use secure proxies or VPN",
				Metadata: map[string]string{
					"port":     fmt.Sprintf("%d", port.Port),
					"protocol": string(port.Protocol),
					"service":  portName,
				},
			})
		}
	}

	return findings
}

func (a *NetworkAuditor) auditIngress(ctx context.Context) ([]types.Finding, error) {
	var findings []types.Finding

	ingresses, err := a.Client.NetworkingV1().Ingresses(a.Namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}

	for _, ing := range ingresses.Items {
		findings = append(findings, a.checkIngress(ing)...)
	}

	return findings, nil
}

func (a *NetworkAuditor) checkIngress(ing networkingv1.Ingress) []types.Finding {
	var findings []types.Finding

	// Check for TLS configuration
	if len(ing.Spec.TLS) == 0 {
		findings = append(findings, types.Finding{
			Severity:    "HIGH",
			Category:    "Network",
			Resource:    fmt.Sprintf("Ingress/%s", ing.Name),
			Namespace:   ing.Namespace,
			Description: "Ingress does not use TLS",
			Suggestion:  "Configure TLS to encrypt traffic",
		})
	}

	// Check for annotations
	securityAnnotations := map[string]string{
		"nginx.ingress.kubernetes.io/ssl-redirect":       "true",
		"nginx.ingress.kubernetes.io/force-ssl-redirect": "true",
		"nginx.ingress.kubernetes.io/secure-backends":    "true",
	}

	for key, expectedValue := range securityAnnotations {
		if value, exists := ing.Annotations[key]; !exists || value != expectedValue {
			findings = append(findings, types.Finding{
				Severity:    "MEDIUM",
				Category:    "Network",
				Resource:    fmt.Sprintf("Ingress/%s", ing.Name),
				Namespace:   ing.Namespace,
				Description: fmt.Sprintf("Missing or incorrect security annotation: %s", key),
				Suggestion:  fmt.Sprintf("Add annotation %s=%s", key, expectedValue),
				Metadata: map[string]string{
					"annotation": key,
					"expected":   expectedValue,
					"current":    value,
				},
			})
		}
	}

	// Check for wildcard hosts
	for _, rule := range ing.Spec.Rules {
		if strings.HasPrefix(rule.Host, "*.") {
			findings = append(findings, types.Finding{
				Severity:    "MEDIUM",
				Category:    "Network",
				Resource:    fmt.Sprintf("Ingress/%s", ing.Name),
				Namespace:   ing.Namespace,
				Description: "Ingress uses wildcard host",
				Suggestion:  "Specify explicit hostnames instead of wildcards",
				Metadata: map[string]string{
					"host": rule.Host,
				},
			})
		}
	}

	return findings
}
