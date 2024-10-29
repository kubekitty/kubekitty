package auditors

import (
	"context"
	"fmt"

	"github.com/kubekitty/kubekitty/pkg/types"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// PodAuditor performs security audits on Pod resources
type PodAuditor struct {
	BaseAuditor
}

// NewPodAuditor creates a new pod auditor instance
func NewPodAuditor(base BaseAuditor) *PodAuditor {
	return &PodAuditor{
		BaseAuditor: base,
	}
}

func (a *PodAuditor) Name() string {
	return "Pod Security Auditor"
}

// Audit performs the security audit
func (a *PodAuditor) Audit(ctx context.Context) ([]types.Finding, error) {
	var findings []types.Finding

	// Get namespaces to audit
	namespaces, err := a.getNamespaces(ctx)
	if err != nil {
		return nil, fmt.Errorf("error getting namespaces: %v", err)
	}

	// Audit pods in each namespace
	for _, ns := range namespaces {
		if a.shouldSkipNamespace(ns) {
			continue
		}

		pods, err := a.Client.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{})
		if err != nil {
			return nil, fmt.Errorf("error listing pods in namespace %s: %v", ns, err)
		}

		for _, pod := range pods.Items {
			// Evaluate against pod rules
			ruleFindings := a.RulesEngine.EvaluateRules("pods", &pod)
			for i := range ruleFindings {
				ruleFindings[i].Resource = fmt.Sprintf("Pod/%s", pod.Name)
				ruleFindings[i].Namespace = ns

				// Add container context if present in metadata
				if container, ok := ruleFindings[i].Metadata["container"]; ok {
					ruleFindings[i].Resource = fmt.Sprintf("Pod/%s/Container/%s", pod.Name, container)
				}
			}
			findings = append(findings, ruleFindings...)

			// Run container-specific checks that are hard to express in YAML
			containerFindings := a.auditContainers(pod)
			findings = append(findings, containerFindings...)
		}
	}

	return findings, nil
}

// auditContainers checks container-specific security settings
func (a *PodAuditor) auditContainers(pod v1.Pod) []types.Finding {
	var findings []types.Finding

	// Check regular containers
	for _, container := range pod.Spec.Containers {
		findings = append(findings, a.evaluateContainer(pod, container)...)
	}

	// Check init containers
	for _, container := range pod.Spec.InitContainers {
		findings = append(findings, a.evaluateContainer(pod, container)...)
	}

	return findings
}

// evaluateContainer performs container-specific checks that are hard to express in YAML
func (a *PodAuditor) evaluateContainer(pod v1.Pod, container v1.Container) []types.Finding {
	var findings []types.Finding

	metadata := map[string]string{
		"container": container.Name,
		"image":     container.Image,
		"pod":       pod.Name,
		"namespace": pod.Namespace,
	}

	// Check resource limits (complex to express in YAML due to numeric comparisons)
	if container.Resources.Limits != nil {
		cpu := container.Resources.Limits.Cpu()
		memory := container.Resources.Limits.Memory()

		if cpu != nil && !cpu.IsZero() {
			metadata["cpu_limit"] = cpu.String()
		}

		if memory != nil && !memory.IsZero() {
			metadata["memory_limit"] = memory.String()
		}

		if cpu.IsZero() || memory.IsZero() {
			findings = append(findings, types.Finding{
				Severity:    "MEDIUM",
				Category:    "Resources",
				Resource:    fmt.Sprintf("Pod/%s/Container/%s", pod.Name, container.Name),
				Namespace:   pod.Namespace,
				Description: "Container has incomplete resource limits",
				Suggestion:  "Set both CPU and memory limits",
				Metadata:    metadata,
			})
		}
	}

	// Check Linux capabilities (complex due to list comparison)
	if container.SecurityContext != nil &&
		container.SecurityContext.Capabilities != nil &&
		len(container.SecurityContext.Capabilities.Add) > 0 {

		findings = append(findings, a.evaluateCapabilities(pod, container)...)
	}

	return findings
}

// evaluateCapabilities checks for dangerous Linux capabilities
func (a *PodAuditor) evaluateCapabilities(pod v1.Pod, container v1.Container) []types.Finding {
	var findings []types.Finding

	dangerousCaps := map[string]string{
		"CAP_SYS_ADMIN":     "Full administrative access",
		"CAP_NET_ADMIN":     "Network interface and routing modifications",
		"CAP_SYS_PTRACE":    "Process inspection and manipulation",
		"CAP_SYS_MODULE":    "Kernel module operations",
		"CAP_NET_RAW":       "Raw network access",
		"CAP_AUDIT_CONTROL": "Audit system manipulation",
	}

	for _, cap := range container.SecurityContext.Capabilities.Add {
		if description, isDangerous := dangerousCaps[string(cap)]; isDangerous {
			findings = append(findings, types.Finding{
				Severity:    "HIGH",
				Category:    "Security",
				Resource:    fmt.Sprintf("Pod/%s/Container/%s", pod.Name, container.Name),
				Namespace:   pod.Namespace,
				Description: fmt.Sprintf("Container adds dangerous capability: %s", cap),
				Suggestion:  "Remove unnecessary capabilities",
				Metadata: map[string]string{
					"container":  container.Name,
					"image":      container.Image,
					"capability": string(cap),
					"risk":       description,
					"mitigation": "Use more specific capabilities or remove if not required",
				},
			})
		}
	}

	return findings
}
