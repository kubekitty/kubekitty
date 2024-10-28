package auditors

import (
	"context"
	"fmt"

	"github.com/afshin-deriv/k8s-auditor/pkg/types"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type PodAuditor struct {
	BaseAuditor
}

func NewPodAuditor(base BaseAuditor) *PodAuditor {
	return &PodAuditor{
		BaseAuditor: base,
	}
}

func (a *PodAuditor) Name() string {
	return "Pod Security Auditor"
}

func (a *PodAuditor) Audit(ctx context.Context) ([]types.Finding, error) {
	var findings []types.Finding

	// Get pods in the specified namespace (or all namespaces if none specified)
	pods, err := a.Client.CoreV1().Pods(a.Namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("error listing pods: %v", err)
	}

	// Audit each pod
	for _, pod := range pods.Items {
		findings = append(findings, a.checkPodSecurity(pod)...)
	}

	return findings, nil
}

func (a *PodAuditor) checkPodSecurity(pod v1.Pod) []types.Finding {
	var findings []types.Finding

	for _, container := range pod.Spec.Containers {
		if container.SecurityContext == nil ||
			container.SecurityContext.RunAsNonRoot == nil ||
			!*container.SecurityContext.RunAsNonRoot {
			findings = append(findings, types.Finding{
				Severity:    "HIGH",
				Category:    "Security",
				Resource:    fmt.Sprintf("Pod/%s/Container/%s", pod.Name, container.Name),
				Namespace:   pod.Namespace,
				Description: "Container may run as root user",
				Suggestion:  "Set SecurityContext.RunAsNonRoot=true and specify a non-root user",
				Metadata: map[string]string{
					"container": container.Name,
					"image":     container.Image,
				},
			})
		}
	}
	return findings
}

func (a *PodAuditor) checkPrivilegedContainers(pod v1.Pod) []types.Finding {
	var findings []types.Finding

	for _, container := range pod.Spec.Containers {
		if container.SecurityContext != nil &&
			container.SecurityContext.Privileged != nil &&
			*container.SecurityContext.Privileged {
			findings = append(findings, types.Finding{
				Severity:    "CRITICAL",
				Category:    "Security",
				Resource:    fmt.Sprintf("Pod/%s/Container/%s", pod.Name, container.Name),
				Namespace:   pod.Namespace,
				Description: "Container is running in privileged mode",
				Suggestion:  "Remove privileged mode unless absolutely necessary. Consider using specific capabilities instead.",
				Metadata: map[string]string{
					"container": container.Name,
					"image":     container.Image,
				},
			})
		}
	}
	return findings
}

func (a *PodAuditor) checkHostPathMounts(pod v1.Pod) []types.Finding {
	var findings []types.Finding

	for _, volume := range pod.Spec.Volumes {
		if volume.HostPath != nil {
			findings = append(findings, types.Finding{
				Severity:    "HIGH",
				Category:    "Security",
				Resource:    fmt.Sprintf("Pod/%s/Volume/%s", pod.Name, volume.Name),
				Namespace:   pod.Namespace,
				Description: fmt.Sprintf("Pod mounts host path: %s", volume.HostPath.Path),
				Suggestion:  "Avoid mounting host paths. Use persistent volumes or configmaps/secrets instead.",
				Metadata: map[string]string{
					"volume":   volume.Name,
					"hostPath": volume.HostPath.Path,
				},
			})
		}
	}
	return findings
}

func (a *PodAuditor) checkResourceLimits(pod v1.Pod) []types.Finding {
	var findings []types.Finding

	for _, container := range pod.Spec.Containers {
		if container.Resources.Limits == nil ||
			container.Resources.Limits.Cpu().IsZero() ||
			container.Resources.Limits.Memory().IsZero() {
			findings = append(findings, types.Finding{
				Severity:    "MEDIUM",
				Category:    "Resources",
				Resource:    fmt.Sprintf("Pod/%s/Container/%s", pod.Name, container.Name),
				Namespace:   pod.Namespace,
				Description: "Container does not have CPU or memory limits set",
				Suggestion:  "Set resource limits to prevent resource exhaustion",
				Metadata: map[string]string{
					"container": container.Name,
					"image":     container.Image,
				},
			})
		}
	}
	return findings
}

func (a *PodAuditor) checkSecurityContext(pod v1.Pod) []types.Finding {
	var findings []types.Finding

	if pod.Spec.SecurityContext == nil {
		findings = append(findings, types.Finding{
			Severity:    "MEDIUM",
			Category:    "Security",
			Resource:    fmt.Sprintf("Pod/%s", pod.Name),
			Namespace:   pod.Namespace,
			Description: "Pod security context not set",
			Suggestion:  "Configure pod security context with appropriate settings",
		})
	}

	for _, container := range pod.Spec.Containers {
		if container.SecurityContext == nil {
			findings = append(findings, types.Finding{
				Severity:    "MEDIUM",
				Category:    "Security",
				Resource:    fmt.Sprintf("Pod/%s/Container/%s", pod.Name, container.Name),
				Namespace:   pod.Namespace,
				Description: "Container security context not set",
				Suggestion:  "Configure container security context with appropriate settings",
				Metadata: map[string]string{
					"container": container.Name,
					"image":     container.Image,
				},
			})
		}
	}
	return findings
}

func (a *PodAuditor) checkHostNetwork(pod v1.Pod) []types.Finding {
	var findings []types.Finding

	if pod.Spec.HostNetwork {
		findings = append(findings, types.Finding{
			Severity:    "HIGH",
			Category:    "Security",
			Resource:    fmt.Sprintf("Pod/%s", pod.Name),
			Namespace:   pod.Namespace,
			Description: "Pod uses host network",
			Suggestion:  "Avoid using host network unless absolutely necessary",
		})
	}
	return findings
}

func (a *PodAuditor) checkHostPID(pod v1.Pod) []types.Finding {
	var findings []types.Finding

	if pod.Spec.HostPID {
		findings = append(findings, types.Finding{
			Severity:    "HIGH",
			Category:    "Security",
			Resource:    fmt.Sprintf("Pod/%s", pod.Name),
			Namespace:   pod.Namespace,
			Description: "Pod uses host PID namespace",
			Suggestion:  "Avoid using host PID namespace",
		})
	}
	return findings
}

func (a *PodAuditor) checkHostIPC(pod v1.Pod) []types.Finding {
	var findings []types.Finding

	if pod.Spec.HostIPC {
		findings = append(findings, types.Finding{
			Severity:    "HIGH",
			Category:    "Security",
			Resource:    fmt.Sprintf("Pod/%s", pod.Name),
			Namespace:   pod.Namespace,
			Description: "Pod uses host IPC namespace",
			Suggestion:  "Avoid using host IPC namespace",
		})
	}
	return findings
}

func (a *PodAuditor) checkCapabilities(pod v1.Pod) []types.Finding {
	var findings []types.Finding
	dangerousCaps := map[string]bool{
		"CAP_SYS_ADMIN":     true,
		"CAP_NET_ADMIN":     true,
		"CAP_SYS_PTRACE":    true,
		"CAP_SYS_MODULE":    true,
		"CAP_NET_RAW":       true,
		"CAP_AUDIT_CONTROL": true,
	}

	for _, container := range pod.Spec.Containers {
		if container.SecurityContext != nil && container.SecurityContext.Capabilities != nil {
			for _, cap := range container.SecurityContext.Capabilities.Add {
				if dangerousCaps[string(cap)] {
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
						},
					})
				}
			}
		}
	}
	return findings
}

func (a *PodAuditor) checkReadOnlyRoot(pod v1.Pod) []types.Finding {
	var findings []types.Finding

	for _, container := range pod.Spec.Containers {
		if container.SecurityContext == nil ||
			container.SecurityContext.ReadOnlyRootFilesystem == nil ||
			!*container.SecurityContext.ReadOnlyRootFilesystem {
			findings = append(findings, types.Finding{
				Severity:    "MEDIUM",
				Category:    "Security",
				Resource:    fmt.Sprintf("Pod/%s/Container/%s", pod.Name, container.Name),
				Namespace:   pod.Namespace,
				Description: "Container root filesystem is not read-only",
				Suggestion:  "Set ReadOnlyRootFilesystem to true",
				Metadata: map[string]string{
					"container": container.Name,
					"image":     container.Image,
				},
			})
		}
	}
	return findings
}

func (a *PodAuditor) checkServiceAccountToken(pod v1.Pod) []types.Finding {
	var findings []types.Finding

	if pod.Spec.AutomountServiceAccountToken == nil || *pod.Spec.AutomountServiceAccountToken {
		findings = append(findings, types.Finding{
			Severity:    "MEDIUM",
			Category:    "Security",
			Resource:    fmt.Sprintf("Pod/%s", pod.Name),
			Namespace:   pod.Namespace,
			Description: "Pod automatically mounts service account token",
			Suggestion:  "Disable automount of service account token if not needed",
		})
	}
	return findings
}
