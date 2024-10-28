package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/homedir"
)

// Finding represents a security or best practice issue
type Finding struct {
	Severity    string `json:"severity"`
	Category    string `json:"category"`
	Resource    string `json:"resource"`
	Namespace   string `json:"namespace"`
	Description string `json:"description"`
	Suggestion  string `json:"suggestion"`
}

// AuditReport contains all findings from the audit
type AuditReport struct {
	Timestamp string    `json:"timestamp"`
	Cluster   string    `json:"cluster"`
	Findings  []Finding `json:"findings"`
}

// Auditor performs security checks on k8s resources
type Auditor struct {
	clientset *kubernetes.Clientset
	context   context.Context
}

// NewAuditor creates a new Kubernetes auditor
func NewAuditor(kubeconfig string) (*Auditor, error) {
	config, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		return nil, fmt.Errorf("error building kubeconfig: %v", err)
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("error creating kubernetes client: %v", err)
	}

	return &Auditor{
		clientset: clientset,
		context:   context.Background(),
	}, nil
}

// auditPods checks for various pod-related security issues
func (a *Auditor) auditPods(namespace string) []Finding {
	var findings []Finding

	pods, err := a.clientset.CoreV1().Pods(namespace).List(a.context, metav1.ListOptions{})
	if err != nil {
		log.Printf("Error listing pods in namespace %s: %v", namespace, err)
		return findings
	}

	for _, pod := range pods.Items {
		// Check for root containers
		findings = append(findings, a.checkRootContainers(pod)...)

		// Check for resource limits
		findings = append(findings, a.checkResourceLimits(pod)...)

		// Check security context
		findings = append(findings, a.checkSecurityContext(pod)...)

		// Check for privileged containers
		findings = append(findings, a.checkPrivilegedContainers(pod)...)

		// Check for host path mounts
		findings = append(findings, a.checkHostPathMounts(pod)...)
	}

	return findings
}

// checkRootContainers checks if containers are running as root
func (a *Auditor) checkRootContainers(pod v1.Pod) []Finding {
	var findings []Finding

	for _, container := range pod.Spec.Containers {
		if container.SecurityContext == nil ||
			container.SecurityContext.RunAsNonRoot == nil ||
			!*container.SecurityContext.RunAsNonRoot {
			findings = append(findings, Finding{
				Severity:    "HIGH",
				Category:    "Security",
				Resource:    fmt.Sprintf("Pod/%s/Container/%s", pod.Name, container.Name),
				Namespace:   pod.Namespace,
				Description: "Container may run as root user",
				Suggestion:  "Set SecurityContext.RunAsNonRoot=true and specify a non-root user",
			})
		}
	}

	return findings
}

// checkResourceLimits verifies that containers have resource limits set
func (a *Auditor) checkResourceLimits(pod v1.Pod) []Finding {
	var findings []Finding

	for _, container := range pod.Spec.Containers {
		if container.Resources.Limits == nil ||
			container.Resources.Limits.Cpu().IsZero() ||
			container.Resources.Limits.Memory().IsZero() {
			findings = append(findings, Finding{
				Severity:    "MEDIUM",
				Category:    "Resources",
				Resource:    fmt.Sprintf("Pod/%s/Container/%s", pod.Name, container.Name),
				Namespace:   pod.Namespace,
				Description: "Container does not have CPU or memory limits set",
				Suggestion:  "Set resource limits to prevent resource exhaustion",
			})
		}
	}

	return findings
}

// checkSecurityContext validates pod and container security contexts
func (a *Auditor) checkSecurityContext(pod v1.Pod) []Finding {
	var findings []Finding

	// Check pod security context
	if pod.Spec.SecurityContext == nil {
		findings = append(findings, Finding{
			Severity:    "MEDIUM",
			Category:    "Security",
			Resource:    fmt.Sprintf("Pod/%s", pod.Name),
			Namespace:   pod.Namespace,
			Description: "Pod security context not set",
			Suggestion:  "Configure pod security context with appropriate settings",
		})
	}

	// Check container security contexts
	for _, container := range pod.Spec.Containers {
		if container.SecurityContext == nil {
			findings = append(findings, Finding{
				Severity:    "MEDIUM",
				Category:    "Security",
				Resource:    fmt.Sprintf("Pod/%s/Container/%s", pod.Name, container.Name),
				Namespace:   pod.Namespace,
				Description: "Container security context not set",
				Suggestion:  "Configure container security context with appropriate settings",
			})
			continue
		}

		// Check for privilege escalation
		if container.SecurityContext.AllowPrivilegeEscalation == nil ||
			*container.SecurityContext.AllowPrivilegeEscalation {
			findings = append(findings, Finding{
				Severity:    "HIGH",
				Category:    "Security",
				Resource:    fmt.Sprintf("Pod/%s/Container/%s", pod.Name, container.Name),
				Namespace:   pod.Namespace,
				Description: "Container allows privilege escalation",
				Suggestion:  "Set allowPrivilegeEscalation: false",
			})
		}
	}

	return findings
}

// checkPrivilegedContainers checks for containers running in privileged mode
func (a *Auditor) checkPrivilegedContainers(pod v1.Pod) []Finding {
	var findings []Finding

	for _, container := range pod.Spec.Containers {
		if container.SecurityContext != nil &&
			container.SecurityContext.Privileged != nil &&
			*container.SecurityContext.Privileged {
			findings = append(findings, Finding{
				Severity:    "CRITICAL",
				Category:    "Security",
				Resource:    fmt.Sprintf("Pod/%s/Container/%s", pod.Name, container.Name),
				Namespace:   pod.Namespace,
				Description: "Container is running in privileged mode",
				Suggestion:  "Avoid running containers in privileged mode",
			})
		}
	}

	return findings
}

// checkHostPathMounts checks for containers mounting host paths
func (a *Auditor) checkHostPathMounts(pod v1.Pod) []Finding {
	var findings []Finding

	for _, volume := range pod.Spec.Volumes {
		if volume.HostPath != nil {
			findings = append(findings, Finding{
				Severity:    "HIGH",
				Category:    "Security",
				Resource:    fmt.Sprintf("Pod/%s/Volume/%s", pod.Name, volume.Name),
				Namespace:   pod.Namespace,
				Description: fmt.Sprintf("Pod mounts host path: %s", volume.HostPath.Path),
				Suggestion:  "Avoid mounting host paths in containers",
			})
		}
	}

	return findings
}

// auditServices checks for exposed sensitive ports
func (a *Auditor) auditServices(namespace string) []Finding {
	var findings []Finding

	services, err := a.clientset.CoreV1().Services(namespace).List(a.context, metav1.ListOptions{})
	if err != nil {
		log.Printf("Error listing services in namespace %s: %v", namespace, err)
		return findings
	}

	sensitivePorts := map[int32]string{
		22:    "SSH",
		3306:  "MySQL",
		5432:  "PostgreSQL",
		6379:  "Redis",
		27017: "MongoDB",
	}

	for _, svc := range services.Items {
		for _, port := range svc.Spec.Ports {
			if serviceName, sensitive := sensitivePorts[port.Port]; sensitive {
				findings = append(findings, Finding{
					Severity:    "HIGH",
					Category:    "Network",
					Resource:    fmt.Sprintf("Service/%s", svc.Name),
					Namespace:   svc.Namespace,
					Description: fmt.Sprintf("Service exposes sensitive %s port %d", serviceName, port.Port),
					Suggestion:  "Review if this port exposure is necessary and consider restricting access",
				})
			}
		}
	}

	return findings
}

func main() {
	var kubeconfig *string
	if home := homedir.HomeDir(); home != "" {
		kubeconfig = flag.String("kubeconfig", filepath.Join(home, ".kube", "config"), "(optional) absolute path to the kubeconfig file")
	} else {
		kubeconfig = flag.String("kubeconfig", "", "absolute path to the kubeconfig file")
	}
	namespace := flag.String("namespace", "", "namespace to audit (default: all namespaces)")
	outputFile := flag.String("output", "audit-report.json", "output file for audit results")
	flag.Parse()

	// Create auditor
	auditor, err := NewAuditor(*kubeconfig)
	if err != nil {
		log.Fatalf("Error creating auditor: %v", err)
	}

	// Initialize report
	report := AuditReport{
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Cluster:   "default",
		Findings:  []Finding{},
	}

	// Get namespaces to audit
	var namespaces []string
	if *namespace != "" {
		namespaces = []string{*namespace}
	} else {
		ns, err := auditor.clientset.CoreV1().Namespaces().List(context.TODO(), metav1.ListOptions{})
		if err != nil {
			log.Fatalf("Error listing namespaces: %v", err)
		}
		for _, n := range ns.Items {
			namespaces = append(namespaces, n.Name)
		}
	}

	// Perform audits for each namespace
	for _, ns := range namespaces {
		// Audit pods
		report.Findings = append(report.Findings, auditor.auditPods(ns)...)

		// Audit services
		report.Findings = append(report.Findings, auditor.auditServices(ns)...)
	}

	// Write report to file
	reportJSON, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		log.Fatalf("Error marshaling report: %v", err)
	}

	err = os.WriteFile(*outputFile, reportJSON, 0644)
	if err != nil {
		log.Fatalf("Error writing report: %v", err)
	}

	fmt.Printf("Audit complete. Found %d issues. Report written to %s\n", len(report.Findings), *outputFile)
}
