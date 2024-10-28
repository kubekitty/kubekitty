package auditors

import (
	"context"
	"fmt"
	"strings"

	"github.com/afshin-deriv/k8s-auditor/pkg/types"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type RBACauditor struct {
	BaseAuditor
}

func NewRBACauditor(base BaseAuditor) *RBACauditor {
	return &RBACauditor{
		BaseAuditor: base,
	}
}

func (a *RBACauditor) Name() string {
	return "RBAC Security Auditor"
}

func (a *RBACauditor) auditClusterRoles(ctx context.Context) ([]types.Finding, error) {
	var findings []types.Finding

	roles, err := a.Client.RbacV1().ClusterRoles().List(ctx, metav1.ListOptions{})
	if err != nil {
		return findings, err
	}

	for _, role := range roles.Items {
		findings = append(findings, a.checkClusterRole(role)...)
	}

	return findings, nil
}

func (a *RBACauditor) checkClusterRole(role rbacv1.ClusterRole) []types.Finding {
	var findings []types.Finding

	// Check for wildcard permissions
	for _, rule := range role.Rules {
		if containsWildcard(rule.Verbs) || containsWildcard(rule.Resources) {
			findings = append(findings, types.Finding{
				Severity:    "HIGH",
				Category:    "RBAC",
				Resource:    fmt.Sprintf("ClusterRole/%s", role.Name),
				Description: "ClusterRole uses wildcard permissions",
				Suggestion:  "Specify explicit permissions instead of using wildcards",
				Metadata: map[string]string{
					"verbs":     strings.Join(rule.Verbs, ","),
					"resources": strings.Join(rule.Resources, ","),
				},
			})
		}
	}

	return findings
}

func containsWildcard(items []string) bool {
	for _, item := range items {
		if item == "*" {
			return true
		}
	}
	return false
}

func (a *RBACauditor) checkClusterRoleBinding(binding rbacv1.ClusterRoleBinding) []types.Finding {
	var findings []types.Finding

	// Check for default service account bindings
	for _, subject := range binding.Subjects {
		if subject.Kind == "ServiceAccount" && subject.Name == "default" {
			findings = append(findings, types.Finding{
				Severity:    "HIGH",
				Category:    "RBAC",
				Resource:    fmt.Sprintf("ClusterRoleBinding/%s", binding.Name),
				Description: "ClusterRoleBinding uses default service account",
				Suggestion:  "Avoid using default service account, create specific service accounts",
				Metadata: map[string]string{
					"roleRef": binding.RoleRef.Name,
					"subject": subject.Name,
				},
			})
		}
	}

	return findings
}

func (a *RBACauditor) auditRoleBindings(ctx context.Context) ([]types.Finding, error) {
	var findings []types.Finding

	// Check cluster role bindings
	clusterBindings, err := a.Client.RbacV1().ClusterRoleBindings().List(ctx, metav1.ListOptions{})
	if err != nil {
		return findings, err
	}

	for _, binding := range clusterBindings.Items {
		findings = append(findings, a.checkClusterRoleBinding(binding)...)
	}

	// Check namespace role bindings
	if a.Namespace != "" {
		roleBindings, err := a.Client.RbacV1().RoleBindings(a.Namespace).List(ctx, metav1.ListOptions{})
		if err != nil {
			return findings, err
		}

		for _, binding := range roleBindings.Items {
			findings = append(findings, a.checkRoleBinding(binding)...)
		}
	}

	return findings, nil
}

func (a *RBACauditor) Audit(ctx context.Context) ([]types.Finding, error) {
	var findings []types.Finding

	// Audit ClusterRoles
	clusterRoleFindings, err := a.auditClusterRoles(ctx)
	if err != nil {
		return nil, fmt.Errorf("error auditing cluster roles: %v", err)
	}
	findings = append(findings, clusterRoleFindings...)

	// Audit Roles
	roleFindings, err := a.auditRoles(ctx)
	if err != nil {
		return nil, fmt.Errorf("error auditing roles: %v", err)
	}
	findings = append(findings, roleFindings...)

	// Audit RoleBindings and ClusterRoleBindings
	bindingFindings, err := a.auditRoleBindings(ctx)
	if err != nil {
		return nil, fmt.Errorf("error auditing role bindings: %v", err)
	}
	findings = append(findings, bindingFindings...)

	// Audit ServiceAccounts
	saFindings, err := a.auditServiceAccounts(ctx)
	if err != nil {
		return nil, fmt.Errorf("error auditing service accounts: %v", err)
	}
	findings = append(findings, saFindings...)

	return findings, nil
}

func (a *RBACauditor) auditRoles(ctx context.Context) ([]types.Finding, error) {
	var findings []types.Finding

	// Get roles in the specified namespace (or all namespaces if none specified)
	roles, err := a.Client.RbacV1().Roles(a.Namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}

	for _, role := range roles.Items {
		findings = append(findings, a.checkRole(role)...)
	}

	return findings, nil
}

func (a *RBACauditor) checkRole(role rbacv1.Role) []types.Finding {
	var findings []types.Finding

	sensitiveResources := map[string]bool{
		"secrets":           true,
		"configmaps":        true,
		"pods":              true,
		"nodes":             true,
		"serviceaccounts":   true,
		"persistentvolumes": true,
	}

	// Check each rule in the role
	for _, rule := range role.Rules {
		// Check for wildcard permissions
		if containsWildcard(rule.Verbs) || containsWildcard(rule.Resources) {
			findings = append(findings, types.Finding{
				Severity:    "HIGH",
				Category:    "RBAC",
				Resource:    fmt.Sprintf("Role/%s", role.Name),
				Namespace:   role.Namespace,
				Description: "Role uses wildcard permissions",
				Suggestion:  "Specify explicit permissions instead of using wildcards",
				Metadata: map[string]string{
					"verbs":     strings.Join(rule.Verbs, ","),
					"resources": strings.Join(rule.Resources, ","),
				},
			})
		}

		// Check for sensitive resource access
		for _, resource := range rule.Resources {
			if sensitiveResources[resource] {
				findings = append(findings, types.Finding{
					Severity:    "MEDIUM",
					Category:    "RBAC",
					Resource:    fmt.Sprintf("Role/%s", role.Name),
					Namespace:   role.Namespace,
					Description: fmt.Sprintf("Role has access to sensitive resource: %s", resource),
					Suggestion:  "Review if access to this resource is necessary",
					Metadata: map[string]string{
						"resource": resource,
						"verbs":    strings.Join(rule.Verbs, ","),
					},
				})
			}
		}

		// Check for dangerous verbs
		if containsAny(rule.Verbs, []string{"delete", "deletecollection", "patch", "update"}) {
			findings = append(findings, types.Finding{
				Severity:    "MEDIUM",
				Category:    "RBAC",
				Resource:    fmt.Sprintf("Role/%s", role.Name),
				Namespace:   role.Namespace,
				Description: "Role has modification permissions",
				Suggestion:  "Review if modification permissions are necessary",
				Metadata: map[string]string{
					"verbs":     strings.Join(rule.Verbs, ","),
					"resources": strings.Join(rule.Resources, ","),
				},
			})
		}
	}

	return findings
}

func (a *RBACauditor) checkRoleBinding(binding rbacv1.RoleBinding) []types.Finding {
	var findings []types.Finding

	// Check for default service account bindings
	for _, subject := range binding.Subjects {
		if subject.Kind == "ServiceAccount" && subject.Name == "default" {
			findings = append(findings, types.Finding{
				Severity:    "HIGH",
				Category:    "RBAC",
				Resource:    fmt.Sprintf("RoleBinding/%s", binding.Name),
				Namespace:   binding.Namespace,
				Description: "RoleBinding uses default service account",
				Suggestion:  "Create dedicated service accounts with minimal permissions",
				Metadata: map[string]string{
					"roleRef":   binding.RoleRef.Name,
					"subject":   subject.Name,
					"kind":      subject.Kind,
					"namespace": subject.Namespace,
				},
			})
		}

		// Check for cross-namespace bindings
		if subject.Namespace != "" && subject.Namespace != binding.Namespace {
			findings = append(findings, types.Finding{
				Severity:    "MEDIUM",
				Category:    "RBAC",
				Resource:    fmt.Sprintf("RoleBinding/%s", binding.Name),
				Namespace:   binding.Namespace,
				Description: "RoleBinding references subject from different namespace",
				Suggestion:  "Review if cross-namespace access is necessary",
				Metadata: map[string]string{
					"roleRef":          binding.RoleRef.Name,
					"subject":          subject.Name,
					"subjectNamespace": subject.Namespace,
					"bindingNamespace": binding.Namespace,
				},
			})
		}
	}

	return findings
}

func (a *RBACauditor) auditServiceAccounts(ctx context.Context) ([]types.Finding, error) {
	var findings []types.Finding

	// Get service accounts in the specified namespace (or all namespaces if none specified)
	sas, err := a.Client.CoreV1().ServiceAccounts(a.Namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}

	for _, sa := range sas.Items {
		// Check for default service account
		if sa.Name == "default" {
			bindings, err := a.getServiceAccountBindings(ctx, sa.Namespace, sa.Name)
			if err != nil {
				continue
			}

			if len(bindings) > 0 {
				findings = append(findings, types.Finding{
					Severity:    "HIGH",
					Category:    "RBAC",
					Resource:    fmt.Sprintf("ServiceAccount/%s", sa.Name),
					Namespace:   sa.Namespace,
					Description: "Default service account has role bindings",
					Suggestion:  "Create dedicated service accounts instead of using default",
					Metadata: map[string]string{
						"bindings": strings.Join(bindings, ","),
					},
				})
			}
		}

		// Check for automounted service account tokens
		if sa.AutomountServiceAccountToken != nil && *sa.AutomountServiceAccountToken {
			findings = append(findings, types.Finding{
				Severity:    "MEDIUM",
				Category:    "RBAC",
				Resource:    fmt.Sprintf("ServiceAccount/%s", sa.Name),
				Namespace:   sa.Namespace,
				Description: "Service account automatically mounts token",
				Suggestion:  "Disable automatic token mounting if not needed",
			})
		}
	}

	return findings, nil
}

func (a *RBACauditor) getServiceAccountBindings(ctx context.Context, namespace, name string) ([]string, error) {
	var bindings []string

	// Check RoleBindings
	roleBindings, err := a.Client.RbacV1().RoleBindings(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}

	for _, rb := range roleBindings.Items {
		for _, subject := range rb.Subjects {
			if subject.Kind == "ServiceAccount" && subject.Name == name {
				bindings = append(bindings, fmt.Sprintf("RoleBinding/%s", rb.Name))
			}
		}
	}

	// Check ClusterRoleBindings
	clusterRoleBindings, err := a.Client.RbacV1().ClusterRoleBindings().List(ctx, metav1.ListOptions{})
	if err != nil {
		return bindings, nil
	}

	for _, crb := range clusterRoleBindings.Items {
		for _, subject := range crb.Subjects {
			if subject.Kind == "ServiceAccount" && subject.Name == name && subject.Namespace == namespace {
				bindings = append(bindings, fmt.Sprintf("ClusterRoleBinding/%s", crb.Name))
			}
		}
	}

	return bindings, nil
}

func containsAny(items []string, targets []string) bool {
	for _, item := range items {
		for _, target := range targets {
			if item == target {
				return true
			}
		}
	}
	return false
}
