package auditors

import (
	"context"
	"fmt"

	"github.com/afshin-deriv/kubekitty/pkg/types"
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

func (a *RBACauditor) Audit(ctx context.Context) ([]types.Finding, error) {
	var findings []types.Finding

	// Audit ClusterRoles
	if clusterRoleFindings, err := a.auditClusterRoles(ctx); err != nil {
		return nil, fmt.Errorf("error auditing cluster roles: %v", err)
	} else {
		findings = append(findings, clusterRoleFindings...)
	}

	// Audit Roles and RoleBindings in namespaces
	namespaces, err := a.getNamespaces(ctx)
	if err != nil {
		return nil, fmt.Errorf("error getting namespaces: %v", err)
	}

	for _, ns := range namespaces {
		if a.shouldSkipNamespace(ns) {
			continue
		}

		// Audit Roles
		if roleFindings, err := a.auditRoles(ctx, ns); err != nil {
			return nil, fmt.Errorf("error auditing roles in namespace %s: %v", ns, err)
		} else {
			findings = append(findings, roleFindings...)
		}

		// Audit RoleBindings
		if bindingFindings, err := a.auditRoleBindings(ctx, ns); err != nil {
			return nil, fmt.Errorf("error auditing role bindings in namespace %s: %v", ns, err)
		} else {
			findings = append(findings, bindingFindings...)
		}

		// Audit ServiceAccounts
		if saFindings, err := a.auditServiceAccounts(ctx, ns); err != nil {
			return nil, fmt.Errorf("error auditing service accounts in namespace %s: %v", ns, err)
		} else {
			findings = append(findings, saFindings...)
		}
	}

	return findings, nil
}

func (a *RBACauditor) auditClusterRoles(ctx context.Context) ([]types.Finding, error) {
	roles, err := a.Client.RbacV1().ClusterRoles().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}

	var findings []types.Finding
	for _, role := range roles.Items {
		ruleFindings := a.RulesEngine.EvaluateRules("rbac", &role)
		for i := range ruleFindings {
			ruleFindings[i].Resource = fmt.Sprintf("ClusterRole/%s", role.Name)
		}
		findings = append(findings, ruleFindings...)
	}

	return findings, nil
}

func (a *RBACauditor) auditRoles(ctx context.Context, namespace string) ([]types.Finding, error) {
	roles, err := a.Client.RbacV1().Roles(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}

	var findings []types.Finding
	for _, role := range roles.Items {
		ruleFindings := a.RulesEngine.EvaluateRules("rbac", &role)
		for i := range ruleFindings {
			ruleFindings[i].Resource = fmt.Sprintf("Role/%s", role.Name)
			ruleFindings[i].Namespace = namespace
		}
		findings = append(findings, ruleFindings...)
	}

	return findings, nil
}

func (a *RBACauditor) auditRoleBindings(ctx context.Context, namespace string) ([]types.Finding, error) {
	roleBindings, err := a.Client.RbacV1().RoleBindings(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}

	var findings []types.Finding
	for _, binding := range roleBindings.Items {
		ruleFindings := a.RulesEngine.EvaluateRules("rbac", &binding)
		for i := range ruleFindings {
			ruleFindings[i].Resource = fmt.Sprintf("RoleBinding/%s", binding.Name)
			ruleFindings[i].Namespace = namespace
		}
		findings = append(findings, ruleFindings...)
	}

	return findings, nil
}

func (a *RBACauditor) auditServiceAccounts(ctx context.Context, namespace string) ([]types.Finding, error) {
	sas, err := a.Client.CoreV1().ServiceAccounts(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}

	var findings []types.Finding
	for _, sa := range sas.Items {
		ruleFindings := a.RulesEngine.EvaluateRules("rbac", &sa)
		for i := range ruleFindings {
			ruleFindings[i].Resource = fmt.Sprintf("ServiceAccount/%s", sa.Name)
			ruleFindings[i].Namespace = namespace
		}
		findings = append(findings, ruleFindings...)
	}

	return findings, nil
}
