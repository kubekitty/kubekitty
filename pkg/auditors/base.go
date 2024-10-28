package auditors

import (
	"context"

	"github.com/afshin-deriv/kubekitty/pkg/rules"
	"github.com/afshin-deriv/kubekitty/pkg/types"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// Auditor interface defines the methods that all auditors must implement
type Auditor interface {
	Audit(ctx context.Context) ([]types.Finding, error)
	Name() string
}

// BaseAuditor provides common functionality for all auditors
type BaseAuditor struct {
	Client      *kubernetes.Clientset
	Namespace   string
	RulesEngine *rules.RulesEngine
}

// NewBaseAuditor creates a new base auditor instance
func NewBaseAuditor(client *kubernetes.Clientset, namespace string, rulesEngine *rules.RulesEngine) BaseAuditor {
	return BaseAuditor{
		Client:      client,
		Namespace:   namespace,
		RulesEngine: rulesEngine,
	}
}

// getNamespaces returns a list of namespaces to audit
func (b *BaseAuditor) getNamespaces(ctx context.Context) ([]string, error) {
	if b.Namespace != "" {
		return []string{b.Namespace}, nil
	}

	nsList, err := b.Client.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}

	var namespaces []string
	for _, ns := range nsList.Items {
		namespaces = append(namespaces, ns.Name)
	}

	return namespaces, nil
}

// shouldSkipNamespace determines if a namespace should be skipped during auditing
func (b *BaseAuditor) shouldSkipNamespace(namespace string) bool {
	// List of system namespaces that are typically skipped
	systemNamespaces := map[string]bool{
		"kube-system":     true,
		"kube-public":     true,
		"kube-node-lease": true,
	}

	return systemNamespaces[namespace]
}
