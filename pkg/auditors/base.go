package auditors

import (
	"context"

	"github.com/afshin-deriv/k8s-auditor/pkg/types"
	"k8s.io/client-go/kubernetes"
)

type Auditor interface {
	Audit(ctx context.Context) ([]types.Finding, error)
	Name() string
}

type BaseAuditor struct {
	Client    *kubernetes.Clientset
	Namespace string
}
