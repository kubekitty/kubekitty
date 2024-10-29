package controller

import (
	"context"
	"fmt"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog/v2"

	"github.com/kubekitty/kubekitty/pkg/config"
	"github.com/kubekitty/kubekitty/pkg/rules"
	"github.com/kubekitty/kubekitty/pkg/types"

	"net/http"

	"k8s.io/client-go/informers"
)

// SecurityController watches Kubernetes resources and runs security audits
type SecurityController struct {
	config      *config.AuditConfig
	rulesEngine *rules.RulesEngine
	workqueue   workqueue.RateLimitingInterface
	informers   map[string]cache.SharedIndexInformer
	findings    chan types.Finding
}

// NewSecurityController creates a new security controller instance
func NewSecurityController(cfg *config.AuditConfig) (*SecurityController, error) {
	// Initialize rules engine
	rulesEngine, err := rules.NewRulesEngine(cfg.RuleFiles)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize rules engine: %v", err)
	}

	controller := &SecurityController{
		config:      cfg,
		rulesEngine: rulesEngine,
		workqueue:   workqueue.NewRateLimitingQueue(workqueue.DefaultControllerRateLimiter()),
		informers:   make(map[string]cache.SharedIndexInformer),
		findings:    make(chan types.Finding, 100),
	}

	// Set up informers for different resource types
	if err := controller.setupInformers(); err != nil {
		return nil, err
	}

	return controller, nil
}

// setupInformers initializes informers for different resource types
func (c *SecurityController) setupInformers() error {
	klog.V(2).Info("Setting up informers for resources")

	for _, scope := range c.config.AuditScopes {
		klog.V(2).Infof("Creating informer for scope: %s", scope)

		informer, err := c.createInformerForScope(scope)
		if err != nil {
			klog.Errorf("Failed to create informer for scope %s: %v", scope, err)
			return err
		}
		c.informers[scope] = informer

		// Enhanced logging for event handlers
		informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				if meta, ok := obj.(metav1.Object); ok {
					klog.V(3).Infof("Resource ADDED - Type: %T, Namespace: %s, Name: %s",
						obj, meta.GetNamespace(), meta.GetName())
				}
				c.enqueueObject(obj)
			},
			UpdateFunc: func(old, new interface{}) {
				if meta, ok := new.(metav1.Object); ok {
					klog.V(3).Infof("Resource UPDATED - Type: %T, Namespace: %s, Name: %s",
						new, meta.GetNamespace(), meta.GetName())
				}
				c.enqueueObject(new)
			},
			DeleteFunc: func(obj interface{}) {
				if meta, ok := obj.(metav1.Object); ok {
					klog.V(3).Infof("Resource DELETED - Type: %T, Namespace: %s, Name: %s",
						obj, meta.GetNamespace(), meta.GetName())
				}
			},
		})

		klog.V(2).Infof("Successfully created informer for scope: %s", scope)
	}
	return nil
}

// Run starts the controller
func (c *SecurityController) Run(ctx context.Context, workers int) error {
	defer c.workqueue.ShutDown()

	c.startHealthzServer()

	klog.Info("Starting security controller")

	// Start informers
	for name, informer := range c.informers {
		klog.Infof("Starting informer for %s", name)
		go informer.Run(ctx.Done())

		// Wait for caches to sync
		if !cache.WaitForCacheSync(ctx.Done(), informer.HasSynced) {
			return fmt.Errorf("failed to sync cache for %s informer", name)
		}
	}

	// Start worker goroutines
	for i := 0; i < workers; i++ {
		go wait.Until(c.runWorker, time.Second, ctx.Done())
	}

	// Start findings processor
	go c.processFindings(ctx)

	<-ctx.Done()
	klog.Info("Shutting down security controller")
	return nil
}

// runWorker processes items from the workqueue
func (c *SecurityController) runWorker() {
	klog.V(4).Info("Worker started processing items")
	for c.processNextItem() {
	}
	klog.V(4).Info("Worker finished processing items")
}

// processNextItem processes a single item from the workqueue
func (c *SecurityController) processNextItem() bool {
	obj, shutdown := c.workqueue.Get()
	if shutdown {
		klog.V(2).Info("Work queue is shutting down")
		return false
	}
	defer c.workqueue.Done(obj)

	klog.V(4).Infof("Processing item of type: %T", obj)

	err := c.auditObject(obj)
	if err != nil {
		// Log error and retry
		if c.workqueue.NumRequeues(obj) < 5 {
			klog.Warningf("Error processing object (will retry): %v", err)
			c.workqueue.AddRateLimited(obj)
			return true
		}
		// Max retries reached
		klog.Errorf("Dropping object after max retries: %v", err)
		c.workqueue.Forget(obj)
		return true
	}

	klog.V(4).Info("Successfully processed item")
	c.workqueue.Forget(obj)
	return true
}

// processFindings handles the findings from security audits
func (c *SecurityController) processFindings(ctx context.Context) {
	for {
		select {
		case finding := <-c.findings:
			// Process the finding (e.g., store in database, send alerts)
			c.handleFinding(finding)
		case <-ctx.Done():
			return
		}
	}
}

func (c *SecurityController) handleFinding(finding types.Finding) {
	klog.V(2).Infof("Security finding detected:")
	klog.V(2).Infof("  Severity: %s", finding.Severity)
	klog.V(2).Infof("  Category: %s", finding.Category)
	klog.V(2).Infof("  Description: %s", finding.Description)
	if finding.Resource != "" {
		klog.V(2).Infof("  Resource: %s", finding.Resource)
	}
	if finding.Namespace != "" {
		klog.V(2).Infof("  Namespace: %s", finding.Namespace)
	}
	if finding.Suggestion != "" {
		klog.V(2).Infof("  Suggestion: %s", finding.Suggestion)
	}
}

// enqueueObject adds an object to the workqueue
func (c *SecurityController) enqueueObject(obj interface{}) {
	c.workqueue.Add(obj)
}

// createInformerForScope creates appropriate informer based on scope
func (c *SecurityController) createInformerForScope(scope string) (cache.SharedIndexInformer, error) {
	// Create shared informer factory
	factory := informers.NewSharedInformerFactory(c.config.Clientset, 10*time.Minute)

	var informer cache.SharedIndexInformer

	switch scope {
	case "pods":
		informer = factory.Core().V1().Pods().Informer()
	case "deployments":
		informer = factory.Apps().V1().Deployments().Informer()
	case "services":
		informer = factory.Core().V1().Services().Informer()
	case "network":
		informer = factory.Networking().V1().NetworkPolicies().Informer()
	case "rbac":
		// For RBAC, we might want to watch multiple resources
		// Here's an example for Roles, but you might want to add more
		informer = factory.Rbac().V1().Roles().Informer()
	default:
		return nil, fmt.Errorf("unsupported scope: %s", scope)
	}

	return informer, nil
}

// helper method to better handle runtime objects
func (c *SecurityController) auditObject(obj interface{}) error {
	runtimeObj, ok := obj.(runtime.Object)
	if !ok {
		return fmt.Errorf("error converting object to runtime.Object")
	}

	// Log object details
	if meta, ok := obj.(metav1.Object); ok {
		klog.V(3).Infof("Auditing object - Kind: %T, Namespace: %s, Name: %s",
			obj, meta.GetNamespace(), meta.GetName())
	}

	findings := c.rulesEngine.EvaluateRules("all", runtimeObj)

	klog.V(3).Infof("Found %d potential issues", len(findings))

	// Send findings to processor
	for _, finding := range findings {
		klog.V(3).Infof("Processing finding - Severity: %s, Category: %s, Description: %s",
			finding.Severity, finding.Category, finding.Description)
		c.findings <- finding
	}

	return nil
}

// startHealthzServer starts a simple health check server
func (c *SecurityController) startHealthzServer() {
	http.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})
	go http.ListenAndServe(":8080", nil)
}
