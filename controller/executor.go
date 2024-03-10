package controller

import (
	"context"
	"fmt"
	"time"

	"github.com/jrodonnell/g8s/controller/apis/api.g8s.io/v1alpha1"
	"golang.org/x/exp/slices"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog/v2"
)

const (
	// SuccessSynced is used as part of the Event 'reason' when a CR is synced
	SuccessSynced = "Synced"
	// ErrResourceExists is used as part of the Event 'reason' when a CR fails
	// to sync due to a Secret of the same name already existing.
	ErrResourceExists = "ErrResourceExists"

	// MessageResourceExists is the message used for Events when a resource
	// fails to sync due to a Secret already existing
	MessageResourceExists = "Resource %q already exists and is not managed by Resource"
	// MessageResourceSynced is the message used for an Event fired when a CR
	// is synced successfully
	MessageResourceSynced = "Resource synced successfully"
)

type Executor struct {
	// workqueue is a rate limited work queue. This is used to queue work to be
	// processed instead of performing it as soon as a change happens. This
	// means we can ensure we only process a fixed amount of resources at a
	// time, and makes it easy to ensure we are never processing the same item
	// simultaneously in two different workers.
	allowlistWorkqueue     workqueue.RateLimitingInterface
	kubeTLSBundleWorkqueue workqueue.RateLimitingInterface
	loginWorkqueue         workqueue.RateLimitingInterface
	sshKeyPairWorkqueue    workqueue.RateLimitingInterface
}

// Run will set up the event handlers for types we are interested in, as well
// as syncing informer caches and starting workers. It will block until stopCh
// is closed, at which point it will shutdown the workqueue and wait for
// workers to finish processing their current work items.
func (c *Controller) Run(ctx context.Context, workers int) error {
	defer utilruntime.HandleCrash()
	defer c.loginWorkqueue.ShutDown()
	logger := klog.FromContext(ctx)

	// Start the informer factories to begin populating the informer caches
	logger.Info("Starting g8s controller")

	// Wait for the caches to be synced before starting workers
	logger.Info("Waiting for informer caches to sync")

	if ok := cache.WaitForCacheSync(ctx.Done(), c.loginsSynced, c.sshKeyPairsSynced, c.clusterRolesSynced,
		c.mutatingWebhookConfigurationsSynced, c.secretsSynced); !ok {
		return fmt.Errorf("failed to wait for caches to sync")
	}

	logger.Info("Starting workers", "count", workers)
	// Launch two workers to process At resources
	for i := 0; i < workers; i++ {
		go wait.UntilWithContext(ctx, c.runAllowlistWorker, time.Second)
		go wait.UntilWithContext(ctx, c.runKubeTLSBundleWorker, time.Second)
		go wait.UntilWithContext(ctx, c.runLoginWorker, time.Second)
		go wait.UntilWithContext(ctx, c.runSSHKeyPairWorker, time.Second)
	}

	logger.Info("Started workers")
	<-ctx.Done()
	logger.Info("Shutting down workers")

	return nil
}

func newClusterRole(s *corev1.Secret) *rbacv1.ClusterRole {
	name := s.ObjectMeta.Name
	idx := slices.IndexFunc(s.OwnerReferences, func(o metav1.OwnerReference) bool { return o.APIVersion == "api.g8s.io/v1alpha1" })
	ownerKind := s.OwnerReferences[idx].Kind
	return &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
			OwnerReferences: []metav1.OwnerReference{
				*metav1.NewControllerRef(s, v1alpha1.SchemeGroupVersion.WithKind(ownerKind)),
			},
			Annotations: map[string]string{
				"controller": "g8s",
			},
		},
		Rules: []rbacv1.PolicyRule{{
			Verbs:         []string{"get", "list", "watch"},
			APIGroups:     []string{""},
			Resources:     []string{"secrets"},
			ResourceNames: []string{name},
		}},
	}
}
