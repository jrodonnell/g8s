package controller

import (
	"context"
	"fmt"
	"time"

	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog/v2"
)

const (
	// SuccessSynced is used as part of the Event 'reason' when a CR is synced
	SuccessSynced = "Synced"
	// SuccessfulDelete is used when an object and all its dependents are successfully
	// deleted
	SuccessDeleted = "Deleted"
	// ErrResourceExists is used as part of the Event 'reason' when a CR fails
	// to sync due to a Secret of the same name already existing.
	ErrResourceExists = "ErrResourceExists"

	// MessageResourceExists is the message used for Events when a resource
	// fails to sync due to a Secret already existing
	MessageResourceExists = "Resource %q already exists and is not managed by Resource"
	// MessageResourceSynced is the message used for an Event fired when a CR
	// is synced successfully
	MessageResourceSynced = "Resource synced successfully"
	// MessageResourceDeleted is the message used for an Event fired when a CR
	// is synced successfully
	MessageResourceDeleted = "Resource and all dependent objects deleted successfully"
)

type Executor struct {
	// workqueue is a rate limited work queue. This is used to queue work to be
	// processed instead of performing it as soon as a change happens. This
	// means we can ensure we only process a fixed amount of resources at a
	// time, and makes it easy to ensure we are never processing the same item
	// simultaneously in two different workers.
	allowlistWorkqueue           workqueue.RateLimitingInterface
	selfSignedTLSBundleWorkqueue workqueue.RateLimitingInterface
	loginWorkqueue               workqueue.RateLimitingInterface
	sshKeyPairWorkqueue          workqueue.RateLimitingInterface
}

// Run will set up the event handlers for types we are interested in, as well
// as syncing informer caches and starting workers. It will block until stopCh
// is closed, at which point it will shutdown the workqueue and wait for
// workers to finish processing their current work items.
func (c *Controller) Run(ctx context.Context, workers int) error {
	defer utilruntime.HandleCrash()
	defer c.allowlistWorkqueue.ShutDown()
	defer c.loginWorkqueue.ShutDown()
	defer c.selfSignedTLSBundleWorkqueue.ShutDown()
	defer c.sshKeyPairWorkqueue.ShutDown()
	logger := klog.FromContext(ctx)

	// Start the informer factories to begin populating the informer caches
	logger.Info("Starting g8s controller")

	// Wait for the caches to be synced before starting workers
	logger.Info("Waiting for informer caches to sync")

	if ok := cache.WaitForCacheSync(ctx.Done(), c.loginSynced, c.sshKeyPairSynced, c.secretSynced); !ok {
		return fmt.Errorf("failed to wait for caches to sync")
	}

	logger.Info("Starting workers", "count", workers)

	// Launch workers to process resources
	for i := 0; i < workers; i++ {
		go wait.UntilWithContext(ctx, c.runAllowlistWorker, time.Second)
		go wait.UntilWithContext(ctx, c.runSelfSignedTLSBundleWorker, time.Second)
		go wait.UntilWithContext(ctx, c.runLoginWorker, time.Second)
		go wait.UntilWithContext(ctx, c.runSSHKeyPairWorker, time.Second)
	}

	logger.Info("Started workers")
	<-ctx.Done()
	logger.Info("Shutting down workers")

	return nil
}
