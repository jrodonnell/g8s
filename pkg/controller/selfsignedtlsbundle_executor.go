package controller

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog/v2"

	g8sv1alpha1 "github.com/jrodonnell/g8s/pkg/controller/apis/api.g8s.io/v1alpha1"
	internalv1alpha1 "github.com/jrodonnell/g8s/pkg/controller/apis/internal.g8s.io/v1alpha1"
)

// runSelfSignedTLSBundleWorker is a long-running function that will continually call the
// processNextSelfSignedTLSBundleWorkItem function in order to read and process a message on the
// workqueue.
func (c *Controller) runSelfSignedTLSBundleWorker(ctx context.Context) {
	for c.processNextSelfSignedTLSBundleWorkItem(ctx) {
	}
}

// processNextSelfSignedTLSBundleWorkItem will read a single work item off the workqueue and
// attempt to process it, by calling the selfSignedTLSBundleSyncHandler.
func (c *Controller) processNextSelfSignedTLSBundleWorkItem(ctx context.Context) bool {
	obj, shutdown := c.selfSignedTLSBundleWorkqueue.Get()
	logger := klog.FromContext(ctx)

	if shutdown {
		return false
	}

	// We wrap this block in a func so we can defer c.selfSignedTLSBundleWorkqueue.Done.
	err := func(obj interface{}) error {
		// We call Done here so the workqueue knows we have finished
		// processing this item. We also must remember to call Forget if we
		// do not want this work item being re-queued. For example, we do
		// not call Forget if a transient error occurs, instead the item is
		// put back on the workqueue and attempted again after a back-off
		// period.
		defer c.selfSignedTLSBundleWorkqueue.Done(obj)
		var key string
		var ok bool
		// We expect strings to come off the workqueue. These are of the
		// form namespace/name. We do this as the delayed nature of the
		// workqueue means the items in the informer cache may actually be
		// more up to date that when the item was initially put onto the
		// workqueue.
		if key, ok = obj.(string); !ok {
			// As the item in the workqueue is actually invalid, we call
			// Forget here else we'd go into a loop of attempting to
			// process a work item that is invalid.
			c.selfSignedTLSBundleWorkqueue.Forget(obj)
			utilruntime.HandleError(fmt.Errorf("expected string in workqueue but got %#v", obj))
			return nil
		}
		// Run the selfSignedTLSBundleSyncHandler, passing it the namespace/name string of the
		// SelfSignedTLSBundle resource to be synced.
		if err := c.selfSignedTLSBundleSyncHandler(ctx, key); err != nil {
			fmt.Println("key: ", key)
			// Put the item back on the workqueue to handle any transient errors.
			c.selfSignedTLSBundleWorkqueue.AddRateLimited(key)
			return fmt.Errorf("error syncing '%s': %s, requeuing", key, err.Error())
		}
		// Finally, if no error occurs we Forget this item so it does not
		// get queued again until another change happens.
		c.selfSignedTLSBundleWorkqueue.Forget(obj)
		logger.Info("Successfully synced", "resourceName", key)
		return nil
	}(obj)

	if err != nil {
		utilruntime.HandleError(err)
		return true
	}

	return true
}

// selfSignedTLSBundleSyncHandler compares the actual state with the desired, and attempts to
// converge the two. It then updates the Status block of the SelfSignedTLSBundle resource
// with the current status of the resource.
func (c *Controller) selfSignedTLSBundleSyncHandler(ctx context.Context, key string) error {
	// Convert the namespace/name string into a distinct namespace and name
	logger := klog.LoggerWithValues(klog.FromContext(ctx), "resourceName", key)

	namespace, name, err := cache.SplitMetaNamespaceKey(key)
	if err != nil {
		utilruntime.HandleError(fmt.Errorf("invalid resource key: %s", key))
		return nil
	}

	// Get the SelfSignedTLSBundle resource with this namespace/name
	selfSignedTLSBundleFromLister, err := c.selfSignedTLSBundleLister.SelfSignedTLSBundles(namespace).Get(name)
	if err != nil {
		// The SelfSignedTLSBundle resource may no longer exist, in which case we stop
		// processing.
		if errors.IsNotFound(err) {
			utilruntime.HandleError(fmt.Errorf("SelfSignedTLSBundle '%s' in work queue no longer exists", key))
			return nil
		}

		return err
	}

	// DeepCopy for safety
	selfSignedTLSBundle := selfSignedTLSBundleFromLister.DeepCopy()

	backendName := "selfsignedtlsbundle-" + selfSignedTLSBundle.ObjectMeta.Name
	historyName := "selfsignedtlsbundle-" + selfSignedTLSBundle.ObjectMeta.Name + "-history"

	// Get the backend Secret, history Secret, and CSR with this namespace/name
	backendFromLister, berr := c.secretLister.Secrets(selfSignedTLSBundle.Namespace).Get(backendName)
	historyFromLister, herr := c.secretLister.Secrets(selfSignedTLSBundle.Namespace).Get(historyName)
	//_, csrerr := c.certificateSigningRequestLister.Get(selfSignedTLSBundle.Name)

	// DeepCopy for safety
	backend := backendFromLister.DeepCopy()
	history := historyFromLister.DeepCopy()

	g8sSelfSignedTLSBundle := internalv1alpha1.NewSelfSignedTLSBundle(selfSignedTLSBundle)

	// If the backend and history resources don't exist, create them
	if errors.IsNotFound(berr) && errors.IsNotFound(herr) {
		logger.V(4).Info("Create backend and history Secret resources and CSR")

		// Create the CSR object needed to create the certificate
		//if errors.IsNotFound(csrerr) {
		//	go newCSR(g8sSelfSignedTLSBundle)
		//}

		historyContent := g8sSelfSignedTLSBundle.Rotate()
		backendContent := make(map[string]string)
		backendContent["key.pem"] = historyContent["key.pem-0"]
		backendContent["cert.pem"] = historyContent["cert.pem-0"]
		backendContent["cacert.pem"] = historyContent["cacert.pem-0"]

		backend, err = c.Client.kubeClientset.CoreV1().Secrets(selfSignedTLSBundle.Namespace).Create(ctx, internalv1alpha1.NewBackendSecret(g8sSelfSignedTLSBundle, backendContent, "g8s.io/self-signed-tls-bundle"), metav1.CreateOptions{})
		if err != nil {
			return err
		}
		history, err = c.Client.kubeClientset.CoreV1().Secrets(selfSignedTLSBundle.Namespace).Create(ctx, internalv1alpha1.NewHistorySecret(g8sSelfSignedTLSBundle, historyContent), metav1.CreateOptions{})
	} else if errors.IsNotFound(berr) { // backend dne but history does, rebuild backend from history
		logger.V(4).Info("Create backend Secret resources from history")
		content := make(map[string]string)
		content["key.pem"] = string(history.Data["key.pem-0"])
		content["cert.pem"] = string(history.Data["cert.pem-0"])
		content["cacert.pem"] = string(history.Data["cacert.pem-0"])
		backend, err = c.Client.kubeClientset.CoreV1().Secrets(selfSignedTLSBundle.Namespace).Create(ctx, internalv1alpha1.NewBackendSecret(g8sSelfSignedTLSBundle, content, "g8s.io/self-signed-tls-bundle"), metav1.CreateOptions{})
	} else if errors.IsNotFound(herr) { // backend exists but history dne, rebuild history from backend
		logger.V(4).Info("Create history Secret resources from backend")
		content := make(map[string]string)
		content["key.pem-0"] = string(backend.Data["key.pem"])
		content["cert.pem-0"] = string(backend.Data["cert.pem"])
		content["cacert.pem-0"] = string(backend.Data["cacert.pem"])
		history, err = c.Client.kubeClientset.CoreV1().Secrets(selfSignedTLSBundle.Namespace).Create(ctx, internalv1alpha1.NewHistorySecret(g8sSelfSignedTLSBundle, content), metav1.CreateOptions{})
	} else {
		logger.V(4).Info("Secret resources for history and backend exist")
	}

	// If an error occurs during Get/Create, we'll requeue the item so we can
	// attempt processing again later. This could have been caused by a
	// temporary network failure, or any other transient reason.
	if err != nil {
		return err
	}

	// If the Secret is not controlled by this SelfSignedTLSBundle resource, we should log
	// a warning to the event recorder and return error msg.
	if !metav1.IsControlledBy(backend, selfSignedTLSBundle) {
		msg := fmt.Sprintf(MessageResourceExists, backend.Name)
		c.recorder.Event(selfSignedTLSBundle, corev1.EventTypeWarning, ErrResourceExists, msg)
		return fmt.Errorf("%s", msg)
	} else if !metav1.IsControlledBy(history, selfSignedTLSBundle) {
		msg := fmt.Sprintf(MessageResourceExists, history.Name)
		c.recorder.Event(selfSignedTLSBundle, corev1.EventTypeWarning, ErrResourceExists, msg)
		return fmt.Errorf("%s", msg)
	}

	// Finally, we update the status block of the SelfSignedTLSBundle resource to reflect the
	// current state of the world
	err = c.updateSelfSignedTLSBundleStatus(selfSignedTLSBundle)
	if err != nil {
		return err
	}

	c.recorder.Event(selfSignedTLSBundle, corev1.EventTypeNormal, SuccessSynced, MessageResourceSynced)
	return nil
}

func (c *Controller) updateSelfSignedTLSBundleStatus(selfSignedTLSBundle *g8sv1alpha1.SelfSignedTLSBundle) error {
	// NEVER modify objects from the store. It's a read-only, local cache.
	// You can use DeepCopy() to make a deep copy of original object and modify this copy
	// Or create a copy manually for better performance
	selfSignedTLSBundleCopy := selfSignedTLSBundle.DeepCopy()
	selfSignedTLSBundleCopy.Status.Ready = true
	// If the CustomResourceSubresources feature gate is not enabled,
	// we must use Update instead of UpdateStatus to update the Status block of the SelfSignedTLSBundle resource.
	// UpdateStatus will not allow changes to the Spec of the resource,
	// which is ideal for ensuring nothing other than resource status has been updated.
	_, err := c.Client.g8sClientset.ApiV1alpha1().SelfSignedTLSBundles(selfSignedTLSBundle.Namespace).UpdateStatus(context.TODO(), selfSignedTLSBundleCopy, metav1.UpdateOptions{})
	return err
}

// enqueueSelfSignedTLSBundle takes a SelfSignedTLSBundle resource and converts it into a namespace/name
// string which is then put onto the workqueue. This method should *not* be
// passed resources of any type other than SelfSignedTLSBundle.
func (c *Controller) enqueueSelfSignedTLSBundle(obj any) {
	var key string
	var err error
	if key, err = cache.MetaNamespaceKeyFunc(obj); err != nil {
		utilruntime.HandleError(err)
		return
	}
	c.selfSignedTLSBundleWorkqueue.Add(key)
}

// handleSelfSignedTLSBundleObject will take any resource implementing metav1.Object and attempt
// to find the SelfSignedTLSBundle resource that 'owns' it. It does this by looking at the
// objects metadata.ownerReferences field for an appropriate OwnerReference.
// It then enqueues that SelfSignedTLSBundle resource to be processed. If the object does not
// have an appropriate OwnerReference, it will simply be skipped.
func (c *Controller) handleSelfSignedTLSBundleObject(obj interface{}) {
	var object metav1.Object
	var ok bool
	logger := klog.FromContext(context.Background())
	if object, ok = obj.(metav1.Object); !ok {
		tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
		if !ok {
			utilruntime.HandleError(fmt.Errorf("error decoding object, invalid type"))
			return
		}
		object, ok = tombstone.Obj.(metav1.Object)
		if !ok {
			utilruntime.HandleError(fmt.Errorf("error decoding object tombstone, invalid type"))
			return
		}
		logger.V(4).Info("Recovered deleted object", "resourceName", object.GetName())
	}
	logger.V(4).Info("Processing object", "object", klog.KObj(object))
	if ownerRef := metav1.GetControllerOf(object); ownerRef != nil {
		// If this object is not owned by a SelfSignedTLSBundle, we should not do anything more
		// with it.
		if ownerRef.Kind != "SelfSignedTLSBundle" {
			return
		}

		selfSignedTLSBundle, err := c.selfSignedTLSBundleLister.SelfSignedTLSBundles(object.GetNamespace()).Get(ownerRef.Name)
		if err != nil {
			logger.V(4).Info("Ignore orphaned object", "object", klog.KObj(object), "selfSignedTLSBundle", ownerRef.Name)
			return
		}

		c.enqueueSelfSignedTLSBundle(selfSignedTLSBundle)
		return
	}
}

// Set up an event handler for when SelfSignedTLSBundle and/or their backend and history Secret resources change
func (c *Controller) setSelfSignedTLSBundleInformersEventHandlers(ctx context.Context) {
	logger := klog.FromContext(ctx)
	c.selfSignedTLSBundleInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: c.enqueueSelfSignedTLSBundle,
		UpdateFunc: func(old, new interface{}) {
			c.enqueueSelfSignedTLSBundle(new)
		},
		DeleteFunc: func(obj interface{}) {
			sstls, ok := obj.(*g8sv1alpha1.SelfSignedTLSBundle)
			if !ok {
				logger.Error(nil, "obj is not a SelfSignedTLSBundle")
			}
			c.recorder.Event(sstls, corev1.EventTypeNormal, SuccessDeleted, MessageResourceDeleted)
		},
	})

	// Set up an event handler for when SelfSignedTLSBundle backend and history Secret resources change. This
	// handler will lookup the owner of the given Secret, and if it is
	// owned by a SelfSignedTLSBundle resource then the handler will enqueue that SelfSignedTLSBundle resource for
	// processing. This way, we don't need to implement custom logic for
	// handling Secret resources. More info on this pattern:
	// https://github.com/kubernetes/community/blob/8cafef897a22026d42f5e5bb3f104febe7e29830/contributors/devel/controllers.md
	c.secretInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: c.handleSelfSignedTLSBundleObject,
		UpdateFunc: func(old, new interface{}) {
			newDepl := new.(*corev1.Secret)
			oldDepl := old.(*corev1.Secret)
			if newDepl.ResourceVersion == oldDepl.ResourceVersion {
				// Periodic resync will send update events for all known Secrets.
				// Two different versions of the same Secret will always have different ResourceVersions.
				// This section will skip calling handleObject() if they are the same.
				return
			}
			c.handleSelfSignedTLSBundleObject(new)
		},
		DeleteFunc: c.handleSelfSignedTLSBundleObject,
	})
}
