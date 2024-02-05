package controller

import (
	"context"
	"fmt"

	g8sv1alpha1 "github.com/the-gizmo-dojo/g8s/pkg/apis/api.g8s.io/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog/v2"
)

// runAllowlistWorker is a long-running function that will continually call the
// processNextAllowlistWorkItem function in order to read and process a message on the
// workqueue.
func (c *Controller) runAllowlistWorker(ctx context.Context) {
	for c.processNextAllowlistWorkItem(ctx) {
	}
}

// processNextAllowlistWorkItem will read a single work item off the workqueue and
// attempt to process it, by calling the allowlistSyncHandler.
func (c *Controller) processNextAllowlistWorkItem(ctx context.Context) bool {
	obj, shutdown := c.allowlistWorkqueue.Get()
	logger := klog.FromContext(ctx)

	if shutdown {
		return false
	}

	// We wrap this block in a func so we can defer c.allowlistWorkqueue.Done.
	err := func(obj interface{}) error {
		// We call Done here so the workqueue knows we have finished
		// processing this item. We also must remember to call Forget if we
		// do not want this work item being re-queued. For example, we do
		// not call Forget if a transient error occurs, instead the item is
		// put back on the workqueue and attempted again after a back-off
		// period.
		defer c.allowlistWorkqueue.Done(obj)
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
			c.allowlistWorkqueue.Forget(obj)
			utilruntime.HandleError(fmt.Errorf("expected string in workqueue but got %#v", obj))
			return nil
		}
		// Run the allowlistSyncHandler, passing it the namespace/name string of the
		// Allowlist resource to be synced.
		if err := c.allowlistSyncHandler(ctx, key); err != nil {
			// Put the item back on the workqueue to handle any transient errors.
			c.allowlistWorkqueue.AddRateLimited(key)
			return fmt.Errorf("error syncing '%s': %s, requeuing", key, err.Error())
		}
		// Finally, if no error occurs we Forget this item so it does not
		// get queued again until another change happens.
		c.allowlistWorkqueue.Forget(obj)
		logger.Info("Successfully synced", "resourceName", key)
		return nil
	}(obj)

	if err != nil {
		utilruntime.HandleError(err)
		return true
	}

	return true
}

// allowlistSyncHandler compares the actual state with the desired, and attempts to
// converge the two. It then updates the Status block of the Allowlist resource
// with the current status of the resource.
func (c *Controller) allowlistSyncHandler(ctx context.Context, key string) error {
	// Convert the namespace/name string into a distinct namespace and name

	// TODO reimplement for Allowlsits
	/*
		logger := klog.LoggerWithValues(klog.FromContext(ctx), "resourceName", key)

		namespace, name, err := cache.SplitMetaNamespaceKey(key)
		if err != nil {
			utilruntime.HandleError(fmt.Errorf("invalid resource key: %s", key))
			return nil
		}

		// Get the Allowlist resource with this namespace/name
		allowlistFromLister, err := c.allowlistsLister.Allowlists(namespace).Get(name)
		if err != nil {
			// The Allowlist resource may no longer exist, in which case we stop
			// processing.
			if errors.IsNotFound(err) {
				utilruntime.HandleError(fmt.Errorf("Allowlist '%s' in work queue no longer exists", key))
				return nil
			}

			return err
		}

			// DeepCopy for safety
			allowlist := allowlistFromLister.DeepCopy()

			backendName := "allowlist-" + allowlist.ObjectMeta.Name
			historyName := "allowlist-" + allowlist.ObjectMeta.Name + "-history"

			// Get the backend Secret and history Secret with this namespace/name
			backendFromLister, berr := c.secretsLister.Secrets(allowlist.Namespace).Get(backendName)
			historyFromLister, herr := c.secretsLister.Secrets(allowlist.Namespace).Get(historyName)

			// DeepCopy for safety
			backend := backendFromLister.DeepCopy()
			history := historyFromLister.DeepCopy()

			g8sPw := internalv1alpha1.AllowlistWithHistory(allowlist)
			// If the backend and history resources don't exist, create them
			if errors.IsNotFound(berr) && errors.IsNotFound(herr) {
				logger.V(4).Info("Create backend and history Secret resources")
				content := g8sPw.Rotate()

				backend, err = c.Client.kubeClientset.CoreV1().Secrets(allowlist.Namespace).Create(ctx, internalv1alpha1.NewBackendSecret(&g8sPw, content), metav1.CreateOptions{})
				history, err = c.Client.kubeClientset.CoreV1().Secrets(allowlist.Namespace).Create(ctx, internalv1alpha1.NewHistorySecret(&g8sPw, content), metav1.CreateOptions{})

				//backend, err = c.Client.kubeClientset.CoreV1().Secrets(allowlist.Namespace).Create(ctx, newAllowlistBackendSecret(allowlist, g8sPwContent["password-0"]), metav1.CreateOptions{})
				//history, err = c.Client.kubeClientset.CoreV1().Secrets(allowlist.Namespace).Create(ctx, newAllowlistHistorySecret(allowlist, g8sPwContent), metav1.CreateOptions{})
			} else if errors.IsNotFound(berr) { // backend dne but history does, rebuild backend from history
				logger.V(4).Info("Create backend Secret resources from history")
				content := make(map[string]string)
				content["password"] = string(history.Data["password-0"])
				backend, err = c.Client.kubeClientset.CoreV1().Secrets(allowlist.Namespace).Create(ctx, internalv1alpha1.NewBackendSecret(&g8sPw, content), metav1.CreateOptions{})
				//backend, err = c.Client.kubeClientset.CoreV1().Secrets(allowlist.Namespace).Create(ctx, newAllowlistBackendSecret(allowlist, string(pwbyte)), metav1.CreateOptions{})
			} else if errors.IsNotFound(herr) { // backend exists but history dne, rebuild history from backend
				logger.V(4).Info("Create history Secret resources from backend")
				content := make(map[string]string)
				content["password-0"] = string(backend.Data["password"])
				history, err = c.Client.kubeClientset.CoreV1().Secrets(allowlist.Namespace).Create(ctx, internalv1alpha1.NewHistorySecret(&g8sPw, content), metav1.CreateOptions{})
				//history, err = c.Client.kubeClientset.CoreV1().Secrets(allowlist.Namespace).Create(ctx, newAllowlistHistorySecret(allowlist, pwmap), metav1.CreateOptions{})
			} else {
				logger.V(4).Info("Secret resources for history and backend exist")
			}

		// If an error occurs during Get/Create, we'll requeue the item so we can
		// attempt processing again later. This could have been caused by a
		// temporary network failure, or any other transient reason.
		if err != nil {
			return err
		}

		// If the Secret is not controlled by this Allowlist resource, we should log
		// a warning to the event recorder and return error msg.
		if !metav1.IsControlledBy(backend, allowlist) {
			msg := fmt.Sprintf(MessageResourceExists, backend.Name)
			c.recorder.Event(allowlist, corev1.EventTypeWarning, ErrResourceExists, msg)
			return fmt.Errorf("%s", msg)
		} else if !metav1.IsControlledBy(history, allowlist) {
			msg := fmt.Sprintf(MessageResourceExists, history.Name)
			c.recorder.Event(allowlist, corev1.EventTypeWarning, ErrResourceExists, msg)
			return fmt.Errorf("%s", msg)
		}

		// Get the ClusterRole for this Allowlist
		_, crerr := c.clusterRolesLister.Get(backendName)

		// if ClusterRole does not exist, create it
		if errors.IsNotFound(crerr) {
			logger.V(4).Info("Create ClusterRole")
			_, err := c.Client.kubeClientset.RbacV1().ClusterRoles().Create(ctx, newClusterRole(backend), metav1.CreateOptions{})

			// If an error occurs during Get/Create, we'll requeue the item so we can
			// attempt processing again later. This could have been caused by a
			// temporary network failure, or any other transient reason.
			if err != nil {
				return err
			}
		}

		// Finally, we update the status block of the Allowlist resource to reflect the
		// current state of the world
		err = c.updateAllowlistStatus(allowlist)
		if err != nil {
			return err
		}

		c.recorder.Event(allowlist, corev1.EventTypeNormal, SuccessSynced, MessageResourceSynced)
	*/
	return nil
}

func (c *Controller) updateAllowlistStatus(allowlist *g8sv1alpha1.Allowlist) error {
	// NEVER modify objects from the store. It's a read-only, local cache.
	// You can use DeepCopy() to make a deep copy of original object and modify this copy
	// Or create a copy manually for better performance
	allowlistCopy := allowlist.DeepCopy()
	allowlistCopy.Status.Ready = true
	// If the CustomResourceSubresources feature gate is not enabled,
	// we must use Update instead of UpdateStatus to update the Status block of the Allowlist resource.
	// UpdateStatus will not allow changes to the Spec of the resource,
	// which is ideal for ensuring nothing other than resource status has been updated.
	_, err := c.Client.g8sClientset.ApiV1alpha1().Allowlists(allowlist.Namespace).UpdateStatus(context.TODO(), allowlistCopy, metav1.UpdateOptions{})
	return err
}

// enqueueAllowlist takes a Allowlist resource and converts it into a namespace/name
// string which is then put onto the workqueue. This method should *not* be
// passed resources of any type other than Allowlist.
func (c *Controller) enqueueAllowlist(obj any) {
	var key string
	var err error
	if key, err = cache.MetaNamespaceKeyFunc(obj); err != nil {
		utilruntime.HandleError(err)
		return
	}
	c.allowlistWorkqueue.Add(key)
}

// handleAllowlistObject will take any resource implementing metav1.Object and attempt
// to find the Allowlist resource that 'owns' it. It does this by looking at the
// objects metadata.ownerReferences field for an appropriate OwnerReference.
// It then enqueues that Allowlist resource to be processed. If the object does not
// have an appropriate OwnerReference, it will simply be skipped.
func (c *Controller) handleAllowlistObject(obj interface{}) {
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
		// If this object is not owned by a Allowlist, we should not do anything more
		// with it.
		if ownerRef.Kind != "Allowlist" {
			return
		}

		allowlist, err := c.allowlistsLister.Allowlists(object.GetNamespace()).Get(ownerRef.Name)
		if err != nil {
			logger.V(4).Info("Ignore orphaned object", "object", klog.KObj(object), "allowlist", ownerRef.Name)
			return
		}

		c.enqueueAllowlist(allowlist)
		return
	}
}

/*
// newAllowlistBackendSecret creates a new Secret for a Allowlist resource which contains the actual allowlist.
// It also sets the appropriate OwnerReferences on the resource so handleAllowlistObject can discover
// the Allowlist resource that 'owns' it.
func newAllowlistBackendSecret(l *g8sv1alpha1.Allowlist, pwstr string) *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "allowlist-" + l.ObjectMeta.Name,
			Namespace: l.ObjectMeta.Namespace,
			OwnerReferences: []metav1.OwnerReference{
				*metav1.NewControllerRef(l, g8sv1alpha1.SchemeGroupVersion.WithKind("Allowlist")),
			},
			Annotations: map[string]string{
				"controller": "g8s",
			},
		},
		Immutable: boolPtr(true),
		StringData: map[string]string{
			"username": l.Spec.Username,
			"password": pwstr,
		},
		Type: "Opaque",
	}
}

// newAllowlistHistorySecret creates a new Secret for a Allowlist resource which contains the password's history.
// It also sets the appropriate OwnerReferences on the resource so handleAllowlistObject can discover
// the Allowlist resource that 'owns' it.
func newAllowlistHistorySecret(l *g8sv1alpha1.Allowlist, pwhist map[string]string) *corev1.Secret {

	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "allowlist-" + l.ObjectMeta.Name + "-history",
			Namespace: l.ObjectMeta.Namespace,
			OwnerReferences: []metav1.OwnerReference{
				*metav1.NewControllerRef(l, g8sv1alpha1.SchemeGroupVersion.WithKind("Allowlist")),
			},
			Annotations: map[string]string{
				"controller": "g8s",
			},
		},
		Immutable:  boolPtr(true),
		StringData: pwhist,
		Type:       "Opaque",
	}
}
*/
