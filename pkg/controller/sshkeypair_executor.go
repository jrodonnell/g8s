package controller

import (
	"context"
	"fmt"

	"github.com/the-gizmo-dojo/g8s/pkg/apis/api.g8s.io/v1alpha1"
	"github.com/the-gizmo-dojo/g8s/pkg/g8s"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog/v2"
)

// runsshKeyPairWorker is a long-running function that will continually call the
// processNextsshKeyPairWorkItem function in order to read and process a message on the
// workqueue.
func (c *Controller) runSSHKeyPairWorker(ctx context.Context) {
	for c.processNextsshKeyPairWorkItem(ctx) {
	}
}

// processNextsshKeyPairWorkItem will read a single work item off the workqueue and
// attempt to process it, by calling the sshKeyPairSyncHandler.
func (c *Controller) processNextsshKeyPairWorkItem(ctx context.Context) bool {
	obj, shutdown := c.sshKeyPairWorkqueue.Get()
	logger := klog.FromContext(ctx)

	if shutdown {
		return false
	}

	// We wrap this block in a func so we can defer c.sshKeyPairWorkqueue.Done.
	err := func(obj interface{}) error {
		// We call Done here so the workqueue knows we have finished
		// processing this item. We also must remember to call Forget if we
		// do not want this work item being re-queued. For example, we do
		// not call Forget if a transient error occurs, instead the item is
		// put back on the workqueue and attempted again after a back-off
		// period.
		defer c.sshKeyPairWorkqueue.Done(obj)
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
			c.sshKeyPairWorkqueue.Forget(obj)
			utilruntime.HandleError(fmt.Errorf("expected string in workqueue but got %#v", obj))
			return nil
		}
		// Run the sshKeyPairSyncHandler, passing it the namespace/name string of the
		// sshKeyPair resource to be synced.
		if err := c.sshKeyPairSyncHandler(ctx, key); err != nil {
			// Put the item back on the workqueue to handle any transient errors.
			c.sshKeyPairWorkqueue.AddRateLimited(key)
			return fmt.Errorf("error syncing '%s': %s, requeuing", key, err.Error())
		}
		// Finally, if no error occurs we Forget this item so it does not
		// get queued again until another change happens.
		c.sshKeyPairWorkqueue.Forget(obj)
		logger.Info("Successfully synced", "resourceName", key)
		return nil
	}(obj)

	if err != nil {
		utilruntime.HandleError(err)
		return true
	}

	return true
}

// sshKeyPairSyncHandler compares the actual state with the desired, and attempts to
// converge the two. It then updates the Status block of the sshKeyPair resource
// with the current status of the resource.
func (c *Controller) sshKeyPairSyncHandler(ctx context.Context, key string) error {
	// Convert the namespace/name string into a distinct namespace and name
	logger := klog.LoggerWithValues(klog.FromContext(ctx), "resourceName", key)

	namespace, name, err := cache.SplitMetaNamespaceKey(key)
	if err != nil {
		utilruntime.HandleError(fmt.Errorf("invalid resource key: %s", key))
		return nil
	}

	// Get the sshKeyPair resource with this namespace/name
	sshKeyPair, err := c.sshKeyPairsLister.SSHKeyPairs(namespace).Get(name)
	if err != nil {
		// The sshKeyPair resource may no longer exist, in which case we stop
		// processing.
		if errors.IsNotFound(err) {
			utilruntime.HandleError(fmt.Errorf("SSHKeyPair '%s' in work queue no longer exists", key))
			return nil
		}

		return err
	}

	backendName := sshKeyPair.ObjectMeta.Name
	historyName := sshKeyPair.ObjectMeta.Name + "-history"

	// Get the backend Secret and history Secret with this namespace/name
	backendFromLister, berr := c.secretsLister.Secrets(sshKeyPair.Namespace).Get(backendName)
	historyFromLister, herr := c.secretsLister.Secrets(sshKeyPair.Namespace).Get(historyName)

	backend := backendFromLister.DeepCopy()
	history := historyFromLister.DeepCopy()

	if err != nil {
		utilruntime.HandleError(fmt.Errorf("invalid resource key: %s", key))
		return nil
	}

	// If the backend and history resources don't exist, create them
	if errors.IsNotFound(berr) && errors.IsNotFound(herr) {
		logger.V(4).Info("Create backend and history Secret resources")
		g8sKp := g8s.SSHKeyPairWithHistory(sshKeyPair)
		g8sKpContent := g8sKp.Rotate()
		backend, err = c.Client.kubeClientset.CoreV1().Secrets(sshKeyPair.Namespace).Create(ctx, newSSHKeyPairBackendSecret(sshKeyPair, g8sKpContent["ssh.pub-0"], g8sKpContent["ssh.key-0"]), metav1.CreateOptions{})
		history, err = c.Client.kubeClientset.CoreV1().Secrets(sshKeyPair.Namespace).Create(ctx, newSSHKeyPairHistorySecret(sshKeyPair, g8sKpContent), metav1.CreateOptions{})
	} else if errors.IsNotFound(berr) { // backend dne but history does, rebuild backend from history
		logger.V(4).Info("Create backend Secret resources from history")
		pub := string(history.Data["ssh.pub-0"])
		key := string(history.Data["ssh.key-0"])
		backend, err = c.Client.kubeClientset.CoreV1().Secrets(sshKeyPair.Namespace).Create(ctx, newSSHKeyPairBackendSecret(sshKeyPair, pub, key), metav1.CreateOptions{})
	} else if errors.IsNotFound(herr) { // backend exists but history dne, rebuild history from backend
		logger.V(4).Info("Create history Secret resources from backend")
		kp := make(map[string]string)
		kp["ssh.pub-0"] = string(backend.Data["ssh.pub"])
		kp["ssh.key-0"] = string(backend.Data["ssh.key"])
		history, err = c.Client.kubeClientset.CoreV1().Secrets(sshKeyPair.Namespace).Create(ctx, newSSHKeyPairHistorySecret(sshKeyPair, kp), metav1.CreateOptions{})
	} else {
		logger.V(4).Info("Secret resources for history and backend exist")
	}
	// If an error occurs during Get/Create, we'll requeue the item so we can
	// attempt processing again later. This could have been caused by a
	// temporary network failure, or any other transient reason.
	if err != nil {
		return err
	}

	// If the Secret is not controlled by this sshKeyPair resource, we should log
	// a warning to the event recorder and return error msg.
	if !metav1.IsControlledBy(backend, sshKeyPair) {
		msg := fmt.Sprintf(MessageResourceExists, backend.Name)
		c.recorder.Event(sshKeyPair, corev1.EventTypeWarning, ErrResourceExists, msg)
		return fmt.Errorf("%s", msg)
	}

	// If the Secret is not controlled by this sshKeyPair resource, we should log
	// a warning to the event recorder and return error msg.
	if !metav1.IsControlledBy(history, sshKeyPair) {
		msg := fmt.Sprintf(MessageResourceExists, history.Name)
		c.recorder.Event(sshKeyPair, corev1.EventTypeWarning, ErrResourceExists, msg)
		return fmt.Errorf("%s", msg)
	}

	// Finally, we update the status block of the sshKeyPair resource to reflect the
	// current state of the world
	err = c.updateSSHKeyPairtatus(sshKeyPair, backend)
	if err != nil {
		return err
	}

	// Finally, we update the status block of the sshKeyPair resource to reflect the
	// current state of the world
	err = c.updateSSHKeyPairtatus(sshKeyPair, history)
	if err != nil {
		return err
	}

	c.recorder.Event(sshKeyPair, corev1.EventTypeNormal, SuccessSynced, MessageResourceSynced)
	return nil
}

func (c *Controller) updateSSHKeyPairtatus(sshKeyPair *v1alpha1.SSHKeyPair, secret *corev1.Secret) error {
	// NEVER modify objects from the store. It's a read-only, local cache.
	// You can use DeepCopy() to make a deep copy of original object and modify this copy
	// Or create a copy manually for better performance
	sshKeyPairCopy := sshKeyPair.DeepCopy()
	// If the CustomResourceSubresources feature gate is not enabled,
	// we must use Update instead of UpdateStatus to update the Status block of the sshKeyPair resource.
	// UpdateStatus will not allow changes to the Spec of the resource,
	// which is ideal for ensuring nothing other than resource status has been updated.
	_, err := c.Client.g8sClientset.ApiV1alpha1().SSHKeyPairs(sshKeyPair.Namespace).UpdateStatus(context.TODO(), sshKeyPairCopy, metav1.UpdateOptions{})
	return err
}

// enqueuesshKeyPair takes a sshKeyPair resource and converts it into a namespace/name
// string which is then put onto the workqueue. This method should *not* be
// passed resources of any type other than sshKeyPair.
func (c *Controller) enqueueSSHKeyPair(obj any) {
	var key string
	var err error
	if key, err = cache.MetaNamespaceKeyFunc(obj); err != nil {
		utilruntime.HandleError(err)
		return
	}
	c.sshKeyPairWorkqueue.Add(key)
}

// handlesshKeyPairObject will take any resource implementing metav1.Object and attempt
// to find the sshKeyPair resource that 'owns' it. It does this by looking at the
// objects metadata.ownerReferences field for an appropriate OwnerReference.
// It then enqueues that sshKeyPair resource to be processed. If the object does not
// have an appropriate OwnerReference, it will simply be skipped.
func (c *Controller) handleSSHKeyPairObject(obj interface{}) {
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
		// If this object is not owned by a sshKeyPair, we should not do anything more
		// with it.
		if ownerRef.Kind != "sshKeyPair" {
			return
		}

		sshKeyPair, err := c.sshKeyPairsLister.SSHKeyPairs(object.GetNamespace()).Get(ownerRef.Name)
		if err != nil {
			logger.V(4).Info("Ignore orphaned object", "object", klog.KObj(object), "sshKeyPair", ownerRef.Name)
			return
		}

		c.enqueueSSHKeyPair(sshKeyPair)
		return
	}
}

// newSSHKeyPairBackendSecret creates a new Secret for a SSHKeyPair resource which contains the actual login.
// It also sets the appropriate OwnerReferences on the resource so handleSSHKeyPairObject can discover
// the SSHKeyPair resource that 'owns' it.
func newSSHKeyPairBackendSecret(ssh *v1alpha1.SSHKeyPair, pub, key string) *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "sshkeypair-" + ssh.ObjectMeta.Name,
			Namespace: ssh.ObjectMeta.Namespace,
			OwnerReferences: []metav1.OwnerReference{
				*metav1.NewControllerRef(ssh, v1alpha1.SchemeGroupVersion.WithKind("SSHKeyPair")),
			},
			Annotations: map[string]string{
				"controller": "g8s",
			},
		},
		Immutable: boolPtr(true),
		StringData: map[string]string{
			"ssh.pub": pub,
			"ssh.key": key,
		},
		Type: "Opaque",
	}
}

// newSSHKeyPairHistorySecret creates a new Secret for a SSHKeyPair resource which contains the password's history.
// It also sets the appropriate OwnerReferences on the resource so handleSSHKeyPairObject can discover
// the SSHKeyPair resource that 'owns' it.
func newSSHKeyPairHistorySecret(ssh *v1alpha1.SSHKeyPair, kphist map[string]string) *corev1.Secret {

	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "sshkeypair-" + ssh.ObjectMeta.Name + "-history",
			Namespace: ssh.ObjectMeta.Namespace,
			OwnerReferences: []metav1.OwnerReference{
				*metav1.NewControllerRef(ssh, v1alpha1.SchemeGroupVersion.WithKind("SSHKeyPair")),
			},
			Annotations: map[string]string{
				"controller": "g8s",
			},
		},
		Immutable:  boolPtr(true),
		StringData: kphist,
		Type:       "Opaque",
	}
}
