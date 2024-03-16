package controller

import (
	"context"
	"fmt"
	"strings"

	g8sv1alpha1 "github.com/jrodonnell/g8s/pkg/controller/apis/api.g8s.io/v1alpha1"
	internalv1alpha1 "github.com/jrodonnell/g8s/pkg/controller/apis/internal.g8s.io/v1alpha1"
	certsv1 "k8s.io/api/certificates/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog/v2"
)

// runKubeTLSBundleWorker is a long-running function that will continually call the
// processNextKubeTLSBundleWorkItem function in order to read and process a message on the
// workqueue.
func (c *Controller) runKubeTLSBundleWorker(ctx context.Context) {
	for c.processNextKubeTLSBundleWorkItem(ctx) {
	}
}

// processNextKubeTLSBundleWorkItem will read a single work item off the workqueue and
// attempt to process it, by calling the kubeTLSBundleSyncHandler.
func (c *Controller) processNextKubeTLSBundleWorkItem(ctx context.Context) bool {
	obj, shutdown := c.kubeTLSBundleWorkqueue.Get()
	logger := klog.FromContext(ctx)

	if shutdown {
		return false
	}

	// We wrap this block in a func so we can defer c.kubeTLSBundleWorkqueue.Done.
	err := func(obj interface{}) error {
		// We call Done here so the workqueue knows we have finished
		// processing this item. We also must remember to call Forget if we
		// do not want this work item being re-queued. For example, we do
		// not call Forget if a transient error occurs, instead the item is
		// put back on the workqueue and attempted again after a back-off
		// period.
		defer c.kubeTLSBundleWorkqueue.Done(obj)
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
			c.kubeTLSBundleWorkqueue.Forget(obj)
			utilruntime.HandleError(fmt.Errorf("expected string in workqueue but got %#v", obj))
			return nil
		}
		// Run the kubeTLSBundleSyncHandler, passing it the namespace/name string of the
		// KubeTLSBundle resource to be synced.
		if err := c.kubeTLSBundleSyncHandler(ctx, key); err != nil {
			fmt.Println("key: ", key)
			// Put the item back on the workqueue to handle any transient errors.
			c.kubeTLSBundleWorkqueue.AddRateLimited(key)
			return fmt.Errorf("error syncing '%s': %s, requeuing", key, err.Error())
		}
		// Finally, if no error occurs we Forget this item so it does not
		// get queued again until another change happens.
		c.kubeTLSBundleWorkqueue.Forget(obj)
		logger.Info("Successfully synced", "resourceName", key)
		return nil
	}(obj)

	if err != nil {
		utilruntime.HandleError(err)
		return true
	}

	return true
}

// kubeTLSBundleSyncHandler compares the actual state with the desired, and attempts to
// converge the two. It then updates the Status block of the KubeTLSBundle resource
// with the current status of the resource.
func (c *Controller) kubeTLSBundleSyncHandler(ctx context.Context, key string) error {
	// Convert the namespace/name string into a distinct namespace and name
	logger := klog.LoggerWithValues(klog.FromContext(ctx), "resourceName", key)

	namespace, name, err := cache.SplitMetaNamespaceKey(key)
	if err != nil {
		utilruntime.HandleError(fmt.Errorf("invalid resource key: %s", key))
		return nil
	}

	// Get the KubeTLSBundle resource with this namespace/name
	kubeTLSBundleFromLister, err := c.kubeTLSBundleLister.KubeTLSBundles(namespace).Get(name)
	if err != nil {
		// The KubeTLSBundle resource may no longer exist, in which case we stop
		// processing.
		if errors.IsNotFound(err) {
			utilruntime.HandleError(fmt.Errorf("KubeTLSBundle '%s' in work queue no longer exists", key))
			return nil
		}

		return err
	}

	// DeepCopy for safety
	kubeTLSBundle := kubeTLSBundleFromLister.DeepCopy()

	backendName := "kubetlsbundle-" + kubeTLSBundle.ObjectMeta.Name
	historyName := "kubetlsbundle-" + kubeTLSBundle.ObjectMeta.Name + "-history"

	// Get the backend Secret, history Secret, and CSR with this namespace/name
	backendFromLister, berr := c.secretLister.Secrets(kubeTLSBundle.Namespace).Get(backendName)
	historyFromLister, herr := c.secretLister.Secrets(kubeTLSBundle.Namespace).Get(historyName)
	_, csrerr := c.certificateSigningRequestLister.Get(kubeTLSBundle.Name)

	// DeepCopy for safety
	backend := backendFromLister.DeepCopy()
	history := historyFromLister.DeepCopy()

	g8sKubeTLSBundle := internalv1alpha1.NewKubeTLSBundle(kubeTLSBundle, c.Client.kubeClientset.CertificatesV1())

	// If the backend and history resources don't exist, create them
	if errors.IsNotFound(berr) && errors.IsNotFound(herr) {
		logger.V(4).Info("Create backend and history Secret resources and CSR")

		// Create the CSR object needed to create the certificate
		if errors.IsNotFound(csrerr) {
			go newCSR(g8sKubeTLSBundle)
		}

		hContent := g8sKubeTLSBundle.Rotate()
		bContent := make(map[string]string)
		bContent["key.pem"] = hContent["key.pem-0"]
		bContent["cert.pem"] = hContent["cert.pem-0"]

		backend, err = c.Client.kubeClientset.CoreV1().Secrets(kubeTLSBundle.Namespace).Create(ctx, internalv1alpha1.NewBackendSecret(g8sKubeTLSBundle, bContent), metav1.CreateOptions{})
		if err != nil {
			return err
		}
		history, err = c.Client.kubeClientset.CoreV1().Secrets(kubeTLSBundle.Namespace).Create(ctx, internalv1alpha1.NewHistorySecret(g8sKubeTLSBundle, hContent), metav1.CreateOptions{})
	} else if errors.IsNotFound(berr) { // backend dne but history does, rebuild backend from history
		logger.V(4).Info("Create backend Secret resources from history")
		content := make(map[string]string)
		content["key.pem"] = string(history.Data["key.pem-0"])
		content["cert.pem"] = string(history.Data["cert.pem-0"])
		backend, err = c.Client.kubeClientset.CoreV1().Secrets(kubeTLSBundle.Namespace).Create(ctx, internalv1alpha1.NewBackendSecret(g8sKubeTLSBundle, content), metav1.CreateOptions{})
	} else if errors.IsNotFound(herr) { // backend exists but history dne, rebuild history from backend
		logger.V(4).Info("Create history Secret resources from backend")
		content := make(map[string]string)
		content["key.pem-0"] = string(backend.Data["key.pem"])
		content["cert.pem-0"] = string(backend.Data["cert.pem"])
		history, err = c.Client.kubeClientset.CoreV1().Secrets(kubeTLSBundle.Namespace).Create(ctx, internalv1alpha1.NewHistorySecret(g8sKubeTLSBundle, content), metav1.CreateOptions{})
	} else {
		logger.V(4).Info("Secret resources for history and backend exist")
	}

	// If an error occurs during Get/Create, we'll requeue the item so we can
	// attempt processing again later. This could have been caused by a
	// temporary network failure, or any other transient reason.
	if err != nil {
		return err
	}

	// If the Secret is not controlled by this KubeTLSBundle resource, we should log
	// a warning to the event recorder and return error msg.
	if !metav1.IsControlledBy(backend, kubeTLSBundle) {
		msg := fmt.Sprintf(MessageResourceExists, backend.Name)
		c.recorder.Event(kubeTLSBundle, corev1.EventTypeWarning, ErrResourceExists, msg)
		return fmt.Errorf("%s", msg)
	} else if !metav1.IsControlledBy(history, kubeTLSBundle) {
		msg := fmt.Sprintf(MessageResourceExists, history.Name)
		c.recorder.Event(kubeTLSBundle, corev1.EventTypeWarning, ErrResourceExists, msg)
		return fmt.Errorf("%s", msg)
	}

	// Get the ClusterRole for this KubeTLSBundle
	_, crerr := c.clusterRoleLister.Get(backendName)

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

	// Finally, we update the status block of the KubeTLSBundle resource to reflect the
	// current state of the world
	err = c.updateKubeTLSBundleStatus(kubeTLSBundle)
	if err != nil {
		return err
	}

	c.recorder.Event(kubeTLSBundle, corev1.EventTypeNormal, SuccessSynced, MessageResourceSynced)
	return nil
}

func (c *Controller) updateKubeTLSBundleStatus(kubeTLSBundle *g8sv1alpha1.KubeTLSBundle) error {
	// NEVER modify objects from the store. It's a read-only, local cache.
	// You can use DeepCopy() to make a deep copy of original object and modify this copy
	// Or create a copy manually for better performance
	kubeTLSBundleCopy := kubeTLSBundle.DeepCopy()
	kubeTLSBundleCopy.Status.Ready = true
	// If the CustomResourceSubresources feature gate is not enabled,
	// we must use Update instead of UpdateStatus to update the Status block of the KubeTLSBundle resource.
	// UpdateStatus will not allow changes to the Spec of the resource,
	// which is ideal for ensuring nothing other than resource status has been updated.
	_, err := c.Client.g8sClientset.ApiV1alpha1().KubeTLSBundles(kubeTLSBundle.Namespace).UpdateStatus(context.TODO(), kubeTLSBundleCopy, metav1.UpdateOptions{})
	return err
}

// enqueueKubeTLSBundle takes a KubeTLSBundle resource and converts it into a namespace/name
// string which is then put onto the workqueue. This method should *not* be
// passed resources of any type other than KubeTLSBundle.
func (c *Controller) enqueueKubeTLSBundle(obj any) {
	var key string
	var err error
	if key, err = cache.MetaNamespaceKeyFunc(obj); err != nil {
		utilruntime.HandleError(err)
		return
	}
	c.kubeTLSBundleWorkqueue.Add(key)
}

// handleKubeTLSBundleObject will take any resource implementing metav1.Object and attempt
// to find the KubeTLSBundle resource that 'owns' it. It does this by looking at the
// objects metadata.ownerReferences field for an appropriate OwnerReference.
// It then enqueues that KubeTLSBundle resource to be processed. If the object does not
// have an appropriate OwnerReference, it will simply be skipped.
func (c *Controller) handleKubeTLSBundleObject(obj interface{}) {
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
		// If this object is not owned by a KubeTLSBundle, we should not do anything more
		// with it.
		if ownerRef.Kind != "KubeTLSBundle" {
			return
		}

		kubeTLSBundle, err := c.kubeTLSBundleLister.KubeTLSBundles(object.GetNamespace()).Get(ownerRef.Name)
		if err != nil {
			logger.V(4).Info("Ignore orphaned object", "object", klog.KObj(object), "kubeTLSBundle", ownerRef.Name)
			return
		}

		c.enqueueKubeTLSBundle(kubeTLSBundle)
		return
	}
}

func newCSR(ktls *internalv1alpha1.KubeTLSBundle) {
	csrpem := <-ktls.CSRPEM
	name := strings.ToLower(ktls.TypeMeta.GetObjectKind().GroupVersionKind().Kind + "-" + ktls.ObjectMeta.Name)
	kubecsr := certsv1.CertificateSigningRequest{
		TypeMeta:   ktls.TypeMeta,
		ObjectMeta: internalv1alpha1.NewG8sObjectMeta(ktls, name),
		Spec: certsv1.CertificateSigningRequestSpec{
			Request:    csrpem,
			SignerName: "kubernetes.io/kube-apiserver-client",
			Usages:     []certsv1.KeyUsage{certsv1.UsageClientAuth, certsv1.UsageDigitalSignature, certsv1.UsageKeyEncipherment},
		},
	}
	pendingcsr, err := ktls.CertificateSigningRequests().Create(context.TODO(), &kubecsr, metav1.CreateOptions{})

	if err != nil {
		fmt.Println(err)
	}

	pendingcsr.Status.Conditions = append(pendingcsr.Status.Conditions, certsv1.CertificateSigningRequestCondition{
		Type:           certsv1.CertificateApproved,
		Status:         "True",
		Reason:         "G8s Approved",
		Message:        "This CSR was generated as part of a KubeTLSBundle Object and approved by g8s-controller",
		LastUpdateTime: metav1.Now(),
	})
	approvedcsr, _ := ktls.CertificateSigningRequests().UpdateApproval(context.TODO(), pendingcsr.ObjectMeta.Name, pendingcsr, metav1.UpdateOptions{})
	certpem := approvedcsr.Status.Certificate

	for {
		if certpem != nil {
			ktls.CertPEM <- certpem
			break
		} else {
			approvedcsr, _ = ktls.CertificateSigningRequests().Get(context.TODO(), pendingcsr.ObjectMeta.Name, metav1.GetOptions{})
			certpem = approvedcsr.Status.Certificate
		}
	}
}
