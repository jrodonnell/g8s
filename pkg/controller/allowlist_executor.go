package controller

import (
	"context"
	"fmt"
	"slices"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog/v2"

	g8sv1alpha1 "github.com/jrodonnell/g8s/pkg/controller/apis/api.g8s.io/v1alpha1"
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
	logger := klog.LoggerWithValues(klog.FromContext(ctx), "resourceName", key)

	_, name, err := cache.SplitMetaNamespaceKey(key)
	if err != nil {
		utilruntime.HandleError(fmt.Errorf("invalid resource key: %s", key))
		return nil
	}

	// Get the Allowlist resource with this namespace/name
	allowlistFromLister, err := c.allowlistLister.Get(name)
	if err != nil {
		// The Allowlist resource may no longer exist, in which case we stop
		// processing.
		if errors.IsNotFound(err) {
			utilruntime.HandleError(fmt.Errorf("allowlist '%s' in work queue no longer exists", key))
			return nil
		}

		return err
	}

	// DeepCopy for safety
	allowlist := allowlistFromLister.DeepCopy()

	// target = map[namespace][]secretname
	targets := make(map[string][]string)
	for _, g := range g8sv1alpha1.G8sTypes {
		switch g {
		case "Logins":
			for _, g := range allowlist.Spec.Logins {
				for _, t := range g.Targets {
					secretname := "login" + "-" + g.Name
					targets[t.Namespace] = append(targets[t.Namespace], secretname)
					sourceFromLister, err := c.secretLister.Secrets("g8s").Get(secretname)
					if err != nil {
						utilruntime.HandleError(fmt.Errorf("cannot find backend Secret '%s'", secretname))
						return err
					}

					var targetSecret corev1.Secret
					sourceFromLister.DeepCopyInto(&targetSecret)

					// change certain ObjectMeta values, clear others
					targetSecret.ObjectMeta.Namespace = t.Namespace
					targetSecret.ObjectMeta.Labels = map[string]string{"owner": "g8s-master"}
					targetSecret.ObjectMeta.OwnerReferences = []metav1.OwnerReference{
						*metav1.NewControllerRef(&allowlist.ObjectMeta, g8sv1alpha1.SchemeGroupVersion.WithKind("Allowlist")),
					}

					targetSecret.ObjectMeta.UID = ""
					targetSecret.ObjectMeta.ResourceVersion = ""
					targetSecret.ObjectMeta.CreationTimestamp = metav1.Time{Time: time.Time{}}

					targetCheck, err := c.secretLister.Secrets(t.Namespace).Get(secretname)
					if err != nil {
						_, err = c.Client.kubeClientset.CoreV1().Secrets(t.Namespace).Create(ctx, &targetSecret, metav1.CreateOptions{})
						if err != nil {
							utilruntime.HandleError(fmt.Errorf("error mirroring Secret '%s' as specified in Allowlist '%s'", secretname, allowlist.ObjectMeta.Name))
							return err
						}
						logger.V(4).Info(fmt.Sprintf("target Secret '%s' created", targetSecret.Name))
					} else if targetCheck.OwnerReferences[0].Name == "g8s-master" {
						logger.V(4).Info(fmt.Sprintf("target Secret '%s' already mirrored", targetSecret.Name))
					}
				}
			}
		case "SelfSignedTLSBundles":
			for _, g := range allowlist.Spec.SelfSignedTLSBundles {
				for _, t := range g.Targets {
					secretname := "selfsignedtlsbundle" + "-" + g.Name
					targets[t.Namespace] = append(targets[t.Namespace], secretname)
					sourceFromLister, err := c.secretLister.Secrets("g8s").Get(secretname)
					if err != nil {
						utilruntime.HandleError(fmt.Errorf("cannot find backend Secret '%s'", secretname))
						return err
					}

					var targetSecret corev1.Secret
					sourceFromLister.DeepCopyInto(&targetSecret)

					// change certain ObjectMeta values, clear others
					targetSecret.Namespace = t.Namespace
					targetSecret.ObjectMeta.Labels = map[string]string{"owner": "g8s-master"}
					targetSecret.OwnerReferences = []metav1.OwnerReference{
						*metav1.NewControllerRef(&allowlist.ObjectMeta, g8sv1alpha1.SchemeGroupVersion.WithKind("Allowlist")),
					}

					targetSecret.UID = ""
					targetSecret.ResourceVersion = ""
					targetSecret.CreationTimestamp = metav1.Time{Time: time.Time{}}

					targetCheck, err := c.secretLister.Secrets(t.Namespace).Get(secretname)
					if err != nil {
						_, err = c.Client.kubeClientset.CoreV1().Secrets(t.Namespace).Create(ctx, &targetSecret, metav1.CreateOptions{})
						if err != nil {
							utilruntime.HandleError(fmt.Errorf("error mirroring Secret '%s' as specified in Allowlist '%s'", secretname, allowlist.ObjectMeta.Name))
							return err
						}
						logger.V(4).Info(fmt.Sprintf("target Secret '%s' created", targetSecret.Name))
					} else if targetCheck.OwnerReferences[0].Name == "g8s-master" {
						logger.V(4).Info(fmt.Sprintf("target Secret '%s' already mirrored", targetSecret.Name))
					}
				}
			}
		case "SSHKeyPairs":
			for _, g := range allowlist.Spec.SSHKeyPairs {
				for _, t := range g.Targets {
					secretname := "sshkeypair" + "-" + g.Name
					targets[t.Namespace] = append(targets[t.Namespace], secretname)
					sourceFromLister, err := c.secretLister.Secrets("g8s").Get(secretname)
					if err != nil {
						utilruntime.HandleError(fmt.Errorf("cannot find backend Secret '%s'", secretname))
						return err
					}

					var targetSecret corev1.Secret
					sourceFromLister.DeepCopyInto(&targetSecret)

					// change certain ObjectMeta values, clear others
					targetSecret.Namespace = t.Namespace
					targetSecret.ObjectMeta.Labels = map[string]string{"owner": "g8s-master"}
					targetSecret.OwnerReferences = []metav1.OwnerReference{
						*metav1.NewControllerRef(&allowlist.ObjectMeta, g8sv1alpha1.SchemeGroupVersion.WithKind("Allowlist")),
					}

					targetSecret.UID = ""
					targetSecret.ResourceVersion = ""
					targetSecret.CreationTimestamp = metav1.Time{Time: time.Time{}}

					targetCheck, err := c.secretLister.Secrets(t.Namespace).Get(secretname)
					if err != nil {
						_, err = c.Client.kubeClientset.CoreV1().Secrets(t.Namespace).Create(ctx, &targetSecret, metav1.CreateOptions{})
						if err != nil {
							utilruntime.HandleError(fmt.Errorf("error mirroring Secret '%s' as specified in Allowlist '%s'", secretname, allowlist.ObjectMeta.Name))
							return err
						}
						logger.V(4).Info(fmt.Sprintf("target Secret '%s' created", targetSecret.Name))
					} else if targetCheck.OwnerReferences[0].Name == "g8s-master" {
						logger.V(4).Info(fmt.Sprintf("target Secret '%s' already mirrored", targetSecret.Name))
					}
				}
			}
		}
	}

	// second pass: search all namespaces with g8s-injection and delete Secrets owned by g8s-master
	// but were removed from the Allowlist
	targetNamespaces, err := c.namespaceLister.List(labels.SelectorFromSet(labels.Set{"g8s-injection": "enabled"}))

	if err != nil {
		utilruntime.HandleError(fmt.Errorf("error listing orphaned target Secrets"))
	}

	for _, n := range targetNamespaces {
		targetsFromLister, _ := c.secretLister.Secrets(n.Name).List(labels.SelectorFromSet(labels.Set{"owner": "g8s-master"}))

		if len(targetsFromLister) > 0 {
			for _, t := range targetsFromLister {
				if len(targets) == 0 {
					err = c.Client.kubeClientset.CoreV1().Secrets(t.Namespace).Delete(ctx, t.Name, metav1.DeleteOptions{})

					if err != nil {
						utilruntime.HandleError(fmt.Errorf("error deleting orphaned target Secret '%s'", t.Name))
						return err
					}
				} else if !slices.Contains(targets[t.Namespace], t.Name) {
					err = c.Client.kubeClientset.CoreV1().Secrets(t.Namespace).Delete(ctx, t.Name, metav1.DeleteOptions{})

					if err != nil {
						utilruntime.HandleError(fmt.Errorf("error deleting orphaned target Secret '%s'", t.Name))
						return err
					}
				}
			}
		}
	}

	// Finally, we update the status block of the Allowlist resource to reflect the
	// current state of the world
	err = c.updateAllowlistStatus(allowlist)
	if err != nil {
		return err
	}

	c.recorder.Event(allowlist, corev1.EventTypeNormal, SuccessSynced, MessageResourceSynced)
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
	_, err := c.Client.g8sClientset.ApiV1alpha1().Allowlists().UpdateStatus(context.TODO(), allowlistCopy, metav1.UpdateOptions{})
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

		allowlist, err := c.allowlistLister.Get(ownerRef.Name)
		if err != nil {
			logger.V(4).Info("Ignore orphaned object", "object", klog.KObj(object), "allowlist", ownerRef.Name)
			return
		}

		c.enqueueAllowlist(allowlist)
		return
	}
}

// Set up an event handler for when Allowlist and/or their backend and history Secret resources change
func (c *Controller) setAllowlistInformersEventHandlers(ctx context.Context) {
	logger := klog.FromContext(ctx)

	c.allowlistInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: c.enqueueAllowlist,
		UpdateFunc: func(old, new interface{}) {
			c.enqueueAllowlist(new)
		},
		DeleteFunc: func(obj interface{}) {
			allow, ok := obj.(*g8sv1alpha1.Allowlist)
			if !ok {
				logger.Error(nil, "obj is not an Allowlist")
			}
			c.recorder.Event(allow, corev1.EventTypeNormal, SuccessDeleted, MessageResourceDeleted)
		},
	})

	// Set up an event handler for when Allowlist target Secret resources change. This
	// handler will lookup the owner of the given Secret, and if it is
	// owned by an Allowlist resource then the handler will enqueue that Allowlist resource for
	// processing. This way, we don't need to implement custom logic for
	// handling Secret resources. More info on this pattern:
	// https://github.com/kubernetes/community/blob/8cafef897a22026d42f5e5bb3f104febe7e29830/contributors/devel/controllers.md
	c.secretInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: c.handleAllowlistObject,
		UpdateFunc: func(old, new interface{}) {
			newDepl := new.(*corev1.Secret)
			oldDepl := old.(*corev1.Secret)
			if newDepl.ResourceVersion == oldDepl.ResourceVersion {
				// Periodic resync will send update events for all known Secrets.
				// Two different versions of the same Secret will always have different ResourceVersions.
				// This section will skip calling handleObject() if they are the same.
				return
			}
			c.handleAllowlistObject(new)
		},
		DeleteFunc: c.handleAllowlistObject,
	})
}
