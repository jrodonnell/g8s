package controller

import (
	"context"
	"strings"
	"time"

	"golang.org/x/time/rate"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	typedcorev1 "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/record"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog/v2"

	admissionregistrationinformers "k8s.io/client-go/informers/admissionregistration/v1"
	certinformers "k8s.io/client-go/informers/certificates/v1"
	secretinformers "k8s.io/client-go/informers/core/v1"
	rbacinformers "k8s.io/client-go/informers/rbac/v1"

	g8sv1alpha1 "github.com/jrodonnell/g8s/controller/apis/api.g8s.io/v1alpha1"
	internalv1alpha1 "github.com/jrodonnell/g8s/controller/apis/internal.g8s.io/v1alpha1"
	clientset "github.com/jrodonnell/g8s/controller/generated/clientset/versioned"
	g8sscheme "github.com/jrodonnell/g8s/controller/generated/clientset/versioned/scheme"
	informers "github.com/jrodonnell/g8s/controller/generated/informers/externalversions/api.g8s.io/v1alpha1"
)

const controllerAgentName = "g8s-controller"

// Controller is the controller implementation for Login resources
type Controller struct {
	Client
	Executor
}

// NewController returns a new g8s controller
func NewController(
	ctx context.Context,
	kubeClientset kubernetes.Interface,
	g8sClientset clientset.Interface,
	allowlistInformer informers.AllowlistInformer,
	kubeTLSBundleInformer informers.KubeTLSBundleInformer,
	loginInformer informers.LoginInformer,
	sshKeyPairInformer informers.SSHKeyPairInformer,
	certificateSigningRequestInformer certinformers.CertificateSigningRequestInformer,
	clusterRoleInformer rbacinformers.ClusterRoleInformer,
	mutatingWebhookConfigurationInformer admissionregistrationinformers.MutatingWebhookConfigurationInformer,
	secretInformer secretinformers.SecretInformer) *Controller {

	logger := klog.FromContext(ctx)

	// Create event broadcaster
	// Add g8s types to the default Kubernetes Scheme so Events can be
	// logged for g8s types.
	utilruntime.Must(g8sscheme.AddToScheme(scheme.Scheme))
	logger.V(4).Info("Creating event broadcaster")

	eventBroadcaster := record.NewBroadcaster()
	eventBroadcaster.StartStructuredLogging(0)
	eventBroadcaster.StartRecordingToSink(&typedcorev1.EventSinkImpl{Interface: kubeClientset.CoreV1().Events("")})
	recorder := eventBroadcaster.NewRecorder(scheme.Scheme, corev1.EventSource{Component: controllerAgentName})

	ratelimiter := workqueue.NewMaxOfRateLimiter(
		workqueue.NewItemExponentialFailureRateLimiter(5*time.Millisecond, 1000*time.Second),
		&workqueue.BucketRateLimiter{Limiter: rate.NewLimiter(rate.Limit(50), 300)},
	)

	controller := &Controller{
		Client: Client{
			kubeClientset: kubeClientset,
			g8sClientset:  g8sClientset,
			recorder:      recorder,

			// informers & listers for our custom types
			allowlistInformer:     allowlistInformer,
			allowlistLister:       allowlistInformer.Lister(),
			allowlistSynced:       allowlistInformer.Informer().HasSynced,
			kubeTLSBundleInformer: kubeTLSBundleInformer,
			kubeTLSBundleLister:   kubeTLSBundleInformer.Lister(),
			kubeTLSBundleSynced:   kubeTLSBundleInformer.Informer().HasSynced,
			loginInformer:         loginInformer,
			loginLister:           loginInformer.Lister(),
			loginSynced:           loginInformer.Informer().HasSynced,
			sshKeyPairInformer:    sshKeyPairInformer,
			sshKeyPairLister:      sshKeyPairInformer.Lister(),
			sshKeyPairSynced:      sshKeyPairInformer.Informer().HasSynced,

			// informers & listers for our backing types
			certificateSigningRequestInformer:    certificateSigningRequestInformer,
			certificateSigningRequestLister:      certificateSigningRequestInformer.Lister(),
			certificateSigningRequestSynced:      certificateSigningRequestInformer.Informer().HasSynced,
			clusterRoleInformer:                  clusterRoleInformer,
			clusterRoleLister:                    clusterRoleInformer.Lister(),
			clusterRoleSynced:                    clusterRoleInformer.Informer().HasSynced,
			mutatingWebhookConfigurationInformer: mutatingWebhookConfigurationInformer,
			mutatingWebhookConfigurationLister:   mutatingWebhookConfigurationInformer.Lister(),
			mutatingWebhookConfigurationSynced:   mutatingWebhookConfigurationInformer.Informer().HasSynced,
			secretInformer:                       secretInformer,
			secretLister:                         secretInformer.Lister(),
			secretSynced:                         secretInformer.Informer().HasSynced,
		},
		Executor: Executor{
			allowlistWorkqueue:     workqueue.NewNamedRateLimitingQueue(ratelimiter, "Allowlist"),
			kubeTLSBundleWorkqueue: workqueue.NewNamedRateLimitingQueue(ratelimiter, "KubeTLSBundle"),
			loginWorkqueue:         workqueue.NewNamedRateLimitingQueue(ratelimiter, "Login"),
			sshKeyPairWorkqueue:    workqueue.NewNamedRateLimitingQueue(ratelimiter, "SSHKeyPair"),
		},
	}

	logger.Info("Setting up event handlers")

	// Set up an event handler for when KubeTLSBundle resources change
	kubeTLSBundleInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: controller.enqueueKubeTLSBundle,
		UpdateFunc: func(old, new interface{}) {
			controller.enqueueKubeTLSBundle(new)
		},
		DeleteFunc: func(obj interface{}) {
			ktls, ok := obj.(*g8sv1alpha1.KubeTLSBundle)
			g8sktls := internalv1alpha1.NewKubeTLSBundle(ktls, kubeClientset.CertificatesV1())
			meta := g8sktls.GetMeta()
			name := strings.ToLower(meta.TypeMeta.Kind + "-" + meta.ObjectMeta.Name)
			if !ok {
				logger.Error(nil, "obj is not a KubeTLSBundle")
			}
			err := controller.kubeClientset.RbacV1().ClusterRoles().Delete(context.TODO(), name, metav1.DeleteOptions{})
			if err != nil {
				logger.Error(err, "Error deleting ClusterRole backing KubeTLSBundle: "+name)
			}
			err = controller.kubeClientset.CertificatesV1().CertificateSigningRequests().Delete(context.TODO(), name, metav1.DeleteOptions{})
			if err != nil {
				logger.Error(err, "Error deleting CertificateSigningRequest backing KubeTLSBundle: "+name)
			}
			controller.recorder.Event(ktls, corev1.EventTypeNormal, SuccessDeleted, MessageResourceDeleted)
		},
	})

	// Set up an event handler for when Login resources change
	loginInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: controller.enqueueLogin,
		UpdateFunc: func(old, new interface{}) {
			controller.enqueueLogin(new)
		},
		DeleteFunc: func(obj interface{}) {
			login, ok := obj.(*g8sv1alpha1.Login)
			g8slogin := internalv1alpha1.NewLogin(login)
			meta := g8slogin.GetMeta()
			name := strings.ToLower(meta.TypeMeta.Kind + "-" + meta.ObjectMeta.Name)
			if !ok {
				logger.Error(nil, "obj is not a Login")
			}
			err := controller.kubeClientset.RbacV1().ClusterRoles().Delete(context.TODO(), name, metav1.DeleteOptions{})
			if err != nil {
				logger.Error(err, "Error deleting ClusterRole backing Login: "+name)
			}
			controller.recorder.Event(login, corev1.EventTypeNormal, SuccessDeleted, MessageResourceDeleted)
		},
	})

	// Set up an event handler for when SSHkeypair resources change
	sshKeyPairInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: controller.enqueueSSHKeyPair,
		UpdateFunc: func(old, new interface{}) {
			controller.enqueueSSHKeyPair(new)
		},
		DeleteFunc: func(obj interface{}) {
			ssh, ok := obj.(*g8sv1alpha1.SSHKeyPair)
			g8sssh := internalv1alpha1.NewSSHKeyPair(ssh)
			meta := g8sssh.GetMeta()
			name := strings.ToLower(meta.TypeMeta.Kind + "-" + meta.ObjectMeta.Name)
			if !ok {
				logger.Error(nil, "obj is not an SSHKeyPair")
			}
			err := controller.kubeClientset.RbacV1().ClusterRoles().Delete(context.TODO(), name, metav1.DeleteOptions{})
			if err != nil {
				logger.Error(err, "Error deleting ClusterRole backing SSHKeyPair: "+name)
			}
			controller.recorder.Event(ssh, corev1.EventTypeNormal, SuccessDeleted, MessageResourceDeleted)
		},
	})

	// Set up an event handler for when Secret resources change. This
	// handler will lookup the owner of the given Secret, and if it is
	// owned by a KubeTLSBundle resource then the handler will enqueue that KubeTLSBundle resource for
	// processing. This way, we don't need to implement custom logic for
	// handling Secret resources. More info on this pattern:
	// https://github.com/kubernetes/community/blob/8cafef897a22026d42f5e5bb3f104febe7e29830/contributors/devel/controllers.md
	secretInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: controller.handleKubeTLSBundleObject,
		UpdateFunc: func(old, new interface{}) {
			newDepl := new.(*corev1.Secret)
			oldDepl := old.(*corev1.Secret)
			if newDepl.ResourceVersion == oldDepl.ResourceVersion {
				// Periodic resync will send update events for all known Secrets.
				// Two different versions of the same Secret will always have different ResourceVersions.
				// This section will skip calling handleObject() if they are the same.
				return
			}
			controller.handleKubeTLSBundleObject(new)
		},
		DeleteFunc: controller.handleKubeTLSBundleObject,
	})

	// Set up an event handler for when ClusterRole resources change. This
	// handler will lookup the owner of the given ClusterRole, and if it is
	// owned by a KubeTLSBundle resource then the handler will enqueue that KubeTLSBundle resource for
	// processing. This way, we don't need to implement custom logic for
	// handling ClusterRole resources. More info on this pattern:
	// https://github.com/kubernetes/community/blob/8cafef897a22026d42f5e5bb3f104febe7e29830/contributors/devel/controllers.md
	clusterRoleInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: controller.handleKubeTLSBundleObject,
		UpdateFunc: func(old, new interface{}) {
			newDepl := new.(*rbacv1.ClusterRole)
			oldDepl := old.(*rbacv1.ClusterRole)
			if newDepl.ResourceVersion == oldDepl.ResourceVersion {
				// Periodic resync will send update events for all known ClusterRole.
				// Two different versions of the same ClusterRole will always have different ResourceVersions.
				// This section will skip calling handleObject() if they are the same.
				return
			}
			controller.handleKubeTLSBundleObject(new)
		},
		DeleteFunc: controller.handleKubeTLSBundleObject,
	})

	// Set up an event handler for when Secret resources change. This
	// handler will lookup the owner of the given Secret, and if it is
	// owned by a Login resource then the handler will enqueue that Login resource for
	// processing. This way, we don't need to implement custom logic for
	// handling Secret resources. More info on this pattern:
	// https://github.com/kubernetes/community/blob/8cafef897a22026d42f5e5bb3f104febe7e29830/contributors/devel/controllers.md
	secretInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: controller.handleLoginObject,
		UpdateFunc: func(old, new interface{}) {
			newDepl := new.(*corev1.Secret)
			oldDepl := old.(*corev1.Secret)
			if newDepl.ResourceVersion == oldDepl.ResourceVersion {
				// Periodic resync will send update events for all known Secrets.
				// Two different versions of the same Secret will always have different ResourceVersions.
				// This section will skip calling handleObject() if they are the same.
				return
			}
			controller.handleLoginObject(new)
		},
		DeleteFunc: controller.handleLoginObject,
	})

	// Set up an event handler for when ClusterRole resources change. This
	// handler will lookup the owner of the given ClusterRole, and if it is
	// owned by a Login resource then the handler will enqueue that Login resource for
	// processing. This way, we don't need to implement custom logic for
	// handling ClusterRole resources. More info on this pattern:
	// https://github.com/kubernetes/community/blob/8cafef897a22026d42f5e5bb3f104febe7e29830/contributors/devel/controllers.md
	clusterRoleInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: controller.handleLoginObject,
		UpdateFunc: func(old, new interface{}) {
			newDepl := new.(*rbacv1.ClusterRole)
			oldDepl := old.(*rbacv1.ClusterRole)
			if newDepl.ResourceVersion == oldDepl.ResourceVersion {
				// Periodic resync will send update events for all known ClusterRole.
				// Two different versions of the same ClusterRole will always have different ResourceVersions.
				// This section will skip calling handleObject() if they are the same.
				return
			}
			controller.handleLoginObject(new)
		},
		DeleteFunc: controller.handleLoginObject,
	})

	// Set up an event handler for when Secret resources change. This
	// handler will lookup the owner of the given Secret, and if it is
	// owned by an SSHKeyPair resource then the handler will enqueue that SSHKeyPair resource for
	// processing. This way, we don't need to implement custom logic for
	// handling Secret resources. More info on this pattern:
	// https://github.com/kubernetes/community/blob/8cafef897a22026d42f5e5bb3f104febe7e29830/contributors/devel/controllers.md
	secretInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: controller.handleSSHKeyPairObject,
		UpdateFunc: func(old, new interface{}) {
			newDepl := new.(*corev1.Secret)
			oldDepl := old.(*corev1.Secret)
			if newDepl.ResourceVersion == oldDepl.ResourceVersion {
				// Periodic resync will send update events for all known Secrets.
				// Two different versions of the same Secret will always have different ResourceVersions.
				// This section will skip calling handleObject() if they are the same.
				return
			}
			controller.handleSSHKeyPairObject(new)
		},
		DeleteFunc: controller.handleSSHKeyPairObject,
	})

	// Set up an event handler for when ClusterRole resources change. This
	// handler will lookup the owner of the given ClusterRole, and if it is
	// owned by a SSHKeyPair resource then the handler will enqueue that SSHKeyPair resource for
	// processing. This way, we don't need to implement custom logic for
	// handling ClusterRole resources. More info on this pattern:
	// https://github.com/kubernetes/community/blob/8cafef897a22026d42f5e5bb3f104febe7e29830/contributors/devel/controllers.md
	clusterRoleInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: controller.handleSSHKeyPairObject,
		UpdateFunc: func(old, new interface{}) {
			newDepl := new.(*rbacv1.ClusterRole)
			oldDepl := old.(*rbacv1.ClusterRole)
			if newDepl.ResourceVersion == oldDepl.ResourceVersion {
				// Periodic resync will send update events for all known ClusterRole.
				// Two different versions of the same ClusterRole will always have different ResourceVersions.
				// This section will skip calling handleObject() if they are the same.
				return
			}
			controller.handleSSHKeyPairObject(new)
		},
		DeleteFunc: controller.handleSSHKeyPairObject,
	})

	return controller
}
