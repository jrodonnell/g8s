package controller

import (
	"context"
	"time"

	"golang.org/x/time/rate"

	corev1 "k8s.io/api/core/v1"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	coreinformers "k8s.io/client-go/informers/core/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	typedcorev1 "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/tools/record"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog/v2"

	clientset "github.com/jrodonnell/g8s/pkg/controller/generated/clientset/versioned"
	g8sscheme "github.com/jrodonnell/g8s/pkg/controller/generated/clientset/versioned/scheme"
	informers "github.com/jrodonnell/g8s/pkg/controller/generated/informers/externalversions/api.g8s.io/v1alpha1"
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
	selfSignedTLSBundleInformer informers.SelfSignedTLSBundleInformer,
	loginInformer informers.LoginInformer,
	sshKeyPairInformer informers.SSHKeyPairInformer,
	namespaceInformer coreinformers.NamespaceInformer,
	secretInformer coreinformers.SecretInformer) *Controller {

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

	rateLimiter := workqueue.NewMaxOfRateLimiter(
		workqueue.NewItemExponentialFailureRateLimiter(5*time.Millisecond, 1000*time.Second),
		&workqueue.BucketRateLimiter{Limiter: rate.NewLimiter(rate.Limit(50), 300)},
	)

	controller := &Controller{
		Client: Client{
			kubeClientset: kubeClientset,
			g8sClientset:  g8sClientset,
			recorder:      recorder,

			// informers & listers for our custom types
			allowlistInformer:           allowlistInformer,
			allowlistLister:             allowlistInformer.Lister(),
			allowlistSynced:             allowlistInformer.Informer().HasSynced,
			selfSignedTLSBundleInformer: selfSignedTLSBundleInformer,
			selfSignedTLSBundleLister:   selfSignedTLSBundleInformer.Lister(),
			selfSignedTLSBundleSynced:   selfSignedTLSBundleInformer.Informer().HasSynced,
			loginInformer:               loginInformer,
			loginLister:                 loginInformer.Lister(),
			loginSynced:                 loginInformer.Informer().HasSynced,
			sshKeyPairInformer:          sshKeyPairInformer,
			sshKeyPairLister:            sshKeyPairInformer.Lister(),
			sshKeyPairSynced:            sshKeyPairInformer.Informer().HasSynced,

			// informers & listers for our backing types
			namespaceInformer: namespaceInformer,
			namespaceLister:   namespaceInformer.Lister(),
			namespaceSynced:   namespaceInformer.Informer().HasSynced,
			secretInformer:    secretInformer,
			secretLister:      secretInformer.Lister(),
			secretSynced:      secretInformer.Informer().HasSynced,
		},
		Executor: Executor{
			allowlistWorkqueue:           workqueue.NewNamedRateLimitingQueue(rateLimiter, "Allowlist"),
			selfSignedTLSBundleWorkqueue: workqueue.NewNamedRateLimitingQueue(rateLimiter, "SelfSignedTLSBundle"),
			loginWorkqueue:               workqueue.NewNamedRateLimitingQueue(rateLimiter, "Login"),
			sshKeyPairWorkqueue:          workqueue.NewNamedRateLimitingQueue(rateLimiter, "SSHKeyPair"),
		},
	}

	logger.Info("Setting up event handlers")

	controller.setAllowlistInformersEventHandlers(ctx)
	controller.setLoginInformersEventHandlers(ctx)
	controller.setSelfSignedTLSBundleInformersEventHandlers(ctx)
	controller.setSSHKeyPairInformersEventHandlers(ctx)

	return controller
}
