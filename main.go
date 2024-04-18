package main

import (
	"errors"
	"flag"
	"time"

	kubeinformers "k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/klog/v2"
	"k8s.io/sample-controller/pkg/signals"

	"github.com/jrodonnell/g8s/pkg/controller"
	clientset "github.com/jrodonnell/g8s/pkg/controller/generated/clientset/versioned"
	informers "github.com/jrodonnell/g8s/pkg/controller/generated/informers/externalversions"
	"github.com/jrodonnell/g8s/pkg/webhook"
)

var (
	masterURL  string
	kubeconfig string
	role       string // must be either 'controller' or 'webhook'
)

func main() {
	klog.InitFlags(nil)
	flag.Parse()

	// set up signals so we handle the shutdown signal gracefully
	ctx := signals.SetupSignalHandler()
	logger := klog.FromContext(ctx)
	cfg, err := clientcmd.BuildConfigFromFlags(masterURL, kubeconfig)
	if err != nil {
		logger.Error(err, "Error building kubeconfig")
		klog.FlushAndExit(klog.ExitFlushTimeout, 1)
	}

	kubeClient, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		logger.Error(err, "Error building kubernetes clientset")
		klog.FlushAndExit(klog.ExitFlushTimeout, 1)
	}

	g8sClient, err := clientset.NewForConfig(cfg)
	if err != nil {
		logger.Error(err, "Error building g8s clientset")
		klog.FlushAndExit(klog.ExitFlushTimeout, 1)
	}

	kubeInformerFactory := kubeinformers.NewSharedInformerFactory(kubeClient, time.Second*30)
	g8sInformerFactory := informers.NewSharedInformerFactory(g8sClient, time.Second*30)

	allowlistInformer := g8sInformerFactory.Api().V1alpha1().Allowlists()
	selfSignedTLSBundleInformer := g8sInformerFactory.Api().V1alpha1().SelfSignedTLSBundles()
	loginInformer := g8sInformerFactory.Api().V1alpha1().Logins()
	sshKeyPairInformer := g8sInformerFactory.Api().V1alpha1().SSHKeyPairs()
	namespaceInformer := kubeInformerFactory.Core().V1().Namespaces()
	secretInformer := kubeInformerFactory.Core().V1().Secrets()

	switch role {
	case "controller":
		controller := controller.NewController(ctx, kubeClient, g8sClient,
			allowlistInformer,
			selfSignedTLSBundleInformer,
			loginInformer,
			sshKeyPairInformer,
			namespaceInformer,
			secretInformer,
		)

		// notice that there is no need to run Start methods in a separate goroutine. (i.e. go kubeInformerFactory.Start(ctx.done())
		// Start method is non-blocking and runs all registered informers in a dedicated goroutine.
		kubeInformerFactory.Start(ctx.Done())
		g8sInformerFactory.Start(ctx.Done())

		if err = controller.Run(ctx, 1); err != nil {
			logger.Error(err, "Error running controller")
			klog.FlushAndExit(klog.ExitFlushTimeout, 1)
		}
	case "webhook":
		allowlistInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
			AddFunc:    func(any) {},
			UpdateFunc: func(old, new interface{}) {},
			DeleteFunc: func(any) {},
		})
		g8sInformerFactory.Start(ctx.Done())

		logger.Info("Waiting for Informer cache to sync...")
		if ok := cache.WaitForCacheSync(ctx.Done(), allowlistInformer.Informer().HasSynced); !ok {
			logger.Error(errors.New("error waiting for Informer cache to sync"), "failed to wait for caches to sync")
		}
		logger.Info("Done")

		err := webhook.Serve(ctx, allowlistInformer)

		if err != nil {
			logger.Error(err, "Error running server")
		}
	default:
		logger.Error(errors.New("invalid role"), "role must be either 'controller' or 'webhook'")
	}
}

func init() {
	flag.StringVar(&kubeconfig, "kubeconfig", "", "Path to a kubeconfig. Only required if out-of-cluster.")
	flag.StringVar(&masterURL, "master", "", "The address of the Kubernetes API server. Overrides any value in kubeconfig. Only required if out-of-cluster.")
	flag.StringVar(&role, "role", "", "Must be one of 'controller' or 'webhook', tells the progam which one to run as")
}
