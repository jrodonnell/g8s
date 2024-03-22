package controller

import (
	clientset "github.com/jrodonnell/g8s/pkg/controller/generated/clientset/versioned"
	informers "github.com/jrodonnell/g8s/pkg/controller/generated/informers/externalversions/api.g8s.io/v1alpha1"
	listers "github.com/jrodonnell/g8s/pkg/controller/generated/listers/api.g8s.io/v1alpha1"

	admissionregistrationinformers "k8s.io/client-go/informers/admissionregistration/v1"
	coreinformers "k8s.io/client-go/informers/core/v1"
	rbacinformers "k8s.io/client-go/informers/rbac/v1"

	"k8s.io/client-go/kubernetes"
	admissionregistrationlisters "k8s.io/client-go/listers/admissionregistration/v1"
	corelisters "k8s.io/client-go/listers/core/v1"
	rbaclisters "k8s.io/client-go/listers/rbac/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/record"
)

type Client struct {
	// kubeclientset is a standard kubernetes clientset
	kubeClientset kubernetes.Interface

	// g8sclientset is a clientset for our own API group
	g8sClientset clientset.Interface

	// Informers for each type, just to expose for access
	allowlistInformer                    informers.AllowlistInformer
	selfSignedTLSBundleInformer          informers.SelfSignedTLSBundleInformer
	loginInformer                        informers.LoginInformer
	sshKeyPairInformer                   informers.SSHKeyPairInformer
	clusterRoleInformer                  rbacinformers.ClusterRoleInformer
	mutatingWebhookConfigurationInformer admissionregistrationinformers.MutatingWebhookConfigurationInformer
	secretInformer                       coreinformers.SecretInformer

	// listers for our custom types
	allowlistLister           listers.AllowlistLister
	allowlistSynced           cache.InformerSynced
	selfSignedTLSBundleLister listers.SelfSignedTLSBundleLister
	selfSignedTLSBundleSynced cache.InformerSynced
	loginLister               listers.LoginLister
	loginSynced               cache.InformerSynced
	sshKeyPairLister          listers.SSHKeyPairLister
	sshKeyPairSynced          cache.InformerSynced

	// listers for k8s types owned by our custom types
	clusterRoleLister                  rbaclisters.ClusterRoleLister
	clusterRoleSynced                  cache.InformerSynced
	mutatingWebhookConfigurationLister admissionregistrationlisters.MutatingWebhookConfigurationLister
	mutatingWebhookConfigurationSynced cache.InformerSynced
	secretLister                       corelisters.SecretLister
	secretSynced                       cache.InformerSynced
	// recorder is an event recorder for recording Event resources to the
	// Kubernetes API.
	recorder record.EventRecorder
}
