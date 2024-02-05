package controller

import (
	clientset "github.com/the-gizmo-dojo/g8s/pkg/generated/clientset/versioned"
	informers "github.com/the-gizmo-dojo/g8s/pkg/generated/informers/externalversions/api.g8s.io/v1alpha1"
	listers "github.com/the-gizmo-dojo/g8s/pkg/generated/listers/api.g8s.io/v1alpha1"

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
	loginInformer                        informers.LoginInformer
	sshKeyPairInformer                   informers.SSHKeyPairInformer
	clusterRoleInformer                  rbacinformers.ClusterRoleInformer
	mutatingWebhookConfigurationInformer admissionregistrationinformers.MutatingWebhookConfigurationInformer
	secretInformer                       coreinformers.SecretInformer

	// listers for our custom types
	allowlistsLister  listers.AllowlistLister
	allowlistsSynced  cache.InformerSynced
	loginsLister      listers.LoginLister
	loginsSynced      cache.InformerSynced
	sshKeyPairsLister listers.SSHKeyPairLister
	sshKeyPairsSynced cache.InformerSynced

	// listers for k8s types owned by our custom types
	clusterRolesLister                  rbaclisters.ClusterRoleLister
	clusterRolesSynced                  cache.InformerSynced
	mutatingWebhookConfigurationsLister admissionregistrationlisters.MutatingWebhookConfigurationLister
	mutatingWebhookConfigurationsSynced cache.InformerSynced
	secretsLister                       corelisters.SecretLister
	secretsSynced                       cache.InformerSynced
	// recorder is an event recorder for recording Event resources to the
	// Kubernetes API.
	recorder record.EventRecorder
}
