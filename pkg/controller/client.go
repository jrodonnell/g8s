package controller

import (
	clientset "github.com/the-gizmo-dojo/g8s/pkg/generated/clientset/versioned"
	informers "github.com/the-gizmo-dojo/g8s/pkg/generated/informers/externalversions/api.g8s.io/v1alpha1"
	listers "github.com/the-gizmo-dojo/g8s/pkg/generated/listers/api.g8s.io/v1alpha1"
	coreinformers "k8s.io/client-go/informers/core/v1"
	rbacinformers "k8s.io/client-go/informers/rbac/v1"
	"k8s.io/client-go/kubernetes"
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
	loginInformer       informers.LoginInformer
	sshKeyInformer      informers.SSHKeyPairInformer
	secretInformer      coreinformers.SecretInformer
	clusterRoleInformer rbacinformers.ClusterRoleInformer

	// listers for our custom types
	loginsLister listers.LoginLister
	loginsSynced cache.InformerSynced

	// listers for our custom types
	sshKeyPairsLister listers.SSHKeyPairLister
	sshKeyPairsSynced cache.InformerSynced
	// listers for k8s types owned by our custom types
	secretsLister corelisters.SecretLister
	secretsSynced cache.InformerSynced

	clusterRolesLister rbaclisters.ClusterRoleLister
	clusterRolesSynced cache.InformerSynced
	// recorder is an event recorder for recording Event resources to the
	// Kubernetes API.
	recorder record.EventRecorder
}
