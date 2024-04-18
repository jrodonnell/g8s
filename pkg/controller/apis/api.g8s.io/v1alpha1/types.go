/*
Copyright 2024 James Riley O'Donnell.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type G8s []string

var G8sTypes G8s = []string{"Logins", "SelfSignedTLSBundles", "SSHKeyPairs"}

// +genclient
// +genclient:nonNamespaced
// +k8s:register-gen
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +k8s:genclient:method=UpdateStatus,verb=updateStatus,subresource=status, \
// result=k8s.io/apimachinery/pkg/apis/meta/v1.Status
// Allowlist is the Schema for the Allowlist API
type Allowlist struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   AllowlistSpec   `json:"spec,omitempty"`
	Status AllowlistStatus `json:"status,omitempty"`
}

// AllowlistSpec defines the desired state of Allowlist
type AllowlistSpec struct {
	// +optional
	Logins []G8sTargets `json:"logins,omitempty"`

	// +optional
	SelfSignedTLSBundles []G8sTargets `json:"selfSignedTLSBundles,omitempty"`

	// +optional
	SSHKeyPairs []G8sTargets `json:"sshKeyPairs,omitempty"`
}

type G8sTargets struct {
	Name string `json:"name,omitempty"`

	Targets []Target `json:"targets,omitempty"`
}

type Target struct {
	Namespace string               `json:"namespace,omitempty"`
	Selector  metav1.LabelSelector `json:"selector,omitempty"`

	// +optional
	Containers []string `json:"containers,omitempty"`
}

// AllowlistStatus defines the observed state of Allowlist
type AllowlistStatus struct {
	Ready bool `json:"ready"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// AllowlistList contains a list of Allowlist
type AllowlistList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Allowlist `json:"items"`
}

// +genclient
// +k8s:register-gen
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +k8s:genclient:method=UpdateStatus,verb=updateStatus,subresource=status, \
// result=k8s.io/apimachinery/pkg/apis/meta/v1.Status
// Login is the Schema for the Logins API
type Login struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   LoginSpec   `json:"spec,omitempty"`
	Status LoginStatus `json:"status,omitempty"`
}

// LoginSpec defines the desired state of Login
type LoginSpec struct {
	Username string        `json:"username,omitempty"`
	Password *PasswordSpec `json:"password,omitempty"`
}

// PasswordSpec defines the desired state of Password
type PasswordSpec struct {
	Length       uint8  `json:"length,omitempty"`
	CharacterSet string `json:"characterSet,omitempty"`
}

// LoginStatus defines the observed state of Login
type LoginStatus struct {
	Ready bool `json:"ready"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// LoginList contains a list of Login
type LoginList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Login `json:"items"`
}

// +genclient
// +k8s:register-gen
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +k8s:genclient:method=UpdateStatus,verb=updateStatus,subresource=status, \
// result=k8s.io/apimachinery/pkg/apis/meta/v1.Status
// SelfSignedTLSBundle is the Schema for the SelfSignedTLSBundles API
type SelfSignedTLSBundle struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   SelfSignedTLSBundleSpec   `json:"spec,omitempty"`
	Status SelfSignedTLSBundleStatus `json:"status,omitempty"`
}

// SelfSignedTLSBundleSpec defines the desired state of SelfSignedTLSBundle
type SelfSignedTLSBundleSpec struct {
	AppName string   `json:"appName,omitempty"`
	SANs    []string `json:"sans,omitempty"`
}

// SelfSignedTLSBundleStatus defines the observed state of SelfSignedTLSBundle
type SelfSignedTLSBundleStatus struct {
	Ready bool `json:"ready"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// SelfSignedTLSBundleList contains a list of SelfSignedTLSBundle
type SelfSignedTLSBundleList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []SelfSignedTLSBundle `json:"items"`
}

type SSHKeyPairType string

const (
	RSA     SSHKeyPairType = "rsa"
	Ed25519 SSHKeyPairType = "ed25519"
)

// +genclient
// +k8s:register-gen
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +k8s:genclient:method=UpdateStatus,verb=updateStatus,subresource=status, \
// result=k8s.io/apimachinery/pkg/apis/meta/v1.Status
// SSHKeyPair is the Schema for the SSHKeyPairs API
type SSHKeyPair struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   SSHKeyPairSpec   `json:"spec,omitempty"`
	Status SSHKeyPairStatus `json:"status,omitempty"`
}

// SSHKeyPairSpec defines the desired state of SSHKeyPair
type SSHKeyPairSpec struct {
	// +optional
	BitSize int `json:"bitSize,omitempty"`

	KeyType SSHKeyPairType `json:"keyType,omitempty"`
}

// SSHKeyPairStatus defines the observed state of SSHKeyPair
type SSHKeyPairStatus struct {
	Ready bool `json:"ready"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// SSHKeyPairList contains a list of SSHKeyPair
type SSHKeyPairList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []SSHKeyPair `json:"items"`
}
