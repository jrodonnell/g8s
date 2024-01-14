/*
Copyright 2023 James Riley O'Donnell.

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

type SSHKeyType string

const (
	RSA     SSHKeyType = "rsa"
	Ed25519 SSHKeyType = "ed25519"
)

// +genclient
// +k8s:register-gen
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +k8s:genclient:method=UpdateStatus,verb=updateStatus,subresource=status, \
// result=k8s.io/apimachinery/pkg/apis/meta/v1.Status
// Login is the Schema for the passwords API
type Login struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   LoginSpec   `json:"spec,omitempty"`
	Status LoginStatus `json:"status,omitempty"`
}

// LoginSpec defines the desired state of Login
type LoginSpec struct {
	Length   uint8         `json:"length,omitempty"`
	Password *PasswordSpec `json:"password,omitempty"`
}

// PasswordSpec defines the desired state of Password
type PasswordSpec struct {
	Length       uint8  `json:"length,omitempty"`
	CharacterSet string `json:"characterset,omitempty"`
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
// SSHKey is the Schema for the passwords API
type SSHKey struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   SSHKeySpec   `json:"spec,omitempty"`
	Status SSHKeyStatus `json:"status,omitempty"`
}

// SSHKeySpec defines the desired state of SSHKey
type SSHKeySpec struct {
	BitSize    int        `json:"bitsize,omitempty"`
	KeyType    SSHKeyType `json:"keytype,omitempty"`
	Passphrase string     `json:"passphrase,omitempty"`
}

// SSHKeyStatus defines the observed state of SSHKey
type SSHKeyStatus struct {
	Ready bool `json:"ready"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// SSHKeyList contains a list of SSHKey
type SSHKeyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []SSHKey `json:"items"`
}
