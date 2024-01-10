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

// +genclient
// +k8s:register-gen
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +k8s:genclient:method=UpdateStatus,verb=updateStatus,subresource=status, \
// result=k8s.io/apimachinery/pkg/apis/meta/v1.Status
// Password is the Schema for the passwords API
type Password struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   PasswordSpec   `json:"spec,omitempty"`
	Status PasswordStatus `json:"status,omitempty"`
}

// PasswordSpec defines the desired state of Password
type PasswordSpec struct {
	Length       uint8  `json:"length,omitempty"`
	CharacterSet string `json:"characterset,omitempty"`
}

// PasswordStatus defines the observed state of Password
type PasswordStatus struct {
	Ready bool `json:"ready"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// PasswordList contains a list of Password
type PasswordList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Password `json:"items"`
}

// +genclient
// +k8s:register-gen
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +k8s:genclient:method=UpdateStatus,verb=updateStatus,subresource=status, \
// result=k8s.io/apimachinery/pkg/apis/meta/v1.Status
// Rotation is the Schema for the rotation API
type Rotation struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   RotationSpec   `json:"spec,omitempty"`
	Status RotationStatus `json:"status,omitempty"`
}

// RotationSpec defines the desired state of Rotation
type RotationSpec struct {
	Target string `json:"target"`
}

const (
	PhaseRunning  = "RUNNING"
	PhaseComplete = "COMPLETE"
)

// RotationStatus defines the observed state of Rotation
type RotationStatus struct {
	Phase string `json:"phase,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// RotationList contains a list of Rotation
type RotationList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Rotation `json:"items"`
}
