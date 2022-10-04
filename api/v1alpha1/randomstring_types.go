/*
Copyright 2022.

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
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!
// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

type SecretRef struct {
	corev1.LocalObjectReference `json:",inline"`
	Key                         string `json:"key"`
}

// RandomStringSpec defines the desired state of RandomString
type RandomStringSpec struct {
	// INSERT ADDITIONAL SPEC FIELDS - desired state of cluster
	// Important: Run "make" to regenerate code after modifying this file

	// +kubebuilder:validation:Minimum=1
	Length           int        `json:"length,omitempty"`
	WriteSecretToRef *SecretRef `json:"writeSecretToRef,omitempty"`

	// +kubebuilder:validation:Enum=base64;base64prefixed;byte
	// the format of the output, "base64", "base64prefixed", or "byte"
	Format string `json:"format,omitempty"`
}

// RandomStringStatus defines the observed state of RandomString
type RandomStringStatus struct {
	// INSERT ADDITIONAL STATUS FIELD - define observed state of cluster
	// Important: Run "make" to regenerate code after modifying this file
}

//+kubebuilder:object:root=true
//+kubebuilder:subresource:status

// RandomString is the Schema for the randomstrings API
type RandomString struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   RandomStringSpec   `json:"spec,omitempty"`
	Status RandomStringStatus `json:"status,omitempty"`
}

//+kubebuilder:object:root=true

// RandomStringList contains a list of RandomString
type RandomStringList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []RandomString `json:"items"`
}

func init() {
	SchemeBuilder.Register(&RandomString{}, &RandomStringList{})
}
