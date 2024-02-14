package v3

import (
	"github.com/rancher/norman/types"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

type Kubeconfig struct {
	types.Namespaced `json:",inline"`
	metav1.TypeMeta  `json:",inline"`

	// Standard object metadata; More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#metadata.
	// +optional
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// Cluster is the cluster that this applies to.
	// +optional
	Cluster string `json:"cluster,omitempty"`

	// ServerURL is the url used to contact the cluster. Changes with ACE.
	// +optional
	ServerURL string `json:"serverurl,omitempty"`

	// Data is a string with the kubeconfig.
	// +optional
	Data string `json:"rawkubeconfig,omitempty"`
}
