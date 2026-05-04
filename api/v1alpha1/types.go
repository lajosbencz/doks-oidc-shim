// Package v1alpha1 contains API types for the oidcshim.io group.
package v1alpha1

import metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

// Shared label and field-manager constants.
const (
	// RoleLabel is set on ServiceAccounts to associate them with a JWT groups-claim value.
	RoleLabel = "oidcshim.io/role"

	// OwnerNamespaceLabel is set on ClusterRoleBinding/RoleBinding objects to
	// reverse-map them to the OIDCRoleBinding that produced them. ClusterRoleBindings
	// are cluster-scoped and cross-namespace RoleBindings cannot use ownerReferences,
	// so the controller relies on these labels for watch-driven reconciliation.
	OwnerNamespaceLabel = "oidcshim.io/owner-namespace"

	// OwnerNameLabel is the OIDCRoleBinding object name; pairs with OwnerNamespaceLabel.
	OwnerNameLabel = "oidcshim.io/owner-name"

	// FieldManagerOperator identifies fields owned by the operator for SSA.
	FieldManagerOperator = "oidcshim-operator"

	// FieldManagerProxy identifies fields owned by the proxy for SSA.
	FieldManagerProxy = "oidcshim-proxy"

	// Finalizer keeps OIDCRoleBinding objects around until owned ClusterRoleBindings
	// (and cross-namespace RoleBindings) are torn down by the operator.
	Finalizer = "oidcshim.io/cleanup"
)

// OIDCRoleBinding maps a JWT groups-claim value to a Kubernetes ClusterRole or
// namespaced Role. The operator creates a labelled ServiceAccount and the
// appropriate binding; the proxy issues short-lived tokens for that SA via the
// TokenRequest API.
//
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:shortName=orb
// +kubebuilder:printcolumn:name="ClaimValue",type=string,JSONPath=".spec.claimValue"
// +kubebuilder:printcolumn:name="ServiceAccount",type=string,JSONPath=".status.serviceAccountName"
// +kubebuilder:printcolumn:name="Ready",type=string,JSONPath=".status.conditions[?(@.type==\"Ready\")].status"
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=".metadata.creationTimestamp"
type OIDCRoleBinding struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   OIDCRoleBindingSpec   `json:"spec"`
	Status OIDCRoleBindingStatus `json:"status,omitempty"`
}

// OIDCRoleBindingSpec defines the desired state.
// Exactly one of ClusterRoleRef or RoleRef must be set.
//
// +kubebuilder:validation:XValidation:rule="(has(self.clusterRoleRef) && !has(self.roleRef)) || (!has(self.clusterRoleRef) && has(self.roleRef))",message="exactly one of clusterRoleRef or roleRef must be specified"
type OIDCRoleBindingSpec struct {
	// ClaimValue is the value matched against the groups JWT claim.
	// Must conform to Kubernetes label-value constraints (max 63 chars, [a-zA-Z0-9_-]).
	//
	// +kubebuilder:validation:Pattern=`^[a-zA-Z0-9][a-zA-Z0-9_-]{0,62}$`
	ClaimValue string `json:"claimValue"`

	// ClusterRoleRef binds the SA to a ClusterRole (cluster-wide access).
	// Mutually exclusive with RoleRef.
	//
	// +optional
	ClusterRoleRef *ClusterRoleRef `json:"clusterRoleRef,omitempty"`

	// RoleRef binds the SA to a namespaced Role.
	// Mutually exclusive with ClusterRoleRef.
	//
	// +optional
	RoleRef *RoleRef `json:"roleRef,omitempty"`
}

// ClusterRoleRef references a ClusterRole.
type ClusterRoleRef struct {
	// Name of the ClusterRole.
	Name string `json:"name"`
}

// RoleRef references a namespaced Role.
type RoleRef struct {
	// Name of the Role.
	Name string `json:"name"`
	// Namespace where the Role lives.
	Namespace string `json:"namespace"`
}

// OIDCRoleBindingStatus describes the observed state.
type OIDCRoleBindingStatus struct {
	// ServiceAccountName is the name of the provisioned ServiceAccount.
	//
	// +optional
	ServiceAccountName string `json:"serviceAccountName,omitempty"`

	// Conditions represent the latest observations of the binding's state.
	// The "Ready" condition indicates whether reconciliation succeeded.
	//
	// +optional
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// OIDCRoleBindingList contains a list of OIDCRoleBinding.
//
// +kubebuilder:object:root=true
type OIDCRoleBindingList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []OIDCRoleBinding `json:"items"`
}
