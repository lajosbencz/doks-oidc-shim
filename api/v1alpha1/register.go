package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// GroupVersion is the API group and version for this package.
var GroupVersion = schema.GroupVersion{Group: "oidcshim.io", Version: "v1alpha1"}

// SchemeBuilder collects functions that add types to a runtime.Scheme.
var SchemeBuilder = runtime.NewSchemeBuilder(addKnownTypes)

// AddToScheme adds the types in this package to the given scheme.
var AddToScheme = SchemeBuilder.AddToScheme

// Resource returns a GroupResource for the given resource name.
func Resource(resource string) schema.GroupResource {
	return GroupVersion.WithResource(resource).GroupResource()
}

// Kind returns a GroupKind for the given kind name.
func Kind(kind string) schema.GroupKind {
	return GroupVersion.WithKind(kind).GroupKind()
}

func addKnownTypes(scheme *runtime.Scheme) error {
	scheme.AddKnownTypes(GroupVersion,
		&OIDCRoleBinding{},
		&OIDCRoleBindingList{},
	)
	metav1.AddToGroupVersion(scheme, GroupVersion)
	return nil
}
