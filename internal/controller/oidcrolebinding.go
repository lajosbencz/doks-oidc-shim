// Package controller implements the OIDCRoleBinding reconciler.
package controller

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	oidcshimv1alpha1 "github.com/lajosbencz/doks-oidc-shim/api/v1alpha1"
)

const saPrefix = "shim-"

// OIDCRoleBindingReconciler reconciles OIDCRoleBinding objects.
//
// +kubebuilder:rbac:groups=oidcshim.io,resources=oidcrolebindings,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=oidcshim.io,resources=oidcrolebindings/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=oidcshim.io,resources=oidcrolebindings/finalizers,verbs=update
// +kubebuilder:rbac:groups="",resources=serviceaccounts,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=rbac.authorization.k8s.io,resources=clusterrolebindings;rolebindings,verbs=get;list;watch;create;update;patch;delete
type OIDCRoleBindingReconciler struct {
	client.Client
	Scheme    *runtime.Scheme
	Namespace string // empty = cluster-wide; restricts watches to this namespace
}

// Reconcile reconciles a single OIDCRoleBinding.
func (r *OIDCRoleBindingReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	var orb oidcshimv1alpha1.OIDCRoleBinding
	if err := r.Get(ctx, req.NamespacedName, &orb); err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, fmt.Errorf("getting OIDCRoleBinding: %w", err)
	}

	if !orb.DeletionTimestamp.IsZero() {
		if controllerutil.ContainsFinalizer(&orb, oidcshimv1alpha1.Finalizer) {
			if err := r.cleanupOwnedResources(ctx, &orb); err != nil {
				return ctrl.Result{}, err
			}
			controllerutil.RemoveFinalizer(&orb, oidcshimv1alpha1.Finalizer)
			if err := r.Update(ctx, &orb); err != nil {
				return ctrl.Result{}, fmt.Errorf("removing finalizer: %w", err)
			}
		}
		return ctrl.Result{}, nil
	}

	if !controllerutil.ContainsFinalizer(&orb, oidcshimv1alpha1.Finalizer) {
		controllerutil.AddFinalizer(&orb, oidcshimv1alpha1.Finalizer)
		if err := r.Update(ctx, &orb); err != nil {
			return ctrl.Result{}, fmt.Errorf("adding finalizer: %w", err)
		}
	}

	sa, reconcileErr := r.ensureServiceAccount(ctx, &orb)
	if reconcileErr == nil {
		reconcileErr = r.ensureBinding(ctx, &orb, sa)
	}

	// Build the desired status, then persist it in a single Status().Update()
	// so transient mutations (e.g. ServiceAccountName) are never lost when the
	// condition itself didn't change.
	statusChanged := false
	if reconcileErr == nil && orb.Status.ServiceAccountName != sa.Name {
		orb.Status.ServiceAccountName = sa.Name
		statusChanged = true
	}
	cond := metav1.Condition{
		Type:               "Ready",
		ObservedGeneration: orb.Generation,
	}
	if reconcileErr != nil {
		cond.Status = metav1.ConditionFalse
		cond.Reason = "ReconcileError"
		cond.Message = reconcileErr.Error()
	} else {
		cond.Status = metav1.ConditionTrue
		cond.Reason = "Reconciled"
		cond.Message = "ServiceAccount and binding are in sync"
	}
	if meta.SetStatusCondition(&orb.Status.Conditions, cond) {
		statusChanged = true
	}
	if statusChanged {
		if err := r.Status().Update(ctx, &orb); err != nil {
			logger.Error(err, "updating status", "orb", orb.Name)
		}
	}

	if reconcileErr != nil {
		return ctrl.Result{}, reconcileErr
	}
	logger.Info("reconciled", "name", orb.Name, "claimValue", orb.Spec.ClaimValue, "sa", sa.Name)
	return ctrl.Result{}, nil
}

// ensureServiceAccount creates or returns the existing ServiceAccount for the role.
func (r *OIDCRoleBindingReconciler) ensureServiceAccount(ctx context.Context, orb *oidcshimv1alpha1.OIDCRoleBinding) (*corev1.ServiceAccount, error) {
	sa := &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      saPrefix + orb.Spec.ClaimValue,
			Namespace: orb.Namespace,
			Labels:    map[string]string{oidcshimv1alpha1.RoleLabel: orb.Spec.ClaimValue},
		},
	}
	if err := controllerutil.SetControllerReference(orb, sa, r.Scheme); err != nil {
		return nil, fmt.Errorf("setting controller reference on SA: %w", err)
	}

	existing := &corev1.ServiceAccount{}
	err := r.Get(ctx, client.ObjectKeyFromObject(sa), existing)
	if apierrors.IsNotFound(err) {
		if err := r.Create(ctx, sa, client.FieldOwner(oidcshimv1alpha1.FieldManagerOperator)); err != nil {
			return nil, fmt.Errorf("creating ServiceAccount %q: %w", sa.Name, err)
		}
		return sa, nil
	}
	if err != nil {
		return nil, fmt.Errorf("getting ServiceAccount %q: %w", sa.Name, err)
	}
	return existing, nil
}

// ensureBinding creates or updates the ClusterRoleBinding or RoleBinding.
func (r *OIDCRoleBindingReconciler) ensureBinding(ctx context.Context, orb *oidcshimv1alpha1.OIDCRoleBinding, sa *corev1.ServiceAccount) error {
	subject := rbacv1.Subject{
		Kind:      "ServiceAccount",
		Name:      sa.Name,
		Namespace: sa.Namespace,
	}

	if orb.Spec.ClusterRoleRef != nil {
		return r.ensureClusterRoleBinding(ctx, orb, subject)
	}
	return r.ensureRoleBinding(ctx, orb, subject)
}

func (r *OIDCRoleBindingReconciler) ensureClusterRoleBinding(ctx context.Context, orb *oidcshimv1alpha1.OIDCRoleBinding, subject rbacv1.Subject) error {
	desired := &rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:   clusterRoleBindingName(orb),
			Labels: ownerLabels(orb),
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: rbacv1.GroupName,
			Kind:     "ClusterRole",
			Name:     orb.Spec.ClusterRoleRef.Name,
		},
		Subjects: []rbacv1.Subject{subject},
	}

	existing := &rbacv1.ClusterRoleBinding{}
	err := r.Get(ctx, client.ObjectKeyFromObject(desired), existing)
	if apierrors.IsNotFound(err) {
		if err := r.Create(ctx, desired, client.FieldOwner(oidcshimv1alpha1.FieldManagerOperator)); err != nil {
			return fmt.Errorf("creating ClusterRoleBinding %q: %w", desired.Name, err)
		}
		return nil
	}
	if err != nil {
		return fmt.Errorf("getting ClusterRoleBinding %q: %w", desired.Name, err)
	}
	existing.RoleRef = desired.RoleRef
	existing.Subjects = desired.Subjects
	if err := r.Update(ctx, existing, client.FieldOwner(oidcshimv1alpha1.FieldManagerOperator)); err != nil {
		return fmt.Errorf("updating ClusterRoleBinding %q: %w", desired.Name, err)
	}
	return nil
}

func (r *OIDCRoleBindingReconciler) ensureRoleBinding(ctx context.Context, orb *oidcshimv1alpha1.OIDCRoleBinding, subject rbacv1.Subject) error {
	desired := &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      roleBindingName(orb),
			Namespace: orb.Spec.RoleRef.Namespace,
			Labels:    ownerLabels(orb),
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: rbacv1.GroupName,
			Kind:     "Role",
			Name:     orb.Spec.RoleRef.Name,
		},
		Subjects: []rbacv1.Subject{subject},
	}

	existing := &rbacv1.RoleBinding{}
	err := r.Get(ctx, client.ObjectKeyFromObject(desired), existing)
	if apierrors.IsNotFound(err) {
		if err := r.Create(ctx, desired, client.FieldOwner(oidcshimv1alpha1.FieldManagerOperator)); err != nil {
			return fmt.Errorf("creating RoleBinding %q: %w", desired.Name, err)
		}
		return nil
	}
	if err != nil {
		return fmt.Errorf("getting RoleBinding %q: %w", desired.Name, err)
	}
	existing.RoleRef = desired.RoleRef
	existing.Subjects = desired.Subjects
	if err := r.Update(ctx, existing, client.FieldOwner(oidcshimv1alpha1.FieldManagerOperator)); err != nil {
		return fmt.Errorf("updating RoleBinding %q: %w", desired.Name, err)
	}
	return nil
}

// cleanupOwnedResources deletes the cluster-scoped ClusterRoleBinding and any
// cross-namespace RoleBinding that ownerReference garbage collection cannot reach.
// Same-namespace SAs are GC'd via the controllerReference set in ensureServiceAccount.
func (r *OIDCRoleBindingReconciler) cleanupOwnedResources(ctx context.Context, orb *oidcshimv1alpha1.OIDCRoleBinding) error {
	if orb.Spec.ClusterRoleRef != nil {
		crb := &rbacv1.ClusterRoleBinding{}
		crb.Name = clusterRoleBindingName(orb)
		if err := client.IgnoreNotFound(r.Delete(ctx, crb)); err != nil {
			return fmt.Errorf("deleting ClusterRoleBinding %q: %w", crb.Name, err)
		}
	}
	if orb.Spec.RoleRef != nil {
		rb := &rbacv1.RoleBinding{}
		rb.Name = roleBindingName(orb)
		rb.Namespace = orb.Spec.RoleRef.Namespace
		if err := client.IgnoreNotFound(r.Delete(ctx, rb)); err != nil {
			return fmt.Errorf("deleting RoleBinding %q: %w", rb.Name, err)
		}
	}
	return nil
}

func clusterRoleBindingName(orb *oidcshimv1alpha1.OIDCRoleBinding) string {
	return "oidcshim-" + orb.Namespace + "-" + orb.Spec.ClaimValue
}

func roleBindingName(orb *oidcshimv1alpha1.OIDCRoleBinding) string {
	return "oidcshim-" + orb.Spec.ClaimValue
}

// ownerLabels are stamped onto bindings so the controller can reverse-map them
// to their owning OIDCRoleBinding without ownerReferences (which don't work for
// cluster-scoped or cross-namespace objects).
func ownerLabels(orb *oidcshimv1alpha1.OIDCRoleBinding) map[string]string {
	return map[string]string{
		oidcshimv1alpha1.RoleLabel:           orb.Spec.ClaimValue,
		oidcshimv1alpha1.OwnerNamespaceLabel: orb.Namespace,
		oidcshimv1alpha1.OwnerNameLabel:      orb.Name,
	}
}

// bindingToOwner extracts the owner-label pair on a CRB/RB and emits a single
// reconcile request for the owning OIDCRoleBinding. Returns nothing if the labels
// are missing — defensive against external objects sharing our naming.
func bindingToOwner(_ context.Context, obj client.Object) []reconcile.Request {
	labels := obj.GetLabels()
	ns, hasNs := labels[oidcshimv1alpha1.OwnerNamespaceLabel]
	name, hasName := labels[oidcshimv1alpha1.OwnerNameLabel]
	if !hasNs || !hasName {
		return nil
	}
	return []reconcile.Request{{NamespacedName: types.NamespacedName{Namespace: ns, Name: name}}}
}

// SetupWithManager registers the controller and declares the resources it watches.
//
// Same-namespace ServiceAccounts use ownerReferences (Owns), so deletion or edit
// triggers a reconcile via standard controller-runtime semantics. ClusterRoleBindings
// (cluster-scoped) and RoleBindings in foreign namespaces cannot use ownerReferences
// and instead carry owner-labels; bindingToOwner reverse-maps watch events on those.
func (r *OIDCRoleBindingReconciler) SetupWithManager(mgr ctrl.Manager) error {
	if err := ctrl.NewControllerManagedBy(mgr).
		For(&oidcshimv1alpha1.OIDCRoleBinding{}).
		Owns(&corev1.ServiceAccount{}).
		Watches(
			&rbacv1.ClusterRoleBinding{},
			handler.EnqueueRequestsFromMapFunc(bindingToOwner),
		).
		Watches(
			&rbacv1.RoleBinding{},
			handler.EnqueueRequestsFromMapFunc(bindingToOwner),
		).
		Complete(r); err != nil {
		return fmt.Errorf("setting up controller: %w", err)
	}
	return nil
}
