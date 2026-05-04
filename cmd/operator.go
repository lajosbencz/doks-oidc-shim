package main

import (
	"fmt"
	"log/slog"

	"github.com/lajosbencz/doks-oidc-shim/api/v1alpha1"
	"github.com/lajosbencz/doks-oidc-shim/internal/controller"
	"github.com/spf13/cobra"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
)

func newOperatorCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "operator",
		Short: "Run the OIDC role binding operator",
		RunE:  runOperator,
	}
	f := cmd.Flags()
	f.String("kubeconfig", "", "path to kubeconfig (empty = in-cluster)")
	f.Bool("leader-elect", false, "enable leader election for high-availability deployments")
	f.String("metrics-bind-address", ":8383", "address for the metrics endpoint")
	f.String("health-probe-bind-address", ":8081", "address for the health probe endpoint")
	f.String("namespace", "", "restrict the operator to a single namespace (empty = cluster-wide)")
	return cmd
}

func runOperator(cmd *cobra.Command, _ []string) error {
	kubeconfig, _ := cmd.Flags().GetString("kubeconfig")
	leaderElect, _ := cmd.Flags().GetBool("leader-elect")
	metricsAddr, _ := cmd.Flags().GetString("metrics-bind-address")
	healthAddr, _ := cmd.Flags().GetString("health-probe-bind-address")
	namespace, _ := cmd.Flags().GetString("namespace")

	scheme := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(scheme); err != nil {
		return fmt.Errorf("registering k8s schemes: %w", err)
	}
	if err := corev1.AddToScheme(scheme); err != nil {
		return fmt.Errorf("registering corev1 scheme: %w", err)
	}
	if err := rbacv1.AddToScheme(scheme); err != nil {
		return fmt.Errorf("registering rbacv1 scheme: %w", err)
	}
	if err := v1alpha1.AddToScheme(scheme); err != nil {
		return fmt.Errorf("registering oidcshim scheme: %w", err)
	}

	var restCfg *rest.Config
	var err error
	if kubeconfig != "" {
		restCfg, err = clientcmd.BuildConfigFromFlags("", kubeconfig)
	} else {
		restCfg, err = ctrl.GetConfig() // honors KUBECONFIG env, ~/.kube/config, in-cluster
	}
	if err != nil {
		return fmt.Errorf("getting k8s config: %w", err)
	}

	mgr, err := ctrl.NewManager(restCfg, ctrl.Options{
		Scheme: scheme,
		Metrics: metricsserver.Options{
			BindAddress: metricsAddr,
		},
		HealthProbeBindAddress: healthAddr,
		LeaderElection:         leaderElect,
		LeaderElectionID:       "oidcshim.io",
	})
	if err != nil {
		return fmt.Errorf("creating manager: %w", err)
	}

	if err := (&controller.OIDCRoleBindingReconciler{
		Client:    mgr.GetClient(),
		Scheme:    mgr.GetScheme(),
		Namespace: namespace,
	}).SetupWithManager(mgr); err != nil {
		return fmt.Errorf("setting up OIDCRoleBinding controller: %w", err)
	}

	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		return fmt.Errorf("adding healthz check: %w", err)
	}
	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		return fmt.Errorf("adding readyz check: %w", err)
	}

	slog.Info("starting operator", "namespace", namespace, "leader-elect", leaderElect)
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		return fmt.Errorf("running operator: %w", err)
	}

	return nil
}
