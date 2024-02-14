package kubeconfig

import (
	"context"

	v3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	managementv3 "github.com/rancher/rancher/pkg/generated/controllers/management.cattle.io/v3"
	"github.com/sirupsen/logrus"
)

func Register(ctx context.Context, kubeconfigs managementv3.KubeconfigController) {
	kubeconfigs.OnChange(ctx, "kubeconfigs-update", sync)
}

func sync(_ string, obj *v3.Kubeconfig) (*v3.Kubeconfig, error) {
	if obj == nil || obj.DeletionTimestamp != nil {
		return nil, nil
	}

	err := reconcileKubeconfig(obj)
	if err != nil {
		return nil, err
	}
	return obj, nil
}

func reconcileKubeconfig(kubeconfig *v3.Kubeconfig) error {
	logrus.Infof("reconcilingKubeconfig called")
	// TODO
	// Insert server URL
	// Make sure the cluster matches the cluster namespace
	// Fill the data section
	return nil
}
