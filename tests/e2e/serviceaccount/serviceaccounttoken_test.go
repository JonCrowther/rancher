package serviceaccount

import (
	"context"
	"sync"

	"github.com/rancher/rancher/pkg/serviceaccounttoken"
	"github.com/rancher/shepherd/extensions/kubeconfig"
	extunstructured "github.com/rancher/shepherd/extensions/unstructured"
	namegen "github.com/rancher/shepherd/pkg/namegenerator"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// TestSingleSecretForServiceAccount tests that concurrent calls to EnsureSecretForServiceAccount for
// the same service account leave exactly one token Secret. Each call races to create a Secret and
// annotate the service account with it; the losers must roll back the Secret they created.
func (s *ServiceAccountTestSuite) TestSingleSecretForServiceAccount() {
	client := s.newSubSession()

	// EnsureSecretForServiceAccount runs in this test process, not in Rancher, and takes typed
	// client-go interfaces, so build a clientset for the cluster.
	kubeConfig, err := kubeconfig.GetKubeconfig(client, s.clusterID)
	s.Require().NoError(err)
	restConfig, err := (*kubeConfig).ClientConfig()
	s.Require().NoError(err)
	clientset, err := kubernetes.NewForConfig(restConfig)
	s.Require().NoError(err)

	// The clientset isn't tracked by the session, so create the namespace through the session's
	// dynamic client instead. Deleting it also removes the service account and Secrets inside it.
	dynamicClient, err := client.GetDownStreamClusterClient(s.clusterID)
	s.Require().NoError(err)
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: namegen.AppendRandomString("test-ns-")}}
	_, err = dynamicClient.Resource(corev1.SchemeGroupVersion.WithResource("namespaces")).Namespace("").Create(context.Background(), extunstructured.MustToUnstructured(ns), metav1.CreateOptions{})
	s.Require().NoError(err)

	serviceAccount, err := clientset.CoreV1().ServiceAccounts(ns.Name).Create(context.Background(), &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{Name: "test", Namespace: ns.Name},
	}, metav1.CreateOptions{})
	s.Require().NoError(err)

	// Require can't be called from a goroutine, so record each call's error and check them once all
	// calls have returned.
	errs := make([]error, 10)
	var wg sync.WaitGroup
	for i := range errs {
		wg.Go(func() {
			_, errs[i] = serviceaccounttoken.EnsureSecretForServiceAccount(context.Background(), nil, clientset.CoreV1(), clientset.CoreV1(), serviceAccount.DeepCopy())
		})
	}
	wg.Wait()
	for i, err := range errs {
		s.Require().NoError(err, "EnsureSecretForServiceAccount call %d failed", i)
	}

	// Every call has returned, including the losers' rollback deletes, so the result can be checked
	// directly without polling.
	secrets, err := clientset.CoreV1().Secrets(ns.Name).List(context.Background(), metav1.ListOptions{
		LabelSelector: serviceaccounttoken.ServiceAccountSecretLabel + "=" + serviceAccount.Name,
	})
	s.Require().NoError(err)
	s.Require().Len(secrets.Items, 1, "expected exactly one token Secret for the service account")

	// The remaining Secret must be the one the service account references, not an orphan.
	serviceAccount, err = clientset.CoreV1().ServiceAccounts(ns.Name).Get(context.Background(), serviceAccount.Name, metav1.GetOptions{})
	s.Require().NoError(err)
	s.Require().Equal(ns.Name+"/"+secrets.Items[0].Name, serviceAccount.Annotations[serviceaccounttoken.ServiceAccountSecretRefAnnotation])
}
