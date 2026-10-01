package clusters

import (
	management "github.com/rancher/shepherd/clients/rancher/generated/management/v3"
	namegen "github.com/rancher/shepherd/pkg/namegenerator"
)

// TestImportInitialConditions asserts that a newly created import cluster
// has no conditions set immediately after creation, mirroring the Python
// test test_import_initial_conditions in test_cluster_defaults.py.
func (s *ClustersTestSuite) TestImportInitialConditions() {
	client := s.newSubSession()

	cluster, err := client.Management.Cluster.Create(&management.Cluster{
		Name: namegen.AppendRandomString("cluster-"),
	})
	s.Require().NoError(err)

	s.Empty(cluster.Conditions, "expected no conditions on a newly created import cluster")
}
