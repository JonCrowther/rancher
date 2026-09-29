# `hpa_test.go` Summary

Verifies that a HorizontalPodAutoscaler with every metric type can be created through the Norman project API on the local cluster.

## `TestHPA`
Creates a project, namespace and an nginx workload requesting 100m CPU, then creates an HPA for the workload with maxReplicas 10 and four metrics: Resource (cpu, 50% utilization), Pods (average value 50), External (value 50) and Object (an Ingress, value 50).
- Checks the HPA is the only one listed in the namespace.
- Checks its state is "initializing".
