# `hpa_test.go` Summary

Verifies that a HorizontalPodAutoscaler with every metric type can be created through the Norman project API on the local cluster.

## `TestHPA`
**Arrange:**
- Creates a project, a namespace, and an nginx workload requesting 100m CPU.

**Act:** Creates an HPA for the workload with maxReplicas 10 and four metrics: Resource (cpu, 50% utilization), Pods (average value 50), External (value 50), and Object (an Ingress, value 50).

**Assert:**
- Checks the HPA is the only one listed in the namespace.
- Checks its state is "initializing".
