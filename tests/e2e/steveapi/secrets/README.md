Steve API Integration Tests
===========================

This test suite tests the steve resource listing API using secrets as the main
test resource, since they are quick to create. The suite uses five user
scenarios, from a cluster owner down to a user who has access to a few
resources in a few namespaces, in order to demonstrate steve's ability to
collect and return resources across multiple access partitions. There are 33
sample secrets across 9 namespaces: 5 namespaces in project test-prj-1 hold 5
secrets each, and 2 namespaces in project test-prj-2 and 2 namespaces outside
any project hold 2 secrets each. Some of the sample secrets have labels or
annotations to demonstrate query parameters that use such fields.

Users
-----

| User   | Access                                                                              |
|--------|-------------------------------------------------------------------------------------|
| user-a | Project Owner of test-prj-1                                                         |
| user-b | get,list for secrets in namespace test-ns-1                                         |
| user-c | get,list for secrets test1,test2 in namespaces test-ns-1,test-ns-2,test-ns-3        |
| user-d | Project Owner of test-prj-1 and test-prj-2, get,list for secrets in test-ns-8,test-ns-9 |
| user-e | Cluster Owner                                                                       |

Users with namespace-level access (user-b, user-c, user-d) are also cluster
members, so they can reach the cluster.

TestList writes a request/response example for every case to `testdata/`:
`testdata/output.csv` indexes the examples in `testdata/json/`.

Running
-------
Create a `steveapi.yaml` file like the following:

```yaml
rancher:
    host: localhost:8444
    adminToken: token-XXX:YYY
```

`adminToken` can be obtained by logging in as the `admin` user into Rancher, then clicking on the user icon (in the top
right corner) -> Account & API Keys -> Create API Key. Choose "No Scope" for the Scope, click Create and copy the Bearer
Token string.

Then run as a normal go test, from your IDE or via:

```shell
CATTLE_TEST_CONFIG=steveapi.yaml go test -count=1 -v -run TestSecretsTestSuite
```
