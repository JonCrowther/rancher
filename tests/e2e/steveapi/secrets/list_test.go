package secrets

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	stevesecrets "github.com/rancher/rancher/tests/e2e/actions/secrets"
	clientv1 "github.com/rancher/shepherd/clients/rancher/v1"
)

const (
	continueToken    = "nondeterministictoken"
	revisionNum      = "nondeterministicint"
	fakeTestID       = "nondeterministicid"
	defautlUrlString = "https://rancherurl/"
)

var (
	urlRegex     = regexp.MustCompile(`https://([\w.:]+)/`)
	continueReg  = regexp.MustCompile(`(continue=)[\w]+(%3D){0,2}`)
	revisionReg  = regexp.MustCompile(`(revision=)[\d]+`)
	testLabelReg = regexp.MustCompile(`(labelSelector=test.cattle.io%2Fsteveapi%3D)[\w]+`)
	projectTag   = regexp.MustCompile(`(test-prj-[1-9])`)
	namespaceTag = regexp.MustCompile(`(test-ns-[1-9])`)
)

func getFileName(user, ns, query string) string {
	if user == "" {
		user = "none"
	}
	if ns == "" {
		ns = "none"
	}
	if query == "" {
		query = "none"
	} else {
		query = strings.ReplaceAll(query, "/", "%2F")
		query = strings.ReplaceAll(query, "<", "%3C")
		query = strings.ReplaceAll(query, ">", "%3E")
	}
	return user + "_" + ns + "_" + query + ".json"
}

func getCurlURL(client *clientv1.Client, namespace, query string) (string, error) {
	curlURL, err := client.APIBaseClient.Ops.GetCollectionURL(stevesecrets.SecretSteveType, "GET")
	if err != nil {
		return "", err
	}
	if namespace != "" {
		curlURL += "/" + namespace
	}
	if query != "" {
		curlURL += "?" + query
	}

	curlURL = urlRegex.ReplaceAllString(curlURL, defautlUrlString)
	return curlURL, nil
}

func formatJSON(obj *clientv1.SteveCollection) ([]byte, error) {
	jsonResp, err := json.Marshal(obj)
	if err != nil {
		return nil, err
	}
	var mapResp map[string]any
	err = json.Unmarshal(jsonResp, &mapResp)
	if err != nil {
		return nil, err
	}

	mapResp["revision"] = "100"
	if _, ok := mapResp["continue"]; ok {
		mapResp["continue"] = continueToken
	}
	if pagination, ok := mapResp["pagination"].(map[string]any); ok {
		if next, ok := pagination["next"].(string); ok {
			next = continueReg.ReplaceAllString(next, "${1}"+continueToken)
			next = revisionReg.ReplaceAllString(next, "${1}"+revisionNum)
			next = testLabelReg.ReplaceAllString(next, "${1}"+fakeTestID)
			pagination["next"] = next
			mapResp["pagination"] = pagination
		}
	}
	data, ok := mapResp["data"].([]any)
	if ok {
		for i := range data {
			delete(data[i].(map[string]any), "JSONResp")
			delete(data[i].(map[string]any)["metadata"].(map[string]any), "creationTimestamp")
			delete(data[i].(map[string]any)["metadata"].(map[string]any), "managedFields")
			delete(data[i].(map[string]any)["metadata"].(map[string]any), "uid")
			data[i].(map[string]any)["metadata"].(map[string]any)["labels"].(map[string]any)[steveAPITestLabel] = fakeTestID
			data[i].(map[string]any)["metadata"].(map[string]any)["resourceVersion"] = "1000"
		}
		mapResp["data"] = data
	}
	jsonBytes, err := json.MarshalIndent(mapResp, "", "  ")
	if err != nil {
		return nil, err
	}
	jsonString := string(jsonBytes)
	for k, v := range namespaceMap {
		jsonString = strings.ReplaceAll(jsonString, v, k)
	}
	jsonString = urlRegex.ReplaceAllString(jsonString, defautlUrlString)
	return []byte(jsonString), nil
}

func setUpResults() (*csv.Writer, *os.File, string, error) {
	testDataDir := "testdata"
	err := os.MkdirAll(testDataDir, 0755)
	if err != nil {
		return nil, nil, "", err
	}
	outputFile := filepath.Join(testDataDir, "output.csv")
	fields := []string{"user", "url", "response"}
	csvFile, err := os.OpenFile(outputFile, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return nil, nil, "", err
	}
	// csv.Writer buffers internally and Flush drains that buffer, so write straight to the file
	csvWriter := csv.NewWriter(csvFile)
	if err := csvWriter.Write(fields); err != nil {
		csvFile.Close()
		return nil, nil, "", err
	}
	jsonDir := filepath.Join(testDataDir, "json")
	err = os.MkdirAll(jsonDir, 0755)
	if err != nil {
		csvFile.Close()
		return nil, nil, "", err
	}
	return csvWriter, csvFile, jsonDir, nil
}

func writeResp(csvWriter *csv.Writer, user, url, path string, resp []byte) error {
	if err := os.WriteFile(path, resp, 0644); err != nil {
		return err
	}
	relPath, err := filepath.Rel("testdata", path)
	if err != nil {
		relPath = path
	}
	return csvWriter.Write([]string{user, url, fmt.Sprintf("[%s](%s)", relPath, relPath)})
}

// objectKey identifies a listed secret by name and namespace.
type objectKey struct {
	Name      string
	Namespace string
}

// expectedKeys converts a test case's expected objects to keys, resolving each namespace alias (e.g.
// "test-ns-1") to the namespace SetupSuite created. Without withNamespace the namespace is left empty.
func expectedKeys(expect []map[string]string, withNamespace bool) []objectKey {
	keys := make([]objectKey, 0, len(expect))
	for _, w := range expect {
		key := objectKey{Name: w["name"]}
		if withNamespace {
			key.Namespace = namespaceMap[w["namespace"]]
		}
		keys = append(keys, key)
	}
	return keys
}

// receivedKeys converts listed objects to keys, in order. Without withNamespace the namespace is
// left empty.
func receivedKeys(list []clientv1.SteveAPIObject, withNamespace bool) []objectKey {
	keys := make([]objectKey, 0, len(list))
	for _, obj := range list {
		key := objectKey{Name: obj.Name}
		if withNamespace {
			key.Namespace = obj.Namespace
		}
		keys = append(keys, key)
	}
	return keys
}

// expectedSummaries resolves the namespace aliases keying a metadata.namespace summary to the
// namespaces SetupSuite created.
func expectedSummaries(summaries []clientv1.SteveAPISummaryItem) []clientv1.SteveAPISummaryItem {
	fixed := make([]clientv1.SteveAPISummaryItem, 0, len(summaries))
	for _, summary := range summaries {
		counts := summary.Counts
		if summary.Property == "metadata.namespace" {
			counts = make(map[string]clientv1.SteveSummaryWithBreakdown, len(summary.Counts))
			for k, v := range summary.Counts {
				counts[namespaceMap[k]] = v
			}
		}
		fixed = append(fixed, clientv1.SteveAPISummaryItem{Property: summary.Property, Counts: counts})
	}
	return fixed
}

// receivedSummaries drops the JSONResp field shepherd fills in on each summary, which the expected
// summaries don't have.
func receivedSummaries(summaries []clientv1.SteveAPISummaryItem) []clientv1.SteveAPISummaryItem {
	fixed := make([]clientv1.SteveAPISummaryItem, 0, len(summaries))
	for _, summary := range summaries {
		fixed = append(fixed, clientv1.SteveAPISummaryItem{Property: summary.Property, Counts: summary.Counts})
	}
	return fixed
}

// TestList runs the listTests and sqlOnlyListTests cases, each as its user, and writes each response
// as a request/response example under testdata/. Cases run in order: a case with continue or
// revision in its query uses the token or revision the previous case returned.
func (s *SecretsTestSuite) TestList() {
	relativeDateRx := regexp.MustCompile(`^(\d+[smhd])+$`)
	containsNamespaceTag := regexp.MustCompile(`(%2Fsteveapi%5D~)[a-z]+`)
	containsSortNamespace := regexp.MustCompile(`sort=.*metadata.namespace\b`)
	containsSortName := regexp.MustCompile(`sort=.*metadata.name\b`)
	containsReverseOrderSortName := regexp.MustCompile(`sort=.*-metadata.name\b`)
	replacementNamespaceTag := "${1}MYTAG"

	tests := slices.Concat(listTests, sqlOnlyListTests)
	// map labelSelector and fieldSelector params to the VAI equivalents
	// ensure metadata.namespace tests are doing partial matching because
	// the actual namespaces are given an `auto` prefix and a random suffix
	for i, test := range tests {
		query := test.query
		parts := strings.Split(query, "&")
		changed := false
		for j, part := range parts {
			subparts := strings.Split(part, "=")
			switch subparts[0] {
			case "labelSelector":
				parts[j] = fmt.Sprintf("filter=metadata.labels[%s]=%s", subparts[1], subparts[2])
				changed = true
			case "fieldSelector":
				op := "="
				if subparts[1] == "metadata.namespace" {
					// Use the partial-match operator because actual namespaces have a random prefix and suffix
					op = "~"
				}
				parts[j] = fmt.Sprintf("filter=%s%s%s", subparts[1], op, subparts[2])
				changed = true
			case "filter":
				if strings.Contains(part, "metadata.namespace=") {
					// No need to break the filter down into sub-filters because in the test suite we don't
					// have any VALUES that match 'metadata.namespace='
					changed = true
					parts[j] = strings.ReplaceAll(part, "metadata.namespace=", "metadata.namespace~")
				}
			}
		}
		if changed {
			query = strings.Join(parts, "&")
			tests[i].query = query
		}
	}

	csvWriter, csvFile, jsonDir, err := setUpResults()
	s.Require().NoError(err)
	defer func() {
		csvWriter.Flush()
		s.NoError(csvWriter.Error())
		s.NoError(csvFile.Close())
	}()

	for _, test := range tests {
		s.Run(test.description, func() {
			userClient := s.userClients[test.user]

			client, err := userClient.Steve.ProxyDownstream(s.clusterID)
			s.Require().NoError(err)
			var secretClient clientv1.SteveOperations
			secretClient = client.SteveType(stevesecrets.SecretSteveType)
			if test.namespace != "" {
				secretClient = secretClient.(*clientv1.SteveClient).NamespacedSteveClient(namespaceMap[test.namespace])
			}
			query, err := url.ParseQuery(test.query)
			s.Require().NoError(err)
			if _, ok := query["continue"]; ok {
				query["continue"] = []string{s.lastContinueToken}
			}
			key := "projectsornamespaces"
			projectsOrNamespaces, ok := query[key]
			if !ok {
				key += "!"
				projectsOrNamespaces = query[key]
			}
			if len(projectsOrNamespaces) != 0 {
				groups := projectTag.FindAllStringSubmatch(projectsOrNamespaces[0], -1)
				for _, g := range groups {
					name := g[1]
					projectID := projectMap[name].ID
					projectID = strings.Split(projectID, ":")[1]
					projectsOrNamespaces[0] = strings.ReplaceAll(projectsOrNamespaces[0], name, projectID)
				}
				groups = namespaceTag.FindAllStringSubmatch(projectsOrNamespaces[0], -1)
				for _, g := range groups {
					name := g[1]
					projectsOrNamespaces[0] = strings.ReplaceAll(projectsOrNamespaces[0], name, namespaceMap[name])
				}
				query[key] = projectsOrNamespaces
			}
			if _, ok := query["revision"]; ok {
				query["revision"] = []string{s.lastRevision}
			}
			query["filter"] = append(query["filter"], fmt.Sprintf("metadata.labels[%s]~%s", steveAPITestLabel, testID))
			secretList, err := secretClient.List(query)
			s.Require().NoError(err)

			if secretList.Continue != "" {
				s.lastContinueToken = secretList.Continue
			}
			s.lastRevision = secretList.Revision

			switch {
			case test.expectContains:
				s.Subset(receivedKeys(secretList.Data, true), expectedKeys(test.expect, true))
			case test.expectExcludes:
				received := receivedKeys(secretList.Data, true)
				for _, key := range expectedKeys(test.expect, true) {
					s.NotContains(received, key)
				}
			default:
				// the expected objects either all carry a namespace or none do
				withNamespace := false
				if len(test.expect) > 0 {
					_, withNamespace = test.expect[0]["namespace"]
				}
				s.Equal(expectedKeys(test.expect, withNamespace), receivedKeys(secretList.Data, withNamespace))
			}
			if test.expectSummary != nil {
				s.Require().NotNil(secretList.Summary)
				s.Equal(expectedSummaries(test.expectSummary), receivedSummaries(secretList.Summary))
			}

			// Write human-readable request and response examples
			curlURL, err := getCurlURL(client, test.namespace, test.query)
			s.Require().NoError(err)
			if containsSortName.MatchString(test.query) && !containsSortNamespace.MatchString(test.query) {
				// We're getting objects with the same name returned in random order based on namespace,
				// so save them consistently w.r.t their namespace
				multiplier := 1
				if containsReverseOrderSortName.MatchString(test.query) {
					multiplier = -1
				}
				isSorted := slices.IsSortedFunc(secretList.Data, func(x, y clientv1.SteveAPIObject) int {
					return multiplier * strings.Compare(x.Name, y.Name)
				})
				s.True(isSorted, "secretList.Data is not sorted by name")
				secretList.Data = slices.SortedStableFunc(slices.Values(secretList.Data),
					func(x, y clientv1.SteveAPIObject) int {
						nameDiff := strings.Compare(x.Name, y.Name)
						if nameDiff != 0 {
							return multiplier * nameDiff
						}
						return multiplier * strings.Compare(x.Namespace, y.Namespace)
					})
			}
			for _, steveAPIObj := range secretList.Data {
				fields := steveAPIObj.Fields
				if len(fields) > 3 {
					fieldValue := fields[3].(string)
					if fieldValue != "0s" && relativeDateRx.MatchString(fieldValue) {
						fields[3] = "0s"
					}
				}
			}
			pagination := secretList.Pagination
			if pagination != nil {
				pagination.First = containsNamespaceTag.ReplaceAllString(pagination.First, replacementNamespaceTag)
				pagination.Next = containsNamespaceTag.ReplaceAllString(pagination.Next, replacementNamespaceTag)
			}

			jsonResp, err := formatJSON(secretList)
			s.Require().NoError(err)
			jsonFilePath := filepath.Join(jsonDir, getFileName(test.user, test.namespace, test.query))
			s.Require().NoError(writeResp(csvWriter, test.user, curlURL, jsonFilePath, jsonResp))
		})
	}
}
