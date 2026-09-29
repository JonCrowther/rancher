package settings

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	management "github.com/rancher/shepherd/clients/rancher/generated/management/v3"
	"github.com/rancher/shepherd/extensions/users"
	password "github.com/rancher/shepherd/extensions/users/passwordgenerator"
	"github.com/rancher/shepherd/pkg/clientbase"
	namegen "github.com/rancher/shepherd/pkg/namegenerator"
	"k8s.io/client-go/rest"
)

// TestCreateReadOnly verifies that creating the readOnly "cacerts" setting is
// rejected with 405 Method Not Allowed.
func (s *SettingsTestSuite) TestCreateReadOnly() {
	client := s.newSubSession()

	_, err := client.Management.Setting.Create(&management.Setting{
		Name:  "cacerts",
		Value: "a",
	})
	s.Require().Error(err)
	var apiErr *clientbase.APIError
	s.Require().True(errors.As(err, &apiErr))
	s.Equal(http.StatusMethodNotAllowed, apiErr.StatusCode)
	s.Contains(apiErr.Msg, "readOnly")
}

// TestUpdateReadOnly verifies that updating the readOnly "cacerts" setting is
// rejected with 405 Method Not Allowed.
func (s *SettingsTestSuite) TestUpdateReadOnly() {
	client := s.newSubSession()

	setting, err := client.Management.Setting.ByID("cacerts")
	s.Require().NoError(err)

	// Rancher rejects any update to a readOnly setting, whatever the value. Sending the current
	// value means a regression that lets the update through can't change the CA certs of the
	// shared Rancher.
	_, err = client.Management.Setting.Update(setting, &management.Setting{Value: setting.Value})
	s.Require().Error(err)
	var apiErr *clientbase.APIError
	s.Require().True(errors.As(err, &apiErr))
	s.Equal(http.StatusMethodNotAllowed, apiErr.StatusCode)
	s.Contains(apiErr.Msg, "readOnly")
}

// TestGetReadOnly verifies that the readOnly "cacerts" setting can be retrieved,
// and is returned without an "update" link even for an admin.
func (s *SettingsTestSuite) TestGetReadOnly() {
	client := s.newSubSession()

	setting, err := client.Management.Setting.ByID("cacerts")
	s.Require().NoError(err)
	s.Equal("cacerts", setting.ID)
	s.NotContains(setting.Links, "update", "readOnly setting should not have an update link")
}

// TestDeleteReadOnly verifies that deleting the readOnly "cacerts" setting is
// rejected with 405 Method Not Allowed.
func (s *SettingsTestSuite) TestDeleteReadOnly() {
	client := s.newSubSession()

	setting, err := client.Management.Setting.ByID("cacerts")
	s.Require().NoError(err)

	err = client.Management.Setting.Delete(setting)
	s.Require().Error(err)
	var apiErr *clientbase.APIError
	s.Require().True(errors.As(err, &apiErr))
	s.Equal(http.StatusMethodNotAllowed, apiErr.StatusCode)
	s.Contains(apiErr.Msg, "readOnly")
}

// TestCreate verifies that a new setting can be created with the expected value.
func (s *SettingsTestSuite) TestCreate() {
	client := s.newSubSession()

	setting, err := client.Management.Setting.Create(&management.Setting{
		Name:  namegen.AppendRandomString("samplesetting-"),
		Value: "a",
	})
	s.Require().NoError(err)
	s.Equal("a", setting.Value)
}

// TestCreateExisting verifies that creating a setting whose name is already
// taken returns 409 Conflict with code AlreadyExists.
func (s *SettingsTestSuite) TestCreateExisting() {
	client := s.newSubSession()

	name := namegen.AppendRandomString("samplesetting-")
	_, err := client.Management.Setting.Create(&management.Setting{
		Name:  name,
		Value: "a",
	})
	s.Require().NoError(err)

	_, err = client.Management.Setting.Create(&management.Setting{
		Name:  name,
		Value: "a",
	})
	s.Require().Error(err)
	var apiErr *clientbase.APIError
	s.Require().True(errors.As(err, &apiErr))
	s.Equal(http.StatusConflict, apiErr.StatusCode)
	s.Contains(apiErr.Msg, "AlreadyExists")
}

// TestUpdate verifies that an existing setting can be updated to a new value.
func (s *SettingsTestSuite) TestUpdate() {
	client := s.newSubSession()

	setting, err := client.Management.Setting.Create(&management.Setting{
		Name:  namegen.AppendRandomString("samplesetting-"),
		Value: "a",
	})
	s.Require().NoError(err)

	updated, err := client.Management.Setting.Update(setting, &management.Setting{Value: "b"})
	s.Require().NoError(err)
	s.Equal("b", updated.Value)
}

// TestUpdateNonExisting verifies that attempting to update a setting that does
// not exist returns 404 Not Found.
func (s *SettingsTestSuite) TestUpdateNonExisting() {
	client := s.newSubSession()

	// The Norman client can only update a resource it has fetched, so send the PUT directly.
	httpClient, err := rest.HTTPClientFor(client.WranglerContext.RESTConfig)
	s.Require().NoError(err)
	putSetting := func(id string) int {
		body, err := json.Marshal(map[string]any{"value": "b"})
		s.Require().NoError(err)
		req, err := http.NewRequest(http.MethodPut,
			fmt.Sprintf("https://%s/v3/settings/%s", client.WranglerContext.RESTConfig.Host, id),
			bytes.NewReader(body))
		s.Require().NoError(err)
		req.Header.Set("Content-Type", "application/json")
		resp, err := httpClient.Do(req)
		s.Require().NoError(err)
		defer resp.Body.Close()
		return resp.StatusCode
	}

	// The same request against an existing setting succeeds, so the 404 below comes from the
	// missing setting and not from a bad URL or credentials.
	existing, err := client.Management.Setting.Create(&management.Setting{
		Name:  namegen.AppendRandomString("samplesetting-"),
		Value: "a",
	})
	s.Require().NoError(err)
	s.Require().Equal(http.StatusOK, putSetting(existing.ID))

	s.Equal(http.StatusNotFound, putSetting(namegen.AppendRandomString("nonexistent-")))
}

// TestUpdateLink verifies that the admin user sees the "update" action link on
// a setting, while a standard user does not.
func (s *SettingsTestSuite) TestUpdateLink() {
	client := s.newSubSession()

	setting, err := client.Management.Setting.Create(&management.Setting{
		Name:  namegen.AppendRandomString("samplesetting-"),
		Value: "a",
	})
	s.Require().NoError(err)

	// Admin should see the update link.
	setting, err = client.Management.Setting.ByID(setting.ID)
	s.Require().NoError(err)
	_, hasUpdate := setting.Links["update"]
	s.True(hasUpdate, "admin should see update link on setting")

	// Create a standard user and verify they do not see the update link.
	enabled := true
	pw := password.GenerateUserPassword("testpass-")
	standardUser, err := users.CreateUserWithRole(client, &management.User{
		Username: namegen.AppendRandomString("user-"),
		Password: pw,
		Name:     "testuser",
		Enabled:  &enabled,
	}, "user")
	s.Require().NoError(err)
	standardUser.Password = pw

	userClient, err := client.AsUser(standardUser)
	s.Require().NoError(err)

	userSetting, err := userClient.Management.Setting.ByID(setting.ID)
	s.Require().NoError(err)
	_, hasUpdate = userSetting.Links["update"]
	s.False(hasUpdate, "standard user should not see update link on setting")
}
