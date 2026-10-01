package users

import (
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/rancher/shepherd/clients/rancher"
	management "github.com/rancher/shepherd/clients/rancher/generated/management/v3"
	"github.com/rancher/shepherd/extensions/users"
	password "github.com/rancher/shepherd/extensions/users/passwordgenerator"
	"github.com/rancher/shepherd/pkg/clientbase"
	namegen "github.com/rancher/shepherd/pkg/namegenerator"
	"github.com/stretchr/testify/assert"
)

// createUser creates a user with a random username and the given global roles, and returns it with
// its password set so the test can log in as it.
func (s *UsersTestSuite) createUser(client *rancher.Client, globalRoles ...string) *management.User {
	enabled := true
	user, err := users.CreateUserWithRole(client, &management.User{
		Username: namegen.AppendRandomString("testuser-"),
		Password: password.GenerateUserPassword("testpass-"),
		Name:     "testuser",
		Enabled:  &enabled,
	}, globalRoles...)
	s.Require().NoError(err)
	return user
}

// TestUserCantDeleteSelf verifies that a user who can delete other users can't delete itself.
func (s *UsersTestSuite) TestUserCantDeleteSelf() {
	client := s.newSubSession()

	// Act as a throwaway user that can manage users, so a regression deletes only that user and not
	// the admin the suite runs as. The other user has no roles, so it's never more privileged.
	manager := s.createUser(client, "users-manage")
	other := s.createUser(client)
	managerClient, err := client.AsUser(manager)
	s.Require().NoError(err)

	// Deleting another user proves the role is in effect, so the rejection below comes from the
	// self-delete rule and not from missing permissions.
	s.EventuallyWithT(func(c *assert.CollectT) {
		assert.NoError(c, managerClient.Management.User.Delete(other))
	}, 2*time.Minute, 2*time.Second, "users-manage user should be able to delete another user")

	err = managerClient.Management.User.Delete(manager)
	var apiErr *clientbase.APIError
	s.Require().ErrorAs(err, &apiErr)
	s.Equal(http.StatusUnprocessableEntity, apiErr.StatusCode)
	s.ErrorContains(err, "You cannot delete yourself")
}

// TestUserCantDeactivateSelf verifies that a user who can deactivate other users can't set itself
// to enabled=false.
func (s *UsersTestSuite) TestUserCantDeactivateSelf() {
	client := s.newSubSession()

	// Act as a throwaway user that can manage users, so a regression disables only that user and not
	// the admin the suite runs as. The other user has no roles, so it's never more privileged.
	manager := s.createUser(client, "users-manage")
	other := s.createUser(client)
	managerClient, err := client.AsUser(manager)
	s.Require().NoError(err)

	// Deactivating another user proves the role is in effect, so the rejection below comes from the
	// self-deactivate rule and not from missing permissions.
	s.EventuallyWithT(func(c *assert.CollectT) {
		_, err := managerClient.Management.User.Update(other, map[string]any{"enabled": false})
		assert.NoError(c, err)
	}, 2*time.Minute, 2*time.Second, "users-manage user should be able to deactivate another user")

	_, err = managerClient.Management.User.Update(manager, map[string]any{"enabled": false})
	var apiErr *clientbase.APIError
	s.Require().ErrorAs(err, &apiErr)
	s.Equal(http.StatusUnprocessableEntity, apiErr.StatusCode)
	s.ErrorContains(err, "You cannot deactivate yourself")
}

// TestUserCantUseUsernameAsPassword verifies that a user can't be created with its username as its password.
func (s *UsersTestSuite) TestUserCantUseUsernameAsPassword() {
	client := s.newSubSession()

	// "testuser-" plus 5 random characters is 14 characters, over the default minimum of 12, so only
	// the username rule applies.
	username := namegen.AppendRandomString("testuser-")
	enabled := true
	_, err := client.Management.User.Create(&management.User{
		Username: username,
		Password: username,
		Name:     username,
		Enabled:  &enabled,
	})
	var apiErr *clientbase.APIError
	s.Require().ErrorAs(err, &apiErr)
	s.Equal(http.StatusUnprocessableEntity, apiErr.StatusCode)
	s.ErrorContains(err, "Password cannot be the same as the username")
}

// TestPasswordTooShort verifies that a user can be created with a password of exactly the length in
// the password-min-length setting, but not with one character fewer.
func (s *UsersTestSuite) TestPasswordTooShort() {
	client := s.newSubSession()

	minLenSetting, err := client.Management.Setting.ByID("password-min-length")
	s.Require().NoError(err)
	minLen, err := strconv.Atoi(minLenSetting.Value)
	s.Require().NoError(err)

	createWithPassword := func(password string) error {
		username := namegen.AppendRandomString("testuser-")
		enabled := true
		_, err := client.Management.User.Create(&management.User{
			Username: username,
			Password: password,
			Name:     username,
			Enabled:  &enabled,
		})
		return err
	}

	// A password of exactly the minimum length is accepted, so the rejection below is about length alone.
	s.Require().NoError(createWithPassword(namegen.RandStringLower(minLen)))

	err = createWithPassword(namegen.RandStringLower(minLen - 1))
	var apiErr *clientbase.APIError
	s.Require().ErrorAs(err, &apiErr)
	s.Equal(http.StatusUnprocessableEntity, apiErr.StatusCode)
	s.ErrorContains(err, fmt.Sprintf("Password must be at least %d characters", minLen))
}
