package rbac

import (
	"errors"
	"net/http"
	"time"

	management "github.com/rancher/shepherd/clients/rancher/generated/management/v3"
	"github.com/rancher/shepherd/pkg/clientbase"
	namegen "github.com/rancher/shepherd/pkg/namegenerator"
	"github.com/stretchr/testify/assert"
)

// assertKontainerDriverCount polls until the client's visible kontainer driver count matches expected,
// since GlobalRoleBinding permissions are reconciled asynchronously by RBAC controllers.
func (p *RBACTestSuite) assertKontainerDriverCount(c *rancher.Client, expected int) {
	var kds *management.KontainerDriverCollection
	p.Require().Eventually(func() bool {
		var err error
		kds, err = c.Management.KontainerDriver.List(nil)
		return err == nil && len(kds.Data) == expected
	}, 30*time.Second, time.Second, "timed out waiting for kontainer driver visibility to reach %d item(s)", expected)
	p.Require().Len(kds.Data, expected)
}

// TestUserVsUserBaseGlobalRoleVisibility tests that users with the "user" and "user-base" global
// roles can only see themselves, and that only "user" can see role templates.
func (p *RBACTestSuite) TestUserVsUserBaseGlobalRoleVisibility() {
	client := p.newSubSession()

	// Create user1 with the standard "user" global role.
	user1 := p.createUser(client, "testuser1", "user")

	// Create user2 with the "user-base" global role.
	user2 := p.createUser(client, "testuser2", "user-base")

	// Create 2 more users (just to pad the user count).
	p.createUser(client, "testuser", "user")
	p.createUser(client, "testuser", "user")

	// Admin should see at least 5 users.
	adminUsers, err := client.Management.User.List(nil)
	p.Require().NoError(err)
	p.Require().GreaterOrEqual(len(adminUsers.Data), 5)

	user1Client, err := client.AsUser(user1)
	p.Require().NoError(err)

	user2Client, err := client.AsUser(user2)
	p.Require().NoError(err)

	// user1 (standard "user" role) should only see themselves.
	user1Users, err := user1Client.Management.User.List(nil)
	p.Require().NoError(err)
	p.Require().Len(user1Users.Data, 1, "user should only see themselves")

	// user1 can see all roleTemplates once the "user" role's RBAC permissions propagate.
	var user1RTs *management.RoleTemplateCollection
	p.Require().Eventually(func() bool {
		user1RTs, err = user1Client.Management.RoleTemplate.List(nil)
		return err == nil && len(user1RTs.Data) > 0
	}, 30*time.Second, time.Second, "timed out waiting for user to see roleTemplates")
	p.Require().NotEmpty(user1RTs.Data, "user should be able to see all roleTemplates")

	// user2 (user-base role) should only see themselves.
	user2Users, err := user2Client.Management.User.List(nil)
	p.Require().NoError(err)
	p.Require().Len(user2Users.Data, 1, "user should only see themselves")

	// user2 should not see any role templates.
	user2RTs, err := user2Client.Management.RoleTemplate.List(nil)
	p.Require().NoError(err)
	p.Require().Empty(user2RTs.Data, "user2 does not have permission to view roleTemplates")
}

// TestKontainerDriverVisibilityByGlobalRole tests which global roles grant visibility of kontainer
// drivers.
func (p *RBACTestSuite) TestKontainerDriverVisibilityByGlobalRole() {
	client := p.newSubSession()

	// "user", "clusters-create" and "kontainerdrivers-manage" can see kontainer drivers;
	// "settings-manage" cannot. A count of 3 assumes the kontainer drivers of a default install.
	visibility := []struct {
		role     string
		expected int
	}{
		{role: "user", expected: 3},
		{role: "clusters-create", expected: 3},
		{role: "kontainerdrivers-manage", expected: 3},
		{role: "settings-manage", expected: 0},
	}

	for _, v := range visibility {
		u := p.createUser(client, "kd-user", v.role)
		userClient, err := client.AsUser(u)
		p.Require().NoError(err)

	// "clusters-create" role can see kontainer drivers.
	p.assertKontainerDriverCount(createUserWithRole("clusters-create"), 3)

	// "kontainerdrivers-manage" role can see kontainer drivers.
	p.assertKontainerDriverCount(createUserWithRole("kontainerdrivers-manage"), 3)

	// "settings-manage" role cannot see kontainer drivers.
	p.assertKontainerDriverCount(createUserWithRole("settings-manage"), 0)
}

// TestOnlyAdminCanCRUDGlobalRoles tests that only admins can create, get, update,
// and delete non-builtin global roles.
func (p *RBACTestSuite) TestOnlyAdminCanCRUDGlobalRoles() {
	client := p.newSubSession()

	user := p.createUser(client, "gr-user", "user")
	userClient, err := client.AsUser(user)
	p.Require().NoError(err)

	// Admin can create a global role.
	gr, err := client.Management.GlobalRole.Create(&management.GlobalRole{
		Name: namegen.AppendRandomString("gr-"),
	})
	p.Require().NoError(err)

	// Admin can update a global role.
	_, err = client.Management.GlobalRole.Update(gr, map[string]any{
		"annotations": map[string]string{"test": "asdf"},
	})
	p.Require().NoError(err)

	// Admin can list global roles.
	grList, err := client.Management.GlobalRole.List(nil)
	p.Require().NoError(err)
	p.Require().NotEmpty(grList.Data)

	// Admin can delete a global role.
	err = client.Management.GlobalRole.Delete(gr)
	p.Require().NoError(err)

	// Standard user cannot create a global role (403).
	_, err = userClient.Management.GlobalRole.Create(&management.GlobalRole{
		Name: namegen.AppendRandomString("gr-"),
	})
	var apiErr *clientbase.APIError
	p.Require().True(errors.As(err, &apiErr), "expected APIError, got: %v", err)
	p.Require().Equal(http.StatusForbidden, apiErr.StatusCode)

	// Admin creates another global role for subsequent user tests.
	gr2, err := client.Management.GlobalRole.Create(&management.GlobalRole{
		Name: namegen.AppendRandomString("gr-"),
	})
	p.Require().NoError(err)

	// Standard user cannot update the global role (403).
	_, err = userClient.Management.GlobalRole.Update(gr2, map[string]any{
		"annotations": map[string]string{"test2": "jkl"},
	})
	p.Require().True(errors.As(err, &apiErr), "expected APIError, got: %v", err)
	p.Require().Equal(http.StatusForbidden, apiErr.StatusCode)

	// Standard user sees no global roles when listing.
	userGRList, err := userClient.Management.GlobalRole.List(nil)
	p.Require().NoError(err)
	p.Require().Empty(userGRList.Data)

	// Standard user cannot delete the global role (403).
	err = userClient.Management.GlobalRole.Delete(gr2)
	p.Require().True(errors.As(err, &apiErr), "expected APIError, got: %v", err)
	p.Require().Equal(http.StatusForbidden, apiErr.StatusCode)
}

// TestBuiltinGlobalRoleOnlyNewUserDefaultEditable tests that admins can only edit
// a builtin global role's newUserDefault field.
func (p *RBACTestSuite) TestBuiltinGlobalRoleOnlyNewUserDefaultEditable() {
	client := p.newSubSession()

	gr, err := client.Management.GlobalRole.ByID("admin")
	p.Require().NoError(err)
	p.Require().True(gr.Builtin)
	_, hasRemove := gr.Links["remove"]
	p.Require().False(hasRemove, "builtin global role should not have a remove link")
	p.Require().False(gr.NewUserDefault)

	// Attempt to update multiple fields; only newUserDefault should change.
	updated, err := client.Management.GlobalRole.Update(gr, map[string]any{
		"name":           "gr-test",
		"description":    "asdf",
		"rules":          nil,
		"newUserDefault": true,
		"builtin":        true,
	})
	p.Require().NoError(err)

	// Revert newUserDefault after test.
	p.T().Cleanup(func() {
		_, _ = client.Management.GlobalRole.Update(updated, map[string]any{
			"newUserDefault": false,
		})
	})

	// Name should remain unchanged.
	p.Require().Equal(gr.Name, updated.Name)
	// Rules should not have been wiped out.
	p.Require().NotEmpty(updated.Rules)
	// Builtin should still be true.
	p.Require().True(updated.Builtin)
	// newUserDefault is the only field that should have changed.
	p.Require().True(updated.NewUserDefault)
}

// TestAdminCannotDeleteBuiltinGlobalRole tests that admins can edit builtin global
// roles but cannot delete them.
func (p *RBACTestSuite) TestAdminCannotDeleteBuiltinGlobalRole() {
	client := p.newSubSession()

	// A low-privilege builtin role, so a failed revert doesn't hand every new user admin.
	gr, err := client.Management.GlobalRole.ByID("kontainerdrivers-manage")
	p.Require().NoError(err)
	p.Require().True(gr.Builtin)
	_, hasRemove := gr.Links["remove"]
	p.Require().False(hasRemove, "builtin global role should not have a remove link")
	p.Require().False(gr.NewUserDefault)

	// Attempt to update multiple fields; only newUserDefault should change.
	updated, err := client.Management.GlobalRole.Update(gr, map[string]any{
		"name":           "gr-test",
		"description":    "asdf",
		"rules":          nil,
		"newUserDefault": true,
		"builtin":        true,
	})
	p.Require().NoError(err)

	// Revert newUserDefault after test. The suite's T is swapped back to the parent before
	// cleanups run, so report through the captured test T.
	t := p.T()
	t.Cleanup(func() {
		_, err := client.Management.GlobalRole.Update(updated, map[string]any{
			"newUserDefault": false,
		})
		assert.NoError(t, err, "failed to revert newUserDefault on global role %s", updated.ID)
	})

	// Name should remain unchanged.
	p.Require().Equal(gr.Name, updated.Name)
	// Rules should not have been wiped out.
	p.Require().NotEmpty(updated.Rules)
	// Builtin should still be true.
	p.Require().True(updated.Builtin)
	// newUserDefault is the only field that should have changed.
	p.Require().True(updated.NewUserDefault)
}

// TestAdminCannotDeleteBuiltinGlobalRole tests that admins can edit builtin global
// roles but cannot delete them.
func (p *RBACTestSuite) TestAdminCannotDeleteBuiltinGlobalRole() {
	client := p.newSubSession()

	// A low-privilege builtin role, so a regression that allows the delete doesn't remove admin.
	gr, err := client.Management.GlobalRole.ByID("kontainerdrivers-manage")
	p.Require().NoError(err)
	p.Require().True(gr.Builtin)
	_, hasRemove := gr.Links["remove"]
	p.Require().False(hasRemove, "builtin global role should not have a remove link")

	// Admin creates a global role with builtin=true; it should be ignored.
	gr2, err := client.Management.GlobalRole.Create(&management.GlobalRole{
		Name:    namegen.AppendRandomString("gr-"),
		Builtin: true,
	})
	p.Require().NoError(err)
	// Builtin cannot be set by admin on creation.
	p.Require().False(gr2.Builtin)

	// Admin can update the builtin role (no error).
	_, err = client.Management.GlobalRole.Update(gr, map[string]any{})
	p.Require().NoError(err)

	// Admin cannot delete the builtin role (403).
	err = client.Management.GlobalRole.Delete(gr)
	var apiErr *clientbase.APIError
	p.Require().True(errors.As(err, &apiErr), "expected APIError, got: %v", err)
	p.Require().Equal(http.StatusForbidden, apiErr.StatusCode)
	p.Require().Contains(apiErr.Body, "cannot delete builtin global roles")
}
