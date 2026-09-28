package rbac

import (
	"errors"
	"net/http"

	management "github.com/rancher/shepherd/clients/rancher/generated/management/v3"
	"github.com/rancher/shepherd/pkg/clientbase"
	namegen "github.com/rancher/shepherd/pkg/namegenerator"
)

// TestGRBCannotUpdateGlobalRoleID tests that the globalRoleId field on a
// GlobalRoleBinding cannot be changed after creation.
func (p *RBACTestSuite) TestGRBCannotUpdateGlobalRoleID() {
	client := p.newSubSession()

	user := p.createUser(client, "grb-user", "user")

	grb, err := client.Management.GlobalRoleBinding.Create(&management.GlobalRoleBinding{
		Name:         namegen.AppendRandomString("grb-"),
		UserID:       user.ID,
		GlobalRoleID: "nodedrivers-manage",
	})
	p.Require().NoError(err)

	// Attempt to change globalRoleId; it should remain unchanged.
	updated, err := client.Management.GlobalRoleBinding.Update(grb, map[string]any{
		"globalRoleId": "settings-manage",
	})
	p.Require().NoError(err)
	p.Require().Equal("nodedrivers-manage", updated.GlobalRoleID)
}

// TestGRBGlobalRoleMustExist tests that creating a GlobalRoleBinding referencing
// a non-existent global role returns a 404.
func (p *RBACTestSuite) TestGRBGlobalRoleMustExist() {
	client := p.newSubSession()

	user := p.createUser(client, "grb-user", "user")

	_, err := client.Management.GlobalRoleBinding.Create(&management.GlobalRoleBinding{
		Name:         namegen.AppendRandomString("grb-"),
		GlobalRoleID: "somefakerole",
		UserID:       user.ID,
	})
	var apiErr *clientbase.APIError
	p.Require().True(errors.As(err, &apiErr), "expected APIError, got: %v", err)
	p.Require().Equal(http.StatusNotFound, apiErr.StatusCode)
}

// TestGRBCannotUpdateSubject tests that userId and groupPrincipalId fields on a
// GlobalRoleBinding cannot be changed after creation.
func (p *RBACTestSuite) TestGRBCannotUpdateSubject() {
	client := p.newSubSession()

	user1 := p.createUser(client, "grb-user1", "user")
	user2 := p.createUser(client, "grb-user2", "user")

	grb, err := client.Management.GlobalRoleBinding.Create(&management.GlobalRoleBinding{
		Name:         namegen.AppendRandomString("grb-"),
		UserID:       user1.ID,
		GlobalRoleID: "nodedrivers-manage",
	})
	p.Require().NoError(err)

	// Attempt to change userId; it should remain unchanged.
	updated, err := client.Management.GlobalRoleBinding.Update(grb, map[string]any{
		"userId": user2.ID,
	})
	p.Require().NoError(err)
	p.Require().Equal(user1.ID, updated.UserID)

	// Attempt to set groupPrincipalId; userId should remain, groupPrincipalId should stay empty.
	updated, err = client.Management.GlobalRoleBinding.Update(updated, map[string]any{
		"groupPrincipalId": "groupa",
	})
	p.Require().NoError(err)
	p.Require().Equal(user1.ID, updated.UserID)
	p.Require().Empty(updated.GroupPrincipalID)
}

// TestGRBTargetsUserOrGroup tests that a GlobalRoleBinding must exclusively target
// a userId or groupPrincipalId, not both and not neither.
func (p *RBACTestSuite) TestGRBTargetsUserOrGroup() {
	client := p.newSubSession()

	user := p.createUser(client, "grb-user", "user")

	// Cannot specify both userId and groupPrincipalId (422).
	_, err := client.Management.GlobalRoleBinding.Create(&management.GlobalRoleBinding{
		UserID:           user.ID,
		GroupPrincipalID: "asd",
		GlobalRoleID:     "admin",
	})
	var apiErr *clientbase.APIError
	p.Require().True(errors.As(err, &apiErr), "expected APIError, got: %v", err)
	p.Require().Equal(http.StatusUnprocessableEntity, apiErr.StatusCode)

	// Cannot omit both userId and groupPrincipalId (422).
	_, err = client.Management.GlobalRoleBinding.Create(&management.GlobalRoleBinding{
		GlobalRoleID: "admin",
	})
	p.Require().True(errors.As(err, &apiErr), "expected APIError, got: %v", err)
	p.Require().Equal(http.StatusUnprocessableEntity, apiErr.StatusCode)
}
