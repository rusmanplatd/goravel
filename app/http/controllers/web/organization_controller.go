package web

import (
	"github.com/goravel/framework/contracts/http"
)

type OrganizationController struct {
}

func NewOrganizationController() *OrganizationController {
	return &OrganizationController{}
}

// Index displays the organizations management page
func (c *OrganizationController) Index(ctx http.Context) http.Response {
	// Get user from context (set by middleware)
	user := ctx.Value("user")
	if user == nil {
		return ctx.Response().Redirect(302, "/login")
	}

	return ctx.Response().View().Make("organizations/index.tmpl", map[string]interface{}{
		"title": "Organizations",
		"user":  user,
	})
}
