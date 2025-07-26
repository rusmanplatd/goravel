package web

import (
	"github.com/goravel/framework/contracts/http"
)

type NotificationController struct {
}

func NewNotificationController() *NotificationController {
	return &NotificationController{}
}

// Index displays the notifications management page
func (c *NotificationController) Index(ctx http.Context) http.Response {
	// Get user from context (set by middleware)
	user := ctx.Value("user")
	if user == nil {
		return ctx.Response().Redirect(302, "/login")
	}

	return ctx.Response().View().Make("notifications/index.tmpl", map[string]interface{}{
		"title": "Notifications",
		"user":  user,
	})
}
