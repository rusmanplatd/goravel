package web

import (
	"github.com/goravel/framework/contracts/http"
	"github.com/goravel/framework/facades"

	"goravel/app/helpers"
	"goravel/app/models"
)

type AppPasswordController struct{}

// NewAppPasswordController creates a new app password controller
func NewAppPasswordController() *AppPasswordController {
	return &AppPasswordController{}
}

// Index displays the app passwords management page
func (c *AppPasswordController) Index(ctx http.Context) http.Response {
	user := ctx.Value("user").(*models.User)

	// Get all app passwords for the user
	var appPasswords []models.AppPassword
	err := facades.Orm().Query().
		Where("user_id", user.ID).
		OrderBy("created_at", "desc").
		Get(&appPasswords)

	if err != nil {
		facades.Log().Error("Failed to fetch app passwords: " + err.Error())
		appPasswords = []models.AppPassword{}
	}

	data := map[string]interface{}{
		"title":        "App Passwords",
		"user":         user,
		"appPasswords": appPasswords,
		"totalActive":  c.countActivePasswords(appPasswords),
	}

	return ctx.Response().View().Make("oauth/app-passwords/index.tmpl", data)
}

// Create displays the form to create a new app password
func (c *AppPasswordController) Create(ctx http.Context) http.Response {
	user := ctx.Value("user").(*models.User)

	data := map[string]interface{}{
		"title": "Create App Password",
		"user":  user,
	}

	return ctx.Response().View().Make("oauth/app-passwords/create.tmpl", data)
}

// Store creates a new app password
func (c *AppPasswordController) Store(ctx http.Context) http.Response {
	user := ctx.Value("user").(*models.User)

	// Get form data
	name := ctx.Request().Input("name")
	if name == "" {
		return ctx.Response().Json(400, map[string]interface{}{
			"success": false,
			"message": "App password name is required",
		})
	}

	// Create new app password
	appPassword := &models.AppPassword{
		ID:     helpers.GenerateULID(),
		UserID: user.ID,
		Name:   name,
	}

	// Generate the password
	plainPassword, err := appPassword.GeneratePassword()
	if err != nil {
		return ctx.Response().Json(500, map[string]interface{}{
			"success": false,
			"message": "Failed to generate app password",
		})
	}

	// Save to database
	err = facades.Orm().Query().Create(appPassword)
	if err != nil {
		return ctx.Response().Json(500, map[string]interface{}{
			"success": false,
			"message": "Failed to create app password",
		})
	}

	// Return the password (this is the only time it will be shown in plain text)
	return ctx.Response().Json(200, map[string]interface{}{
		"success":  true,
		"message":  "App password created successfully",
		"password": plainPassword,
		"id":       appPassword.ID,
		"name":     appPassword.Name,
	})
}

// Revoke revokes an app password
func (c *AppPasswordController) Revoke(ctx http.Context) http.Response {
	user := ctx.Value("user").(*models.User)
	passwordID := ctx.Request().Route("id")

	// Find the app password
	var appPassword models.AppPassword
	err := facades.Orm().Query().
		Where("id", passwordID).
		Where("user_id", user.ID).
		First(&appPassword)

	if err != nil {
		return ctx.Response().Json(404, map[string]interface{}{
			"success": false,
			"message": "App password not found",
		})
	}

	// Revoke the password
	appPassword.Revoke()
	err = facades.Orm().Query().Save(&appPassword)
	if err != nil {
		return ctx.Response().Json(500, map[string]interface{}{
			"success": false,
			"message": "Failed to revoke app password",
		})
	}

	return ctx.Response().Json(200, map[string]interface{}{
		"success": true,
		"message": "App password revoked successfully",
	})
}

// Delete permanently deletes an app password
func (c *AppPasswordController) Delete(ctx http.Context) http.Response {
	user := ctx.Value("user").(*models.User)
	passwordID := ctx.Request().Route("id")

	// Find and delete the app password
	_, err := facades.Orm().Query().
		Where("id", passwordID).
		Where("user_id", user.ID).
		Delete(&models.AppPassword{})

	if err != nil {
		return ctx.Response().Json(500, map[string]interface{}{
			"success": false,
			"message": "Failed to delete app password",
		})
	}

	return ctx.Response().Json(200, map[string]interface{}{
		"success": true,
		"message": "App password deleted successfully",
	})
}

// countActivePasswords counts the number of active (non-revoked, non-expired) passwords
func (c *AppPasswordController) countActivePasswords(passwords []models.AppPassword) int {
	count := 0
	for _, password := range passwords {
		if password.IsActive() {
			count++
		}
	}
	return count
}
