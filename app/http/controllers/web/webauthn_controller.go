package web

import (
	"github.com/goravel/framework/contracts/http"
	"github.com/goravel/framework/facades"

	"goravel/app/models"
	"goravel/app/services"
)

type WebAuthnController struct {
	authService         *services.AuthService
	webauthnService     *services.WebAuthnService
	multiAccountService *services.MultiAccountService
}

func NewWebAuthnController() *WebAuthnController {
	return &WebAuthnController{
		authService:         services.NewAuthService(),
		webauthnService:     services.NewWebAuthnService(),
		multiAccountService: services.NewMultiAccountService(),
	}
}

// getCurrentUser gets the current authenticated user from context
func (c *WebAuthnController) getCurrentUser(ctx http.Context) *models.User {
	// Get user from context (set by WebAuth middleware)
	user := ctx.Value("user")
	if user == nil {
		return nil
	}

	// Type assertion to ensure it's a User pointer
	if userPtr, ok := user.(*models.User); ok {
		return userPtr
	}

	return nil
}

// ShowSetup displays the WebAuthn setup page
func (c *WebAuthnController) ShowSetup(ctx http.Context) http.Response {
	user := c.getCurrentUser(ctx)
	if user == nil {
		return ctx.Response().Redirect(302, "/login")
	}

	// Get existing credentials
	credentials, err := c.webauthnService.GetUserCredentials(user)
	if err != nil {
		credentials = []models.WebauthnCredential{}
	}

	return ctx.Response().View().Make("security/webauthn/setup.tmpl", map[string]interface{}{
		"title":       "Setup Passwordless Authentication",
		"user":        user,
		"credentials": credentials,
	})
}

// ShowManage displays the WebAuthn management page
func (c *WebAuthnController) ShowManage(ctx http.Context) http.Response {
	user := c.getCurrentUser(ctx)
	if user == nil {
		return ctx.Response().Redirect(302, "/login")
	}

	// Get existing credentials
	credentials, err := c.webauthnService.GetUserCredentials(user)
	if err != nil {
		credentials = []models.WebauthnCredential{}
	}

	return ctx.Response().View().Make("security/webauthn/manage.tmpl", map[string]interface{}{
		"title":       "Manage Security Keys",
		"user":        user,
		"credentials": credentials,
	})
}

// BeginRegistration starts the WebAuthn registration process
func (c *WebAuthnController) BeginRegistration(ctx http.Context) http.Response {
	user := c.getCurrentUser(ctx)
	if user == nil {
		return ctx.Response().Json(401, map[string]interface{}{
			"error": "Unauthorized",
		})
	}

	registrationData, err := c.webauthnService.BeginRegistration(user)
	if err != nil {
		return ctx.Response().Json(500, map[string]interface{}{
			"error": "Failed to begin registration",
		})
	}

	return ctx.Response().Json(200, registrationData)
}

// FinishRegistration completes the WebAuthn registration process
func (c *WebAuthnController) FinishRegistration(ctx http.Context) http.Response {
	user := c.getCurrentUser(ctx)
	if user == nil {
		return ctx.Response().Json(401, map[string]interface{}{
			"error": "Unauthorized",
		})
	}

	var request struct {
		Name     string                 `json:"name"`
		Response map[string]interface{} `json:"response"`
	}
	if err := ctx.Request().Bind(&request); err != nil {
		return ctx.Response().Json(400, map[string]interface{}{
			"error": "Invalid request data",
		})
	}

	// Use default name if not provided
	credentialName := request.Name
	if credentialName == "" {
		credentialName = "Security Key"
	}

	credential, err := c.webauthnService.FinishRegistration(user, credentialName, request.Response)
	if err != nil {
		return ctx.Response().Json(400, map[string]interface{}{
			"error": err.Error(),
		})
	}

	return ctx.Response().Json(200, map[string]interface{}{
		"success":    true,
		"credential": credential,
		"message":    "Security key registered successfully",
	})
}

// BeginAuthentication starts the WebAuthn authentication process
func (c *WebAuthnController) BeginAuthentication(ctx http.Context) http.Response {
	// This can be called without authentication for login flow
	email := ctx.Request().Input("email", "")
	if email == "" {
		return ctx.Response().Json(400, map[string]interface{}{
			"error": "Email is required",
		})
	}

	var user models.User
	err := facades.Orm().Query().Where("email", email).First(&user)
	if err != nil {
		return ctx.Response().Json(404, map[string]interface{}{
			"error": "User not found",
		})
	}

	authData, err := c.webauthnService.BeginLogin(&user)
	if err != nil {
		return ctx.Response().Json(400, map[string]interface{}{
			"error": err.Error(),
		})
	}

	return ctx.Response().Json(200, authData)
}

// FinishAuthentication completes the WebAuthn authentication process
func (c *WebAuthnController) FinishAuthentication(ctx http.Context) http.Response {
	var response map[string]interface{}
	if err := ctx.Request().Bind(&response); err != nil {
		return ctx.Response().Json(400, map[string]interface{}{
			"error": "Invalid request data",
		})
	}

	// Get user from the response (should include user identifier)
	email := response["email"].(string)
	var user models.User
	err := facades.Orm().Query().Where("email", email).First(&user)
	if err != nil {
		return ctx.Response().Json(404, map[string]interface{}{
			"error": "User not found",
		})
	}

	err = c.webauthnService.FinishLogin(&user, response)
	if err != nil {
		return ctx.Response().Json(400, map[string]interface{}{
			"error": err.Error(),
		})
	}

	// Add account to multi-account session
	err = c.multiAccountService.AddAccount(ctx, &user, "webauthn")
	if err != nil {
		facades.Log().Error("Failed to add account to multi-account session", map[string]interface{}{
			"error":   err.Error(),
			"user_id": user.ID,
		})
	}

	// Multi-account session is already set by AddAccount above

	// Check for intended URL and redirect appropriately
	intendedURL := ctx.Request().Session().Get("intended_url", "/dashboard")
	ctx.Request().Session().Remove("intended_url")

	return ctx.Response().Json(200, map[string]interface{}{
		"success":  true,
		"message":  "Authentication successful",
		"redirect": intendedURL.(string),
	})
}

// DeleteCredential deletes a WebAuthn credential
func (c *WebAuthnController) DeleteCredential(ctx http.Context) http.Response {
	user := c.getCurrentUser(ctx)
	if user == nil {
		return ctx.Response().Redirect(302, "/login")
	}

	credentialID := ctx.Request().Route("id")
	if credentialID == "" {
		return ctx.Response().Redirect(302, "/security/webauthn/manage?error=Invalid credential ID")
	}

	err := c.webauthnService.DeleteCredential(user, credentialID)
	if err != nil {
		return ctx.Response().Redirect(302, "/security/webauthn/manage?error=Failed to delete credential")
	}

	return ctx.Response().Redirect(302, "/security/webauthn/manage?success=Security key deleted successfully")
}

// ShowCredentials displays credentials as JSON (for AJAX requests)
func (c *WebAuthnController) ShowCredentials(ctx http.Context) http.Response {
	user := c.getCurrentUser(ctx)
	if user == nil {
		return ctx.Response().Json(401, map[string]interface{}{
			"error": "Unauthorized",
		})
	}

	credentials, err := c.webauthnService.GetUserCredentials(user)
	if err != nil {
		return ctx.Response().Json(500, map[string]interface{}{
			"error": "Failed to fetch credentials",
		})
	}

	return ctx.Response().Json(200, map[string]interface{}{
		"credentials": credentials,
	})
}

// UpdateCredentialName updates the name of a WebAuthn credential
func (c *WebAuthnController) UpdateCredentialName(ctx http.Context) http.Response {
	user := c.getCurrentUser(ctx)
	if user == nil {
		return ctx.Response().Json(401, map[string]interface{}{
			"error": "Unauthorized",
		})
	}

	credentialID := ctx.Request().Route("id")
	if credentialID == "" {
		return ctx.Response().Json(400, map[string]interface{}{
			"error": "Invalid credential ID",
		})
	}

	var req struct {
		Name string `form:"name" json:"name"`
	}

	if err := ctx.Request().Bind(&req); err != nil {
		return ctx.Response().Json(400, map[string]interface{}{
			"error": "Invalid request data",
		})
	}

	// Find and update credential
	var credential models.WebauthnCredential
	err := facades.Orm().Query().Where("user_id", user.ID).Where("credential_id", credentialID).First(&credential)
	if err != nil {
		return ctx.Response().Json(404, map[string]interface{}{
			"error": "Credential not found",
		})
	}

	credential.Name = req.Name
	err = facades.Orm().Query().Save(&credential)
	if err != nil {
		return ctx.Response().Json(500, map[string]interface{}{
			"error": "Failed to update credential",
		})
	}

	return ctx.Response().Json(200, map[string]interface{}{
		"success": true,
		"message": "Credential name updated successfully",
	})
}
