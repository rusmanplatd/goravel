package v1

import (
	"strings"

	"goravel/app/http/responses"
	"goravel/app/services"

	"github.com/goravel/framework/contracts/http"
	"github.com/goravel/framework/facades"
)

type OIDCClientController struct {
	oidcClientService *services.OIDCClientService
}

// NewOIDCClientController creates a new OIDC client controller
func NewOIDCClientController() *OIDCClientController {
	return &OIDCClientController{
		oidcClientService: services.NewOIDCClientService(),
	}
}

// RegisterClient handles OIDC client registration
// @Summary Register OIDC client
// @Description Registers a new OIDC client
// @Tags OIDC Client
// @Accept json
// @Produce json
// @Param client body services.OIDCClientRegistrationRequest true "Client registration request"
// @Success 201 {object} services.OIDCClientRegistrationResponse
// @Failure 400 {object} responses.APIResponse
// @Failure 500 {object} responses.APIResponse
// @Router /oidc/register [post]
func (c *OIDCClientController) RegisterClient(ctx http.Context) http.Response {
	var req services.OIDCClientRegistrationRequest
	if err := ctx.Request().Bind(&req); err != nil {
		return ctx.Response().Status(400).Json(responses.APIResponse{
			Status:  "error",
			Message: "Invalid request format",
			Error:   err.Error(),
		})
	}

	// Register the client
	response, err := c.oidcClientService.RegisterClient(&req)
	if err != nil {
		facades.Log().Error("Failed to register OIDC client", map[string]interface{}{
			"error":       err.Error(),
			"client_name": req.ClientName,
		})

		return ctx.Response().Status(400).Json(responses.APIResponse{
			Status:  "error",
			Message: "Failed to register client",
			Error:   err.Error(),
		})
	}

	facades.Log().Info("OIDC client registered successfully", map[string]interface{}{
		"client_id":   response.ClientID,
		"client_name": response.ClientName,
	})

	return ctx.Response().Status(201).Json(response)
}

// GetClient retrieves OIDC client information
// @Summary Get OIDC client
// @Description Retrieves OIDC client information by ID
// @Tags OIDC Client
// @Accept json
// @Produce json
// @Param client_id path string true "Client ID"
// @Success 200 {object} services.OIDCClientRegistrationResponse
// @Failure 404 {object} responses.APIResponse
// @Failure 500 {object} responses.APIResponse
// @Router /oidc/register/{client_id} [get]
func (c *OIDCClientController) GetClient(ctx http.Context) http.Response {
	clientID := ctx.Request().Route("client_id")
	if clientID == "" {
		return ctx.Response().Status(400).Json(responses.APIResponse{
			Status:  "error",
			Message: "Client ID is required",
		})
	}

	// Get the client
	response, err := c.oidcClientService.GetClient(clientID)
	if err != nil {
		facades.Log().Error("Failed to get OIDC client", map[string]interface{}{
			"error":     err.Error(),
			"client_id": clientID,
		})

		return ctx.Response().Status(404).Json(responses.APIResponse{
			Status:  "error",
			Message: "Client not found",
			Error:   err.Error(),
		})
	}

	return ctx.Response().Success().Json(response)
}

// UpdateClient updates OIDC client information
// @Summary Update OIDC client
// @Description Updates OIDC client information
// @Tags OIDC Client
// @Accept json
// @Produce json
// @Param client_id path string true "Client ID"
// @Param client body services.OIDCClientRegistrationRequest true "Client update request"
// @Success 200 {object} services.OIDCClientRegistrationResponse
// @Failure 400 {object} responses.APIResponse
// @Failure 404 {object} responses.APIResponse
// @Failure 500 {object} responses.APIResponse
// @Router /oidc/register/{client_id} [put]
func (c *OIDCClientController) UpdateClient(ctx http.Context) http.Response {
	clientID := ctx.Request().Route("client_id")
	if clientID == "" {
		return ctx.Response().Status(400).Json(responses.APIResponse{
			Status:  "error",
			Message: "Client ID is required",
		})
	}

	var req services.OIDCClientRegistrationRequest
	if err := ctx.Request().Bind(&req); err != nil {
		return ctx.Response().Status(400).Json(responses.APIResponse{
			Status:  "error",
			Message: "Invalid request format",
			Error:   err.Error(),
		})
	}

	// Update the client
	response, err := c.oidcClientService.UpdateClient(clientID, &req)
	if err != nil {
		facades.Log().Error("Failed to update OIDC client", map[string]interface{}{
			"error":     err.Error(),
			"client_id": clientID,
		})

		return ctx.Response().Status(400).Json(responses.APIResponse{
			Status:  "error",
			Message: "Failed to update client",
			Error:   err.Error(),
		})
	}

	facades.Log().Info("OIDC client updated successfully", map[string]interface{}{
		"client_id":   response.ClientID,
		"client_name": response.ClientName,
	})

	return ctx.Response().Success().Json(response)
}

// DeleteClient deletes an OIDC client
// @Summary Delete OIDC client
// @Description Deletes (revokes) an OIDC client
// @Tags OIDC Client
// @Accept json
// @Produce json
// @Param client_id path string true "Client ID"
// @Success 204
// @Failure 404 {object} responses.APIResponse
// @Failure 500 {object} responses.APIResponse
// @Router /oidc/register/{client_id} [delete]
func (c *OIDCClientController) DeleteClient(ctx http.Context) http.Response {
	clientID := ctx.Request().Route("client_id")
	if clientID == "" {
		return ctx.Response().Status(400).Json(responses.APIResponse{
			Status:  "error",
			Message: "Client ID is required",
		})
	}

	// Delete the client
	err := c.oidcClientService.DeleteClient(clientID)
	if err != nil {
		facades.Log().Error("Failed to delete OIDC client", map[string]interface{}{
			"error":     err.Error(),
			"client_id": clientID,
		})

		return ctx.Response().Status(404).Json(responses.APIResponse{
			Status:  "error",
			Message: "Failed to delete client",
			Error:   err.Error(),
		})
	}

	facades.Log().Info("OIDC client deleted successfully", map[string]interface{}{
		"client_id": clientID,
	})

	return ctx.Response().Status(204).Json(nil)
}

// ValidateClient validates client credentials
// @Summary Validate OIDC client
// @Description Validates OIDC client credentials
// @Tags OIDC Client
// @Accept json
// @Produce json
// @Param client_id formData string true "Client ID"
// @Param client_secret formData string true "Client Secret"
// @Success 200 {object} responses.APIResponse
// @Failure 401 {object} responses.APIResponse
// @Failure 500 {object} responses.APIResponse
// @Router /oidc/validate [post]
func (c *OIDCClientController) ValidateClient(ctx http.Context) http.Response {
	clientID := ctx.Request().Input("client_id")
	clientSecret := ctx.Request().Input("client_secret")

	if clientID == "" || clientSecret == "" {
		return ctx.Response().Status(400).Json(responses.APIResponse{
			Status:  "error",
			Message: "Client ID and Client Secret are required",
		})
	}

	// Validate the client
	client, err := c.oidcClientService.ValidateClient(clientID, clientSecret)
	if err != nil {
		facades.Log().Error("Failed to validate OIDC client", map[string]interface{}{
			"error":     err.Error(),
			"client_id": clientID,
		})

		return ctx.Response().Status(401).Json(responses.APIResponse{
			Status:  "error",
			Message: "Invalid client credentials",
			Error:   err.Error(),
		})
	}

	facades.Log().Info("OIDC client validated successfully", map[string]interface{}{
		"client_id":   client.ID,
		"client_name": client.Name,
	})

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:  "success",
		Message: "Client credentials are valid",
		Data: map[string]interface{}{
			"client_id":   client.ID,
			"client_name": client.Name,
			"revoked":     client.Revoked,
		},
	})
}

// ListClients lists all OIDC clients (admin only)
// @Summary List OIDC clients
// @Description Lists all OIDC clients (admin only)
// @Tags OIDC Client
// @Accept json
// @Produce json
// @Security BearerAuth
// @Success 200 {object} responses.APIResponse
// @Failure 401 {object} responses.APIResponse
// @Failure 403 {object} responses.APIResponse
// @Router /oidc/clients [get]
func (c *OIDCClientController) ListClients(ctx http.Context) http.Response {
	// TODO: Implement admin authorization check
	// For now, we'll return a placeholder response

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:  "success",
		Message: "Client listing endpoint",
		Data: map[string]interface{}{
			"message": "Client listing functionality to be implemented",
			"note":    "This endpoint requires admin authorization",
		},
	})
}

// GetClientMetadata returns client metadata for discovery
// @Summary Get OIDC client metadata
// @Description Returns OIDC client metadata for discovery
// @Tags OIDC Client
// @Accept json
// @Produce json
// @Param client_id path string true "Client ID"
// @Success 200 {object} map[string]interface{}
// @Failure 404 {object} responses.APIResponse
// @Router /oidc/client/{client_id}/metadata [get]
func (c *OIDCClientController) GetClientMetadata(ctx http.Context) http.Response {
	clientID := ctx.Request().Route("client_id")
	if clientID == "" {
		return ctx.Response().Status(400).Json(responses.APIResponse{
			Status:  "error",
			Message: "Client ID is required",
		})
	}

	// Get the client
	response, err := c.oidcClientService.GetClient(clientID)
	if err != nil {
		return ctx.Response().Status(404).Json(responses.APIResponse{
			Status:  "error",
			Message: "Client not found",
			Error:   err.Error(),
		})
	}

	// Return client metadata in OIDC format
	metadata := map[string]interface{}{
		"client_id":                  response.ClientID,
		"client_name":                response.ClientName,
		"client_uri":                 response.ClientURI,
		"logo_uri":                   response.LogoURI,
		"redirect_uris":              response.RedirectURIs,
		"token_endpoint_auth_method": response.TokenEndpointAuthMethod,
		"grant_types":                response.GrantTypes,
		"response_types":             response.ResponseTypes,
		"scope":                      strings.Join(response.Scopes, " "),
		"contacts":                   response.Contacts,
		"policy_uri":                 response.PolicyURI,
		"tos_uri":                    response.TermsOfServiceURI,
		"jwks_uri":                   response.JwksURI,
		"software_id":                response.SoftwareID,
		"software_version":           response.SoftwareVersion,
		"subject_type":               response.SubjectType,
	}

	return ctx.Response().Success().Json(metadata)
}
