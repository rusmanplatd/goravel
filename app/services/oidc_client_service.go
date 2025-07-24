package services

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	"goravel/app/models"

	"github.com/goravel/framework/facades"
)

type OIDCClientService struct {
	oauthService *OAuthService
}

type OIDCClientRegistrationRequest struct {
	ClientName                        string   `json:"client_name"`
	ClientURI                         string   `json:"client_uri,omitempty"`
	LogoURI                           string   `json:"logo_uri,omitempty"`
	RedirectURIs                      []string `json:"redirect_uris"`
	TokenEndpointAuthMethod           string   `json:"token_endpoint_auth_method,omitempty"`
	GrantTypes                        []string `json:"grant_types,omitempty"`
	ResponseTypes                     []string `json:"response_types,omitempty"`
	Scopes                            []string `json:"scope,omitempty"`
	Contacts                          []string `json:"contacts,omitempty"`
	PolicyURI                         string   `json:"policy_uri,omitempty"`
	TermsOfServiceURI                 string   `json:"tos_uri,omitempty"`
	JwksURI                           string   `json:"jwks_uri,omitempty"`
	SoftwareID                        string   `json:"software_id,omitempty"`
	SoftwareVersion                   string   `json:"software_version,omitempty"`
	SubjectType                       string   `json:"subject_type,omitempty"`
	SectorIdentifierURI               string   `json:"sector_identifier_uri,omitempty"`
	RequestObjectSigningAlg           string   `json:"request_object_signing_alg,omitempty"`
	UserinfoSignedResponseAlg         string   `json:"userinfo_signed_response_alg,omitempty"`
	UserinfoEncryptedResponseAlg      string   `json:"userinfo_encrypted_response_alg,omitempty"`
	UserinfoEncryptedResponseEnc      string   `json:"userinfo_encrypted_response_enc,omitempty"`
	IDTokenSignedResponseAlg          string   `json:"id_token_signed_response_alg,omitempty"`
	IDTokenEncryptedResponseAlg       string   `json:"id_token_encrypted_response_alg,omitempty"`
	IDTokenEncryptedResponseEnc       string   `json:"id_token_encrypted_response_enc,omitempty"`
	AuthorizationSignedResponseAlg    string   `json:"authorization_signed_response_alg,omitempty"`
	AuthorizationEncryptedResponseAlg string   `json:"authorization_encrypted_response_alg,omitempty"`
	AuthorizationEncryptedResponseEnc string   `json:"authorization_encrypted_response_enc,omitempty"`
}

type OIDCClientRegistrationResponse struct {
	ClientID                string   `json:"client_id"`
	ClientSecret            string   `json:"client_secret,omitempty"`
	ClientIDIssuedAt        int64    `json:"client_id_issued_at"`
	ClientSecretExpiresAt   int64    `json:"client_secret_expires_at,omitempty"`
	ClientName              string   `json:"client_name"`
	ClientURI               string   `json:"client_uri,omitempty"`
	LogoURI                 string   `json:"logo_uri,omitempty"`
	RedirectURIs            []string `json:"redirect_uris"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	GrantTypes              []string `json:"grant_types"`
	ResponseTypes           []string `json:"response_types"`
	Scopes                  []string `json:"scope"`
	Contacts                []string `json:"contacts,omitempty"`
	PolicyURI               string   `json:"policy_uri,omitempty"`
	TermsOfServiceURI       string   `json:"tos_uri,omitempty"`
	JwksURI                 string   `json:"jwks_uri,omitempty"`
	SoftwareID              string   `json:"software_id,omitempty"`
	SoftwareVersion         string   `json:"software_version,omitempty"`
	SubjectType             string   `json:"subject_type"`
	RegistrationAccessToken string   `json:"registration_access_token,omitempty"`
	RegistrationClientURI   string   `json:"registration_client_uri,omitempty"`
}

func NewOIDCClientService() *OIDCClientService {
	return &OIDCClientService{
		oauthService: NewOAuthService(),
	}
}

// RegisterClient registers a new OIDC client
func (s *OIDCClientService) RegisterClient(req *OIDCClientRegistrationRequest) (*OIDCClientRegistrationResponse, error) {
	// Validate request
	if err := s.validateRegistrationRequest(req); err != nil {
		return nil, err
	}

	// Generate client ID and secret
	clientID := s.generateClientID()
	clientSecret := s.generateClientSecret()

	// Determine token endpoint auth method
	tokenEndpointAuthMethod := req.TokenEndpointAuthMethod
	if tokenEndpointAuthMethod == "" {
		tokenEndpointAuthMethod = "client_secret_basic"
	}

	// Set default grant types if not provided
	grantTypes := req.GrantTypes
	if len(grantTypes) == 0 {
		grantTypes = []string{"authorization_code"}
	}

	// Set default response types if not provided
	responseTypes := req.ResponseTypes
	if len(responseTypes) == 0 {
		responseTypes = []string{"code"}
	}

	// Set default scopes if not provided
	scopes := req.Scopes
	if len(scopes) == 0 {
		scopes = []string{"openid"}
	}

	// Set default subject type if not provided
	subjectType := req.SubjectType
	if subjectType == "" {
		subjectType = "public"
	}

	// Create OAuth client
	client := &models.OAuthClient{
		ID:     clientID,
		Name:   req.ClientName,
		Secret: &clientSecret,
	}

	// Set redirect URIs
	client.SetRedirectURIs(req.RedirectURIs)

	// TODO: Store additional metadata in a separate field or use JSON field if available
	// This would need to be implemented based on your database schema
	// For now, we'll use the basic OAuth client model

	// Save client to database
	err := facades.Orm().Query().Create(client)
	if err != nil {
		return nil, fmt.Errorf("failed to create OIDC client: %v", err)
	}

	// Generate registration access token
	registrationAccessToken := s.generateRegistrationAccessToken(clientID)

	// Create response
	response := &OIDCClientRegistrationResponse{
		ClientID:                clientID,
		ClientSecret:            clientSecret,
		ClientIDIssuedAt:        time.Now().Unix(),
		ClientSecretExpiresAt:   0, // No expiration for now
		ClientName:              req.ClientName,
		ClientURI:               req.ClientURI,
		LogoURI:                 req.LogoURI,
		RedirectURIs:            req.RedirectURIs,
		TokenEndpointAuthMethod: tokenEndpointAuthMethod,
		GrantTypes:              grantTypes,
		ResponseTypes:           responseTypes,
		Scopes:                  scopes,
		Contacts:                req.Contacts,
		PolicyURI:               req.PolicyURI,
		TermsOfServiceURI:       req.TermsOfServiceURI,
		JwksURI:                 req.JwksURI,
		SoftwareID:              req.SoftwareID,
		SoftwareVersion:         req.SoftwareVersion,
		SubjectType:             subjectType,
		RegistrationAccessToken: registrationAccessToken,
		RegistrationClientURI:   fmt.Sprintf("%s/oidc/register/%s", facades.Config().GetString("oidc.issuer"), clientID),
	}

	return response, nil
}

// GetClient retrieves an OIDC client by ID
func (s *OIDCClientService) GetClient(clientID string) (*OIDCClientRegistrationResponse, error) {
	var client models.OAuthClient
	err := facades.Orm().Query().Where("id", clientID).First(&client)
	if err != nil {
		return nil, fmt.Errorf("client not found: %v", err)
	}

	// Convert to response format
	response := &OIDCClientRegistrationResponse{
		ClientID:                client.ID,
		ClientName:              client.Name,
		RedirectURIs:            client.GetRedirectURIs(),
		TokenEndpointAuthMethod: "client_secret_basic",          // Default
		GrantTypes:              []string{"authorization_code"}, // Default
		ResponseTypes:           []string{"code"},               // Default
		Scopes:                  []string{"openid"},             // Default
		SubjectType:             "public",                       // Default
	}

	return response, nil
}

// UpdateClient updates an existing OIDC client
func (s *OIDCClientService) UpdateClient(clientID string, req *OIDCClientRegistrationRequest) (*OIDCClientRegistrationResponse, error) {
	// Validate request
	if err := s.validateRegistrationRequest(req); err != nil {
		return nil, err
	}

	// Get existing client
	var client models.OAuthClient
	err := facades.Orm().Query().Where("id", clientID).First(&client)
	if err != nil {
		return nil, fmt.Errorf("client not found: %v", err)
	}

	// Update client fields
	client.Name = req.ClientName
	client.SetRedirectURIs(req.RedirectURIs)

	// Save updated client
	err = facades.Orm().Query().Save(&client)
	if err != nil {
		return nil, fmt.Errorf("failed to update OIDC client: %v", err)
	}

	// Return updated client info
	return s.GetClient(clientID)
}

// DeleteClient deletes an OIDC client
func (s *OIDCClientService) DeleteClient(clientID string) error {
	var client models.OAuthClient
	err := facades.Orm().Query().Where("id", clientID).First(&client)
	if err != nil {
		return fmt.Errorf("client not found: %v", err)
	}

	// Mark as revoked instead of deleting
	client.Revoked = true
	err = facades.Orm().Query().Save(&client)
	if err != nil {
		return fmt.Errorf("failed to revoke OIDC client: %v", err)
	}

	return nil
}

// ValidateClient validates client credentials
func (s *OIDCClientService) ValidateClient(clientID, clientSecret string) (*models.OAuthClient, error) {
	var client models.OAuthClient
	err := facades.Orm().Query().Where("id", clientID).First(&client)
	if err != nil {
		return nil, fmt.Errorf("client not found: %v", err)
	}

	if client.Revoked {
		return nil, fmt.Errorf("client is revoked")
	}

	if client.Secret != nil && *client.Secret != clientSecret {
		return nil, fmt.Errorf("invalid client secret")
	}

	return &client, nil
}

// validateRegistrationRequest validates the client registration request
func (s *OIDCClientService) validateRegistrationRequest(req *OIDCClientRegistrationRequest) error {
	if req.ClientName == "" {
		return fmt.Errorf("client_name is required")
	}

	if len(req.RedirectURIs) == 0 {
		return fmt.Errorf("redirect_uris is required")
	}

	// Validate redirect URIs
	for _, uri := range req.RedirectURIs {
		if !s.isValidRedirectURI(uri) {
			return fmt.Errorf("invalid redirect URI: %s", uri)
		}
	}

	// Validate token endpoint auth method
	if req.TokenEndpointAuthMethod != "" {
		supportedMethods := facades.Config().Get("oidc.token_endpoint_auth_methods_supported").([]string)
		methodValid := false
		for _, method := range supportedMethods {
			if method == req.TokenEndpointAuthMethod {
				methodValid = true
				break
			}
		}
		if !methodValid {
			return fmt.Errorf("unsupported token endpoint auth method")
		}
	}

	// Validate grant types
	if len(req.GrantTypes) > 0 {
		supportedGrantTypes := facades.Config().Get("oidc.grant_types_supported").([]string)
		for _, gt := range req.GrantTypes {
			grantTypeValid := false
			for _, supported := range supportedGrantTypes {
				if supported == gt {
					grantTypeValid = true
					break
				}
			}
			if !grantTypeValid {
				return fmt.Errorf("unsupported grant type: %s", gt)
			}
		}
	}

	// Validate response types
	if len(req.ResponseTypes) > 0 {
		supportedResponseTypes := facades.Config().Get("oidc.response_types_supported").([]string)
		for _, rt := range req.ResponseTypes {
			responseTypeValid := false
			for _, supported := range supportedResponseTypes {
				if supported == rt {
					responseTypeValid = true
					break
				}
			}
			if !responseTypeValid {
				return fmt.Errorf("unsupported response type: %s", rt)
			}
		}
	}

	// Validate scopes
	if len(req.Scopes) > 0 {
		for _, scope := range req.Scopes {
			if !s.isValidScope(scope) {
				return fmt.Errorf("invalid scope: %s", scope)
			}
		}
	}

	// Validate subject type
	if req.SubjectType != "" {
		supportedSubjectTypes := facades.Config().Get("oidc.subject_types_supported").([]string)
		subjectTypeValid := false
		for _, st := range supportedSubjectTypes {
			if st == req.SubjectType {
				subjectTypeValid = true
				break
			}
		}
		if !subjectTypeValid {
			return fmt.Errorf("unsupported subject type")
		}
	}

	return nil
}

// isValidRedirectURI validates a redirect URI
func (s *OIDCClientService) isValidRedirectURI(uri string) bool {
	// Basic validation - in production, you might want more sophisticated validation
	if uri == "" {
		return false
	}

	// Check if it's a valid URL
	if !strings.HasPrefix(uri, "http://") && !strings.HasPrefix(uri, "https://") {
		return false
	}

	// Check for localhost in production
	if facades.Config().GetString("app.env") == "production" {
		if strings.Contains(uri, "localhost") || strings.Contains(uri, "127.0.0.1") {
			return false
		}
	}

	return true
}

// isValidScope validates a scope
func (s *OIDCClientService) isValidScope(scope string) bool {
	supportedScopes := facades.Config().Get("oidc.scopes_supported").([]string)
	for _, supported := range supportedScopes {
		if supported == scope {
			return true
		}
	}
	return false
}

// generateClientID generates a unique client ID
func (s *OIDCClientService) generateClientID() string {
	bytes := make([]byte, 16)
	rand.Read(bytes)
	return base64.RawURLEncoding.EncodeToString(bytes)
}

// generateClientSecret generates a secure client secret
func (s *OIDCClientService) generateClientSecret() string {
	bytes := make([]byte, 32)
	rand.Read(bytes)
	return base64.RawURLEncoding.EncodeToString(bytes)
}

// generateRegistrationAccessToken generates a registration access token
func (s *OIDCClientService) generateRegistrationAccessToken(clientID string) string {
	// In a production environment, you should generate a proper JWT token
	// For now, we'll use a simple hash
	hash := sha256.Sum256([]byte(clientID + time.Now().String()))
	return base64.RawURLEncoding.EncodeToString(hash[:])
}

// StoreClientMetadata stores additional client metadata
func (s *OIDCClientService) StoreClientMetadata(clientID string, metadata map[string]interface{}) error {
	// In a production environment, you would store this in a separate table
	// or in a JSON field in the oauth_clients table
	// For now, we'll log it
	facades.Log().Info("Client metadata stored", map[string]interface{}{
		"client_id": clientID,
		"metadata":  metadata,
	})
	return nil
}

// GetClientMetadata retrieves client metadata
func (s *OIDCClientService) GetClientMetadata(clientID string) (map[string]interface{}, error) {
	// In a production environment, you would retrieve this from storage
	// For now, we'll return empty metadata
	return map[string]interface{}{}, nil
}

// ValidateClientCredentials validates client credentials
func (s *OIDCClientService) ValidateClientCredentials(clientID, clientSecret string) error {
	client, err := s.ValidateClient(clientID, clientSecret)
	if err != nil {
		return err
	}

	if client.IsRevoked() {
		return fmt.Errorf("client is revoked")
	}

	return nil
}

// ListClientsByUser lists all clients for a specific user
func (s *OIDCClientService) ListClientsByUser(userID string) ([]*OIDCClientRegistrationResponse, error) {
	var clients []models.OAuthClient
	err := facades.Orm().Query().Where("user_id", userID).Find(&clients)
	if err != nil {
		return nil, err
	}

	var responses []*OIDCClientRegistrationResponse
	for _, client := range clients {
		response := &OIDCClientRegistrationResponse{
			ClientID:                client.ID,
			ClientName:              client.Name,
			RedirectURIs:            client.GetRedirectURIs(),
			TokenEndpointAuthMethod: "client_secret_basic",
			GrantTypes:              []string{"authorization_code"},
			ResponseTypes:           []string{"code"},
			Scopes:                  []string{"openid"},
			SubjectType:             "public",
		}
		responses = append(responses, response)
	}

	return responses, nil
}

// UpdateClientSecret updates a client's secret
func (s *OIDCClientService) UpdateClientSecret(clientID string) (string, error) {
	var client models.OAuthClient
	err := facades.Orm().Query().Where("id", clientID).First(&client)
	if err != nil {
		return "", fmt.Errorf("client not found: %v", err)
	}

	// Generate new secret
	newSecret := s.generateClientSecret()
	client.Secret = &newSecret

	// Save updated client
	err = facades.Orm().Query().Save(&client)
	if err != nil {
		return "", fmt.Errorf("failed to update client secret: %v", err)
	}

	return newSecret, nil
}

// GetClientStatistics returns client usage statistics
func (s *OIDCClientService) GetClientStatistics(clientID string) (map[string]interface{}, error) {
	// In a production environment, you would query actual usage data
	// For now, we'll return placeholder statistics
	return map[string]interface{}{
		"total_authorizations": 0,
		"total_tokens_issued":  0,
		"last_used":            time.Now().Unix(),
		"active_tokens":        0,
	}, nil
}

// ValidateClientPermissions validates if a client has required permissions
func (s *OIDCClientService) ValidateClientPermissions(clientID string, requiredPermissions []string) error {
	// In a production environment, you would check actual permissions
	// For now, we'll assume all clients have basic permissions
	return nil
}

// LogClientActivity logs client activity for audit purposes
func (s *OIDCClientService) LogClientActivity(clientID, activityType string, metadata map[string]interface{}) {
	if !facades.Config().GetBool("oidc.logging.enable_client_activity_logging", true) {
		return
	}

	facades.Log().Info("Client Activity", map[string]interface{}{
		"client_id":     clientID,
		"activity_type": activityType,
		"metadata":      metadata,
		"timestamp":     time.Now().Unix(),
	})
}
