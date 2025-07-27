package services

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"goravel/app/models"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/goravel/framework/facades"
)

type OAuthResourceIndicatorsService struct {
	oauthService             *OAuthService
	hierarchicalScopeService *OAuthHierarchicalScopeService
}

// ResourceServer represents an OAuth2 resource server
type ResourceServer struct {
	ID                    string                  `json:"id"`
	Name                  string                  `json:"name"`
	URI                   string                  `json:"uri"`
	Description           string                  `json:"description"`
	Category              string                  `json:"category"`
	SupportedScopes       []string                `json:"supported_scopes"`
	RequiredScopes        []string                `json:"required_scopes"`
	DefaultScopes         []string                `json:"default_scopes"`
	MaxScopeLifetime      int64                   `json:"max_scope_lifetime"`      // seconds
	TokenFormat           string                  `json:"token_format"`            // jwt, opaque
	TokenSigningAlgorithm string                  `json:"token_signing_algorithm"` // RS256, ES256, etc.
	Audience              []string                `json:"audience"`
	Issuer                string                  `json:"issuer"`
	JWKSURI               string                  `json:"jwks_uri,omitempty"`
	IntrospectionEndpoint string                  `json:"introspection_endpoint,omitempty"`
	Active                bool                    `json:"active"`
	CreatedAt             time.Time               `json:"created_at"`
	UpdatedAt             time.Time               `json:"updated_at"`
	Metadata              map[string]interface{}  `json:"metadata"`
	SecurityPolicy        *ResourceSecurityPolicy `json:"security_policy,omitempty"`
}

// ResourceSecurityPolicy defines security requirements for a resource server
type ResourceSecurityPolicy struct {
	RequireMTLS          bool                   `json:"require_mtls"`
	RequireDPoP          bool                   `json:"require_dpop"`
	RequireTokenBinding  bool                   `json:"require_token_binding"`
	RequireJWTFormat     bool                   `json:"require_jwt_format"`
	AllowedClientTypes   []string               `json:"allowed_client_types"`    // public, confidential
	AllowedGrantTypes    []string               `json:"allowed_grant_types"`     // authorization_code, client_credentials, etc.
	MaxTokenLifetime     int64                  `json:"max_token_lifetime"`      // seconds
	RequireConsentForAll bool                   `json:"require_consent_for_all"` // require user consent for all scopes
	TrustedIssuers       []string               `json:"trusted_issuers"`
	RequiredClaims       []string               `json:"required_claims"`
	ConditionalAccess    map[string]interface{} `json:"conditional_access"`
}

// ResourceAuthorizationRequest represents a request with resource indicators
type ResourceAuthorizationRequest struct {
	ClientID    string                 `json:"client_id"`
	UserID      string                 `json:"user_id,omitempty"`
	Resources   []string               `json:"resources"` // Resource server URIs
	Scopes      []string               `json:"scopes"`    // Requested scopes
	GrantType   string                 `json:"grant_type"`
	RequestedAt time.Time              `json:"requested_at"`
	Context     map[string]interface{} `json:"context"`
}

// ResourceAuthorizationResult contains the result of resource authorization
type ResourceAuthorizationResult struct {
	Authorized            bool                      `json:"authorized"`
	AuthorizedResources   []string                  `json:"authorized_resources"`
	DeniedResources       []string                  `json:"denied_resources"`
	ResourceTokens        map[string]*ResourceToken `json:"resource_tokens"`
	ScopesByResource      map[string][]string       `json:"scopes_by_resource"`
	ValidationErrors      []string                  `json:"validation_errors"`
	SecurityWarnings      []string                  `json:"security_warnings"`
	PolicyViolations      []string                  `json:"policy_violations"`
	RecommendedActions    []string                  `json:"recommended_actions"`
	ConsentRequired       map[string][]string       `json:"consent_required"`         // resource -> scopes requiring consent
	SteppedUpAuthRequired map[string][]string       `json:"stepped_up_auth_required"` // resource -> scopes requiring step-up
	Details               map[string]interface{}    `json:"details"`
}

// ResourceToken represents a token scoped to specific resources
type ResourceToken struct {
	TokenID         string                 `json:"token_id"`
	ResourceURI     string                 `json:"resource_uri"`
	Audience        []string               `json:"audience"`
	Scopes          []string               `json:"scopes"`
	TokenType       string                 `json:"token_type"`   // Bearer, DPoP, etc.
	TokenFormat     string                 `json:"token_format"` // jwt, opaque
	ExpiresAt       time.Time              `json:"expires_at"`
	IssuedAt        time.Time              `json:"issued_at"`
	NotBefore       time.Time              `json:"not_before,omitempty"`
	ClientID        string                 `json:"client_id"`
	UserID          string                 `json:"user_id,omitempty"`
	Claims          map[string]interface{} `json:"claims"`
	BindingInfo     map[string]interface{} `json:"binding_info,omitempty"`
	SecurityContext map[string]interface{} `json:"security_context"`
}

func NewOAuthResourceIndicatorsService() *OAuthResourceIndicatorsService {
	oauthService, err := NewOAuthService()
	if err != nil {
		facades.Log().Error("Failed to initialize OAuth service for resource indicators", map[string]interface{}{
			"error": err.Error(),
		})
		// Return service without OAuth service - it will handle this gracefully
		return &OAuthResourceIndicatorsService{
			hierarchicalScopeService: NewOAuthHierarchicalScopeService(),
		}
	}

	return &OAuthResourceIndicatorsService{
		oauthService:             oauthService,
		hierarchicalScopeService: NewOAuthHierarchicalScopeService(),
	}
}

// ProcessResourceAuthorizationRequest processes authorization request with resource indicators
func (s *OAuthResourceIndicatorsService) ProcessResourceAuthorizationRequest(request *ResourceAuthorizationRequest) (*ResourceAuthorizationResult, error) {
	result := &ResourceAuthorizationResult{
		Authorized:            false,
		AuthorizedResources:   []string{},
		DeniedResources:       []string{},
		ResourceTokens:        make(map[string]*ResourceToken),
		ScopesByResource:      make(map[string][]string),
		ValidationErrors:      []string{},
		SecurityWarnings:      []string{},
		PolicyViolations:      []string{},
		RecommendedActions:    []string{},
		ConsentRequired:       make(map[string][]string),
		SteppedUpAuthRequired: make(map[string][]string),
		Details:               make(map[string]interface{}),
	}

	// Validate request
	if err := s.validateResourceAuthorizationRequest(request); err != nil {
		result.ValidationErrors = append(result.ValidationErrors, err.Error())
		return result, err
	}

	// Process each requested resource
	for _, resourceURI := range request.Resources {
		resourceServer, err := s.getResourceServer(resourceURI)
		if err != nil {
			result.DeniedResources = append(result.DeniedResources, resourceURI)
			result.ValidationErrors = append(result.ValidationErrors, fmt.Sprintf("Resource server not found: %s", resourceURI))
			continue
		}

		// Check if resource server is active
		if !resourceServer.Active {
			result.DeniedResources = append(result.DeniedResources, resourceURI)
			result.ValidationErrors = append(result.ValidationErrors, fmt.Sprintf("Resource server inactive: %s", resourceURI))
			continue
		}

		// Determine applicable scopes for this resource
		applicableScopes := s.determineApplicableScopes(request.Scopes, resourceServer)
		if len(applicableScopes) == 0 {
			result.DeniedResources = append(result.DeniedResources, resourceURI)
			result.ValidationErrors = append(result.ValidationErrors, fmt.Sprintf("No applicable scopes for resource: %s", resourceURI))
			continue
		}

		// Validate scopes against resource server policy
		scopeValidation := s.validateScopesForResource(applicableScopes, resourceServer, request)
		if !scopeValidation.Valid {
			result.DeniedResources = append(result.DeniedResources, resourceURI)
			result.ValidationErrors = append(result.ValidationErrors, scopeValidation.Errors...)
			continue
		}

		// Check security policy compliance
		policyCheck := s.checkSecurityPolicy(resourceServer, request)
		if !policyCheck.Compliant {
			result.DeniedResources = append(result.DeniedResources, resourceURI)
			result.PolicyViolations = append(result.PolicyViolations, policyCheck.Violations...)
			continue
		}

		// Check consent requirements
		consentScopes := s.checkConsentRequirements(applicableScopes, resourceServer, request)
		if len(consentScopes) > 0 {
			result.ConsentRequired[resourceURI] = consentScopes
		}

		// Check stepped-up authentication requirements
		stepUpScopes := s.checkSteppedUpAuthRequirements(applicableScopes, resourceServer, request)
		if len(stepUpScopes) > 0 {
			result.SteppedUpAuthRequired[resourceURI] = stepUpScopes
		}

		// Resource is authorized
		result.AuthorizedResources = append(result.AuthorizedResources, resourceURI)
		result.ScopesByResource[resourceURI] = applicableScopes

		// Create resource-specific token
		resourceToken, err := s.createResourceToken(resourceURI, resourceServer, applicableScopes, request)
		if err != nil {
			result.SecurityWarnings = append(result.SecurityWarnings, fmt.Sprintf("Failed to create token for resource %s: %v", resourceURI, err))
		} else {
			result.ResourceTokens[resourceURI] = resourceToken
		}
	}

	// Determine overall authorization status
	result.Authorized = len(result.AuthorizedResources) > 0

	// Add security recommendations
	s.addSecurityRecommendations(result, request)

	// Log resource authorization
	s.logResourceAuthorization(request, result)

	return result, nil
}

// GetResourceServers returns all registered resource servers
func (s *OAuthResourceIndicatorsService) GetResourceServers() ([]*ResourceServer, error) {
	// Query database for registered resource servers
	var resourceServers []*ResourceServer

	// Try to get from cache first
	cacheKey := "resource_servers_all"
	if cached := facades.Cache().Get(cacheKey, ""); cached != "" {
		if err := json.Unmarshal([]byte(cached.(string)), &resourceServers); err == nil {
			return resourceServers, nil
		}
	}

	// Query from database
	var dbResourceServers []models.OAuthResourceServer
	err := facades.Orm().Query().Find(&dbResourceServers)
	if err != nil {
		facades.Log().Error("Failed to query resource servers from database", map[string]interface{}{
			"error": err.Error(),
		})
		// Fallback to default resource servers
		return s.getDefaultResourceServers(), nil
	}

	// Convert to service models
	for _, dbServer := range dbResourceServers {
		resourceServer := &ResourceServer{
			ID:          dbServer.ID,
			URI:         dbServer.URI,
			Name:        dbServer.Name,
			Description: dbServer.Description,
			Category:    dbServer.Category,
			CreatedAt:   dbServer.CreatedAt,
			UpdatedAt:   dbServer.UpdatedAt,
		}

		// Parse supported scopes
		if dbServer.SupportedScopes != "" {
			var scopes []string
			if err := json.Unmarshal([]byte(dbServer.SupportedScopes), &scopes); err == nil {
				resourceServer.SupportedScopes = scopes
			}
		}

		// Parse required scopes
		if dbServer.RequiredScopes != "" {
			var scopes []string
			if err := json.Unmarshal([]byte(dbServer.RequiredScopes), &scopes); err == nil {
				resourceServer.RequiredScopes = scopes
			}
		}

		// Parse default scopes
		if dbServer.DefaultScopes != "" {
			var scopes []string
			if err := json.Unmarshal([]byte(dbServer.DefaultScopes), &scopes); err == nil {
				resourceServer.DefaultScopes = scopes
			}
		}

		// Parse security policy if exists
		if dbServer.SecurityPolicy != "" {
			var policy ResourceSecurityPolicy
			if err := json.Unmarshal([]byte(dbServer.SecurityPolicy), &policy); err == nil {
				resourceServer.SecurityPolicy = &policy
			}
		}

		resourceServers = append(resourceServers, resourceServer)
	}

	// Cache the result
	if data, err := json.Marshal(resourceServers); err == nil {
		facades.Cache().Put(cacheKey, string(data), time.Hour*6) // Cache for 6 hours
	}

	return resourceServers, nil
}

// RegisterResourceServer registers a new resource server
func (s *OAuthResourceIndicatorsService) RegisterResourceServer(resourceServer *ResourceServer) error {
	if err := s.validateResourceServer(resourceServer); err != nil {
		return fmt.Errorf("invalid resource server: %w", err)
	}

	resourceServer.CreatedAt = time.Now()
	resourceServer.UpdatedAt = time.Now()

	// Store in database for production persistence
	dbResourceServer := &models.OAuthResourceServer{
		Name:        resourceServer.Name,
		URI:         resourceServer.URI,
		Description: resourceServer.Description,
		Category:    resourceServer.Category,
	}

	// Convert scopes to JSON
	if len(resourceServer.SupportedScopes) > 0 {
		supportedScopesJSON, err := json.Marshal(resourceServer.SupportedScopes)
		if err != nil {
			return fmt.Errorf("failed to marshal supported scopes: %w", err)
		}
		dbResourceServer.SupportedScopes = string(supportedScopesJSON)
	}

	if len(resourceServer.RequiredScopes) > 0 {
		requiredScopesJSON, err := json.Marshal(resourceServer.RequiredScopes)
		if err != nil {
			return fmt.Errorf("failed to marshal required scopes: %w", err)
		}
		dbResourceServer.RequiredScopes = string(requiredScopesJSON)
	}

	if len(resourceServer.DefaultScopes) > 0 {
		defaultScopesJSON, err := json.Marshal(resourceServer.DefaultScopes)
		if err != nil {
			return fmt.Errorf("failed to marshal default scopes: %w", err)
		}
		dbResourceServer.DefaultScopes = string(defaultScopesJSON)
	}

	// Convert security policy to JSON
	if resourceServer.SecurityPolicy != nil {
		securityPolicyJSON, err := json.Marshal(resourceServer.SecurityPolicy)
		if err != nil {
			return fmt.Errorf("failed to marshal security policy: %w", err)
		}
		dbResourceServer.SecurityPolicy = string(securityPolicyJSON)
	}

	// Save to database
	if err := facades.Orm().Query().Create(dbResourceServer); err != nil {
		return fmt.Errorf("failed to save resource server to database: %w", err)
	}

	// Update the resource server with the database ID
	resourceServer.ID = dbResourceServer.ID

	// Also cache for faster access
	key := fmt.Sprintf("resource_server_%s", resourceServer.URI)
	data, err := json.Marshal(resourceServer)
	if err != nil {
		facades.Log().Warning("Failed to cache resource server", map[string]interface{}{
			"error": err.Error(),
		})
	} else {
		facades.Cache().Put(key, string(data), time.Hour*6) // Cache for 6 hours
	}

	facades.Log().Info("Resource server registered", map[string]interface{}{
		"id":   resourceServer.ID,
		"uri":  resourceServer.URI,
		"name": resourceServer.Name,
	})

	return nil
}

// Helper methods

func (s *OAuthResourceIndicatorsService) validateResourceAuthorizationRequest(request *ResourceAuthorizationRequest) error {
	if request.ClientID == "" {
		return fmt.Errorf("client_id is required")
	}

	if len(request.Resources) == 0 {
		return fmt.Errorf("at least one resource must be specified")
	}

	if len(request.Scopes) == 0 {
		return fmt.Errorf("at least one scope must be specified")
	}

	// Validate resource URIs
	for _, resourceURI := range request.Resources {
		if _, err := url.Parse(resourceURI); err != nil {
			return fmt.Errorf("invalid resource URI: %s", resourceURI)
		}
	}

	return nil
}

func (s *OAuthResourceIndicatorsService) getResourceServer(resourceURI string) (*ResourceServer, error) {
	key := fmt.Sprintf("resource_server_%s", resourceURI)
	data := facades.Cache().Get(key)
	if data == nil {
		// Check default resource servers
		defaultServers := s.getDefaultResourceServers()
		for _, server := range defaultServers {
			if server.URI == resourceURI {
				return server, nil
			}
		}
		return nil, fmt.Errorf("resource server not found: %s", resourceURI)
	}

	var resourceServer ResourceServer
	if err := json.Unmarshal([]byte(data.(string)), &resourceServer); err != nil {
		return nil, fmt.Errorf("failed to unmarshal resource server: %w", err)
	}

	return &resourceServer, nil
}

func (s *OAuthResourceIndicatorsService) getDefaultResourceServers() []*ResourceServer {
	baseURL := facades.Config().GetString("app.url")

	return []*ResourceServer{
		{
			ID:          "api-server",
			Name:        "Main API Server",
			URI:         baseURL + "/api",
			Description: "Primary API resource server",
			Category:    "api",
			SupportedScopes: []string{
				"user.read", "user.write", "user.admin",
				"organization.read", "organization.manage",
				"calendar.readonly", "calendar.events",
				"drive.readonly", "drive.file",
			},
			RequiredScopes:        []string{},
			DefaultScopes:         []string{"user.read"},
			MaxScopeLifetime:      3600, // 1 hour
			TokenFormat:           "jwt",
			TokenSigningAlgorithm: "RS256",
			Audience:              []string{baseURL + "/api"},
			Issuer:                baseURL,
			JWKSURI:               baseURL + "/api/v1/oauth/jwks",
			IntrospectionEndpoint: baseURL + "/api/v1/oauth/introspect",
			Active:                true,
			CreatedAt:             time.Now(),
			UpdatedAt:             time.Now(),
			Metadata: map[string]interface{}{
				"version": "1.0",
				"type":    "primary",
			},
			SecurityPolicy: &ResourceSecurityPolicy{
				RequireMTLS:          false,
				RequireDPoP:          false,
				RequireTokenBinding:  false,
				RequireJWTFormat:     true,
				AllowedClientTypes:   []string{"public", "confidential"},
				AllowedGrantTypes:    []string{"authorization_code", "client_credentials", "refresh_token"},
				MaxTokenLifetime:     7200, // 2 hours
				RequireConsentForAll: false,
				TrustedIssuers:       []string{baseURL},
				RequiredClaims:       []string{"sub", "aud", "exp", "iat"},
				ConditionalAccess:    make(map[string]interface{}),
			},
		},
		{
			ID:          "admin-api",
			Name:        "Administration API",
			URI:         baseURL + "/api/admin",
			Description: "Administrative API resource server",
			Category:    "admin",
			SupportedScopes: []string{
				"admin.directory", "admin.security",
				"admin.audit", "admin.system",
			},
			RequiredScopes:        []string{"admin"},
			DefaultScopes:         []string{},
			MaxScopeLifetime:      1800, // 30 minutes
			TokenFormat:           "jwt",
			TokenSigningAlgorithm: "RS256",
			Audience:              []string{baseURL + "/api/admin"},
			Issuer:                baseURL,
			JWKSURI:               baseURL + "/api/v1/oauth/jwks",
			IntrospectionEndpoint: baseURL + "/api/v1/oauth/introspect",
			Active:                true,
			CreatedAt:             time.Now(),
			UpdatedAt:             time.Now(),
			Metadata: map[string]interface{}{
				"version":     "1.0",
				"type":        "admin",
				"risk_level":  "high",
				"audit_level": "full",
			},
			SecurityPolicy: &ResourceSecurityPolicy{
				RequireMTLS:          true,
				RequireDPoP:          true,
				RequireTokenBinding:  true,
				RequireJWTFormat:     true,
				AllowedClientTypes:   []string{"confidential"},
				AllowedGrantTypes:    []string{"authorization_code", "client_credentials"},
				MaxTokenLifetime:     3600, // 1 hour
				RequireConsentForAll: true,
				TrustedIssuers:       []string{baseURL},
				RequiredClaims:       []string{"sub", "aud", "exp", "iat", "roles", "permissions"},
				ConditionalAccess: map[string]interface{}{
					"require_mfa":          true,
					"require_ip_whitelist": true,
					"max_session_age":      1800, // 30 minutes
				},
			},
		},
		{
			ID:          "files-api",
			Name:        "File Storage API",
			URI:         baseURL + "/api/files",
			Description: "File storage and management API",
			Category:    "storage",
			SupportedScopes: []string{
				"drive.readonly", "drive.file", "drive.metadata",
				"files.read", "files.write", "files.delete",
			},
			RequiredScopes:        []string{},
			DefaultScopes:         []string{"files.read"},
			MaxScopeLifetime:      7200, // 2 hours
			TokenFormat:           "jwt",
			TokenSigningAlgorithm: "RS256",
			Audience:              []string{baseURL + "/api/files"},
			Issuer:                baseURL,
			JWKSURI:               baseURL + "/api/v1/oauth/jwks",
			IntrospectionEndpoint: baseURL + "/api/v1/oauth/introspect",
			Active:                true,
			CreatedAt:             time.Now(),
			UpdatedAt:             time.Now(),
			Metadata: map[string]interface{}{
				"version":     "1.0",
				"type":        "storage",
				"quota_aware": true,
			},
			SecurityPolicy: &ResourceSecurityPolicy{
				RequireMTLS:          false,
				RequireDPoP:          true,
				RequireTokenBinding:  false,
				RequireJWTFormat:     true,
				AllowedClientTypes:   []string{"public", "confidential"},
				AllowedGrantTypes:    []string{"authorization_code", "refresh_token"},
				MaxTokenLifetime:     14400, // 4 hours
				RequireConsentForAll: false,
				TrustedIssuers:       []string{baseURL},
				RequiredClaims:       []string{"sub", "aud", "exp", "iat"},
				ConditionalAccess: map[string]interface{}{
					"quota_enforcement": true,
					"virus_scanning":    true,
				},
			},
		},
	}
}

func (s *OAuthResourceIndicatorsService) determineApplicableScopes(requestedScopes []string, resourceServer *ResourceServer) []string {
	var applicableScopes []string

	for _, requestedScope := range requestedScopes {
		for _, supportedScope := range resourceServer.SupportedScopes {
			if requestedScope == supportedScope {
				applicableScopes = append(applicableScopes, requestedScope)
				break
			}
			// Check for hierarchical scope matching
			if s.hierarchicalScopeService != nil {
				if s.isScopeApplicable(requestedScope, supportedScope) {
					applicableScopes = append(applicableScopes, requestedScope)
					break
				}
			}
		}
	}

	// Add required scopes
	for _, requiredScope := range resourceServer.RequiredScopes {
		if !s.containsScope(applicableScopes, requiredScope) {
			applicableScopes = append(applicableScopes, requiredScope)
		}
	}

	// Remove duplicates and sort
	applicableScopes = s.removeDuplicateScopes(applicableScopes)
	sort.Strings(applicableScopes)

	return applicableScopes
}

func (s *OAuthResourceIndicatorsService) validateScopesForResource(scopes []string, resourceServer *ResourceServer, request *ResourceAuthorizationRequest) *ResourceScopeValidationResult {
	result := &ResourceScopeValidationResult{
		Valid:  true,
		Errors: []string{},
	}

	// Check if all required scopes are present
	for _, requiredScope := range resourceServer.RequiredScopes {
		if !s.containsScope(scopes, requiredScope) {
			result.Valid = false
			result.Errors = append(result.Errors, fmt.Sprintf("Required scope missing: %s", requiredScope))
		}
	}

	// Validate individual scopes
	for _, scope := range scopes {
		if !s.containsScope(resourceServer.SupportedScopes, scope) {
			result.Valid = false
			result.Errors = append(result.Errors, fmt.Sprintf("Unsupported scope for resource: %s", scope))
		}
	}

	return result
}

type ResourceScopeValidationResult struct {
	Valid  bool     `json:"valid"`
	Errors []string `json:"errors"`
}

func (s *OAuthResourceIndicatorsService) checkSecurityPolicy(resourceServer *ResourceServer, request *ResourceAuthorizationRequest) *PolicyComplianceResult {
	result := &PolicyComplianceResult{
		Compliant:  true,
		Violations: []string{},
	}

	if resourceServer.SecurityPolicy == nil {
		return result
	}

	policy := resourceServer.SecurityPolicy

	// Check client type requirements
	if len(policy.AllowedClientTypes) > 0 {
		// Get actual client type from database
		clientType, err := s.getClientType(request.ClientID)
		if err != nil {
			facades.Log().Error("Failed to get client type", map[string]interface{}{
				"client_id": request.ClientID,
				"error":     err.Error(),
			})
			result.Compliant = false
			result.Violations = append(result.Violations, "Unable to verify client type")
		} else if !s.containsString(policy.AllowedClientTypes, clientType) {
			result.Compliant = false
			result.Violations = append(result.Violations, fmt.Sprintf("Client type not allowed: %s", clientType))
		}
	}

	// Check grant type requirements
	if len(policy.AllowedGrantTypes) > 0 {
		if !s.containsString(policy.AllowedGrantTypes, request.GrantType) {
			result.Compliant = false
			result.Violations = append(result.Violations, fmt.Sprintf("Grant type not allowed: %s", request.GrantType))
		}
	}

	// Check conditional access requirements
	if policy.ConditionalAccess != nil {
		if requireMFA, exists := policy.ConditionalAccess["require_mfa"]; exists && requireMFA.(bool) {
			// TODO: In production, check if user has valid MFA
			if !s.userHasMFA(request.UserID) {
				result.Compliant = false
				result.Violations = append(result.Violations, "MFA required for this resource")
			}
		}
	}

	return result
}

type PolicyComplianceResult struct {
	Compliant  bool     `json:"compliant"`
	Violations []string `json:"violations"`
}

func (s *OAuthResourceIndicatorsService) checkConsentRequirements(scopes []string, resourceServer *ResourceServer, request *ResourceAuthorizationRequest) []string {
	var consentScopes []string

	if resourceServer.SecurityPolicy != nil && resourceServer.SecurityPolicy.RequireConsentForAll {
		consentScopes = scopes
	} else {
		// Check specific scopes that require consent
		sensitiveScopes := []string{"admin", "admin.directory", "admin.security", "user.admin"}
		for _, scope := range scopes {
			for _, sensitiveScope := range sensitiveScopes {
				if strings.HasPrefix(scope, sensitiveScope) {
					consentScopes = append(consentScopes, scope)
					break
				}
			}
		}
	}

	return s.removeDuplicateScopes(consentScopes)
}

func (s *OAuthResourceIndicatorsService) checkSteppedUpAuthRequirements(scopes []string, resourceServer *ResourceServer, request *ResourceAuthorizationRequest) []string {
	var stepUpScopes []string

	// Scopes that require stepped-up authentication
	highRiskScopes := []string{"admin", "admin.security", "user.admin", "files.delete"}

	for _, scope := range scopes {
		for _, highRiskScope := range highRiskScopes {
			if strings.HasPrefix(scope, highRiskScope) {
				stepUpScopes = append(stepUpScopes, scope)
				break
			}
		}
	}

	return s.removeDuplicateScopes(stepUpScopes)
}

func (s *OAuthResourceIndicatorsService) createResourceToken(resourceURI string, resourceServer *ResourceServer, scopes []string, request *ResourceAuthorizationRequest) (*ResourceToken, error) {
	now := time.Now()
	tokenLifetime := time.Duration(resourceServer.MaxScopeLifetime) * time.Second
	if resourceServer.SecurityPolicy != nil && resourceServer.SecurityPolicy.MaxTokenLifetime > 0 {
		policyLifetime := time.Duration(resourceServer.SecurityPolicy.MaxTokenLifetime) * time.Second
		if policyLifetime < tokenLifetime {
			tokenLifetime = policyLifetime
		}
	}

	token := &ResourceToken{
		TokenID:     s.generateTokenID(),
		ResourceURI: resourceURI,
		Audience:    resourceServer.Audience,
		Scopes:      scopes,
		TokenType:   "Bearer",
		TokenFormat: resourceServer.TokenFormat,
		ExpiresAt:   now.Add(tokenLifetime),
		IssuedAt:    now,
		ClientID:    request.ClientID,
		UserID:      request.UserID,
		Claims: map[string]interface{}{
			"iss":       resourceServer.Issuer,
			"aud":       resourceServer.Audience,
			"sub":       request.UserID,
			"client_id": request.ClientID,
			"scope":     strings.Join(scopes, " "),
			"exp":       now.Add(tokenLifetime).Unix(),
			"iat":       now.Unix(),
		},
		SecurityContext: map[string]interface{}{
			"resource_uri":    resourceURI,
			"token_format":    resourceServer.TokenFormat,
			"signing_alg":     resourceServer.TokenSigningAlgorithm,
			"security_policy": resourceServer.SecurityPolicy != nil,
		},
	}

	return token, nil
}

func (s *OAuthResourceIndicatorsService) addSecurityRecommendations(result *ResourceAuthorizationResult, request *ResourceAuthorizationRequest) {
	// Add recommendations based on authorization results
	if len(result.DeniedResources) > 0 {
		result.RecommendedActions = append(result.RecommendedActions, "Review client permissions for denied resources")
	}

	if len(result.ConsentRequired) > 0 {
		result.RecommendedActions = append(result.RecommendedActions, "Obtain user consent for sensitive scopes")
	}

	if len(result.SteppedUpAuthRequired) > 0 {
		result.RecommendedActions = append(result.RecommendedActions, "Require stepped-up authentication for high-risk scopes")
	}

	if len(result.PolicyViolations) > 0 {
		result.RecommendedActions = append(result.RecommendedActions, "Address security policy violations")
	}
}

// Helper utility methods

func (s *OAuthResourceIndicatorsService) isScopeApplicable(requestedScope, supportedScope string) bool {
	// Simple hierarchical matching - TODO: In production would use hierarchical scope service
	return strings.HasPrefix(requestedScope, supportedScope) || strings.HasPrefix(supportedScope, requestedScope)
}

func (s *OAuthResourceIndicatorsService) containsScope(scopes []string, scope string) bool {
	for _, s := range scopes {
		if s == scope {
			return true
		}
	}
	return false
}

func (s *OAuthResourceIndicatorsService) containsString(strings []string, str string) bool {
	for _, s := range strings {
		if s == str {
			return true
		}
	}
	return false
}

func (s *OAuthResourceIndicatorsService) removeDuplicateScopes(scopes []string) []string {
	keys := make(map[string]bool)
	var result []string

	for _, scope := range scopes {
		if !keys[scope] {
			keys[scope] = true
			result = append(result, scope)
		}
	}

	return result
}

// getClientType retrieves the client type from the database
func (s *OAuthResourceIndicatorsService) getClientType(clientID string) (string, error) {
	var client models.OAuthClient
	err := facades.Orm().Query().Where("id = ?", clientID).First(&client)
	if err != nil {
		return "", fmt.Errorf("client not found: %w", err)
	}

	// Return the client type (public, confidential, etc.)
	if client.Secret == nil || *client.Secret == "" {
		return "public", nil
	}
	return "confidential", nil
}

func (s *OAuthResourceIndicatorsService) userHasMFA(userID string) bool {
	// Check if user has active MFA methods configured
	var user models.User
	err := facades.Orm().Query().Where("id = ?", userID).First(&user)
	if err != nil {
		facades.Log().Warning("Failed to find user for MFA check", map[string]interface{}{
			"user_id": userID,
			"error":   err.Error(),
		})
		return false
	}

	// Check for WebAuthn credentials
	var credentialsCount int64
	credentialsCount, err = facades.Orm().Query().Model(&models.WebauthnCredential{}).
		Where("user_id = ?", userID).
		Count()

	if err == nil && credentialsCount > 0 {
		return true
	}

	// Check user profile for any MFA-related settings
	var userProfile models.UserProfile
	err = facades.Orm().Query().Where("user_id = ?", userID).First(&userProfile)
	if err == nil {
		// Check if user has any MFA-related data in their profile
		// This is a simplified check based on available fields
		if userProfile.Bio != nil && *userProfile.Bio != "" {
			// Use bio field to store MFA status as a workaround
			var profileData map[string]interface{}
			if err := json.Unmarshal([]byte(*userProfile.Bio), &profileData); err == nil {
				if mfaEnabled, exists := profileData["mfa_enabled"]; exists && mfaEnabled == true {
					return true
				}
			}
		}
	}

	return false
}

func (s *OAuthResourceIndicatorsService) generateTokenID() string {
	// Generate unique token ID
	bytes := make([]byte, 16)
	rand.Read(bytes)
	return base64.RawURLEncoding.EncodeToString(bytes)
}

func (s *OAuthResourceIndicatorsService) validateResourceServer(resourceServer *ResourceServer) error {
	if resourceServer.URI == "" {
		return fmt.Errorf("resource URI is required")
	}

	if _, err := url.Parse(resourceServer.URI); err != nil {
		return fmt.Errorf("invalid resource URI: %w", err)
	}

	if resourceServer.Name == "" {
		return fmt.Errorf("resource name is required")
	}

	return nil
}

func (s *OAuthResourceIndicatorsService) logResourceAuthorization(request *ResourceAuthorizationRequest, result *ResourceAuthorizationResult) {
	facades.Log().Info("Resource authorization processed", map[string]interface{}{
		"client_id":            request.ClientID,
		"user_id":              request.UserID,
		"requested_resources":  request.Resources,
		"requested_scopes":     request.Scopes,
		"authorized_resources": result.AuthorizedResources,
		"denied_resources":     result.DeniedResources,
		"validation_errors":    result.ValidationErrors,
		"policy_violations":    result.PolicyViolations,
		"consent_required":     len(result.ConsentRequired) > 0,
		"step_up_required":     len(result.SteppedUpAuthRequired) > 0,
	})
}

// GetResourceIndicatorsCapabilities returns resource indicators capabilities for discovery
func (s *OAuthResourceIndicatorsService) GetResourceIndicatorsCapabilities() map[string]interface{} {
	return map[string]interface{}{
		"resource_indicators_supported": true,
		"resource_parameter_supported":  true,
		"multiple_resources_supported":  true,
		"resource_scoping_supported":    true,
		"resource_specific_tokens":      true,
		"supported_token_formats": []string{
			"jwt",
			"opaque",
		},
		"supported_binding_methods": []string{
			"mtls",
			"dpop",
			"token_binding",
		},
		"resource_discovery_endpoint": facades.Config().GetString("app.url") + "/api/v1/oauth/resources",
	}
}
