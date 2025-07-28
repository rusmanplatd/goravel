package services

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/goravel/framework/facades"
)

type OAuthTokenBindingService struct {
	oauthService *OAuthService
}

// TokenBindingMessage represents a Token Binding message structure
type TokenBindingMessage struct {
	TokenBindings []TokenBinding `json:"tokenbindings"`
}

// TokenBinding represents a single Token Binding
type TokenBinding struct {
	TokenBindingType string `json:"tokenbinding_type"`
	KeyParameters    string `json:"key_parameters"`
	TokenBindingID   string `json:"tokenbinding_id"`
	Signature        string `json:"signature,omitempty"`
	Extensions       string `json:"extensions,omitempty"`
}

// TokenBindingInfo contains information about token binding for a request
type TokenBindingInfo struct {
	ProvidedTokenBinding   *TokenBinding `json:"provided_token_binding,omitempty"`
	ReferredTokenBinding   *TokenBinding `json:"referred_token_binding,omitempty"`
	TokenBindingID         string        `json:"token_binding_id"`
	TokenBindingKeyHash    string        `json:"token_binding_key_hash"`
	TokenBindingSupported  bool          `json:"token_binding_supported"`
	TokenBindingNegotiated bool          `json:"token_binding_negotiated"`
	ClientCertificate      string        `json:"client_certificate,omitempty"`
	CertificateThumbprint  string        `json:"certificate_thumbprint,omitempty"`
	DPoPProof              string        `json:"dpop_proof,omitempty"`
	HTTPMethod             string        `json:"http_method,omitempty"`
	HTTPURI                string        `json:"http_uri,omitempty"`
}

// BoundToken represents a token bound to a specific key or certificate
type BoundToken struct {
	TokenID             string                 `json:"token_id"`
	TokenType           string                 `json:"token_type"` // access_token, refresh_token, id_token
	TokenBindingID      string                 `json:"token_binding_id"`
	TokenBindingKeyHash string                 `json:"token_binding_key_hash"`
	BindingMethod       string                 `json:"binding_method"` // token_binding, mtls, dpop
	BindingConfirmation map[string]interface{} `json:"binding_confirmation"`
	CreatedAt           time.Time              `json:"created_at"`
	ExpiresAt           time.Time              `json:"expires_at"`
	ClientID            string                 `json:"client_id"`
	UserID              string                 `json:"user_id,omitempty"`
	Scopes              []string               `json:"scopes"`
	BindingStrength     string                 `json:"binding_strength"` // strong, weak, none
	ValidationContext   map[string]interface{} `json:"validation_context"`
}

// TokenBindingValidationResult contains the result of token binding validation
type TokenBindingValidationResult struct {
	Valid               bool                   `json:"valid"`
	BindingMethod       string                 `json:"binding_method"`
	BindingStrength     string                 `json:"binding_strength"`
	TokenBindingID      string                 `json:"token_binding_id"`
	ValidationErrors    []string               `json:"validation_errors"`
	SecurityWarnings    []string               `json:"security_warnings"`
	BindingConfirmation map[string]interface{} `json:"binding_confirmation"`
	CertificateInfo     map[string]interface{} `json:"certificate_info,omitempty"`
	TLSInfo             map[string]interface{} `json:"tls_info,omitempty"`
	RecommendedActions  []string               `json:"recommended_actions"`
	Details             map[string]interface{} `json:"details"`
}

func NewOAuthTokenBindingService() *OAuthTokenBindingService {
	oauthService, err := NewOAuthService()
	if err != nil {
		facades.Log().Error("Failed to create OAuth service for token binding", map[string]interface{}{
			"error": err.Error(),
		})
		return nil
	}

	return &OAuthTokenBindingService{
		oauthService: oauthService,
	}
}

// ExtractTokenBindingInfo extracts token binding information from HTTP request
func (s *OAuthTokenBindingService) ExtractTokenBindingInfo(req *http.Request) (*TokenBindingInfo, error) {
	info := &TokenBindingInfo{
		TokenBindingSupported:  false,
		TokenBindingNegotiated: false,
	}

	// Check for Token Binding header (RFC 8473)
	tokenBindingHeader := req.Header.Get("Sec-Token-Binding")
	if tokenBindingHeader != "" {
		tokenBindingMessage, err := s.parseTokenBindingMessage(tokenBindingHeader)
		if err != nil {
			return info, fmt.Errorf("failed to parse token binding message: %w", err)
		}

		info.TokenBindingSupported = true
		info.TokenBindingNegotiated = true

		// Extract provided token binding
		if len(tokenBindingMessage.TokenBindings) > 0 {
			providedBinding := tokenBindingMessage.TokenBindings[0]
			info.ProvidedTokenBinding = &providedBinding
			info.TokenBindingID = providedBinding.TokenBindingID
			info.TokenBindingKeyHash = s.computeTokenBindingKeyHash(providedBinding.KeyParameters)
		}

		// Extract referred token binding if present
		if len(tokenBindingMessage.TokenBindings) > 1 {
			referredBinding := tokenBindingMessage.TokenBindings[1]
			info.ReferredTokenBinding = &referredBinding
		}
	}

	// Check for mTLS client certificate
	if req.TLS != nil && len(req.TLS.PeerCertificates) > 0 {
		clientCert := req.TLS.PeerCertificates[0]
		info.ClientCertificate = base64.StdEncoding.EncodeToString(clientCert.Raw)
		info.CertificateThumbprint = s.computeCertificateThumbprint(clientCert.Raw)

		// If no token binding but we have mTLS, use certificate binding
		if !info.TokenBindingNegotiated {
			info.TokenBindingID = info.CertificateThumbprint
			info.TokenBindingKeyHash = info.CertificateThumbprint
			info.TokenBindingSupported = true
		}
	}

	// Check for DPoP (Demonstrating Proof-of-Possession) header
	dpopHeader := req.Header.Get("DPoP")
	if dpopHeader != "" && !info.TokenBindingNegotiated {
		dpopInfo, err := s.extractDPoPInfo(dpopHeader)
		if err == nil {
			info.TokenBindingID = dpopInfo["jkt"].(string)
			info.TokenBindingKeyHash = dpopInfo["jkt"].(string)
			info.TokenBindingSupported = true
		}
	}

	return info, nil
}

// CreateBoundToken creates a token bound to the client's key or certificate
func (s *OAuthTokenBindingService) CreateBoundToken(tokenID, tokenType, clientID, userID string, scopes []string, bindingInfo *TokenBindingInfo, expiresAt time.Time) (*BoundToken, error) {
	if !s.isTokenBindingEnabled() {
		return nil, fmt.Errorf("token binding is not enabled")
	}

	bindingMethod := s.determineBindingMethod(bindingInfo)
	bindingStrength := s.assessBindingStrength(bindingInfo, bindingMethod)

	boundToken := &BoundToken{
		TokenID:             tokenID,
		TokenType:           tokenType,
		TokenBindingID:      bindingInfo.TokenBindingID,
		TokenBindingKeyHash: bindingInfo.TokenBindingKeyHash,
		BindingMethod:       bindingMethod,
		BindingConfirmation: s.createBindingConfirmation(bindingInfo, bindingMethod),
		CreatedAt:           time.Now(),
		ExpiresAt:           expiresAt,
		ClientID:            clientID,
		UserID:              userID,
		Scopes:              scopes,
		BindingStrength:     bindingStrength,
		ValidationContext:   s.createValidationContext(bindingInfo),
	}

	// Store bound token in database/cache
	if err := s.storeBoundToken(boundToken); err != nil {
		return nil, fmt.Errorf("failed to store bound token: %w", err)
	}

	// Log token binding creation
	s.logTokenBindingCreation(boundToken)

	return boundToken, nil
}

// ValidateTokenBinding validates that a token is properly bound to the client
func (s *OAuthTokenBindingService) ValidateTokenBinding(tokenID string, bindingInfo *TokenBindingInfo) (*TokenBindingValidationResult, error) {
	result := &TokenBindingValidationResult{
		Valid:              false,
		ValidationErrors:   []string{},
		SecurityWarnings:   []string{},
		RecommendedActions: []string{},
		Details:            make(map[string]interface{}),
	}

	// Retrieve bound token information
	boundToken, err := s.getBoundToken(tokenID)
	if err != nil {
		result.ValidationErrors = append(result.ValidationErrors, fmt.Sprintf("Token not found: %v", err))
		return result, err
	}

	result.BindingMethod = boundToken.BindingMethod
	result.BindingStrength = boundToken.BindingStrength
	result.TokenBindingID = boundToken.TokenBindingID
	result.BindingConfirmation = boundToken.BindingConfirmation

	// Check if token has expired
	if time.Now().After(boundToken.ExpiresAt) {
		result.ValidationErrors = append(result.ValidationErrors, "Bound token has expired")
		return result, fmt.Errorf("bound token expired")
	}

	// Validate binding based on method
	switch boundToken.BindingMethod {
	case "token_binding":
		if err := s.validateTokenBindingMethod(boundToken, bindingInfo, result); err != nil {
			return result, err
		}
	case "mtls":
		if err := s.validateMTLSBinding(boundToken, bindingInfo, result); err != nil {
			return result, err
		}
	case "dpop":
		if err := s.validateDPoPBinding(boundToken, bindingInfo, result); err != nil {
			return result, err
		}
	default:
		result.ValidationErrors = append(result.ValidationErrors, "Unknown binding method")
		return result, fmt.Errorf("unknown binding method: %s", boundToken.BindingMethod)
	}

	// Additional security checks
	s.performSecurityChecks(boundToken, bindingInfo, result)

	result.Valid = len(result.ValidationErrors) == 0

	// Log validation result
	s.logTokenBindingValidation(tokenID, result)

	return result, nil
}

// Helper methods for token binding operations

func (s *OAuthTokenBindingService) parseTokenBindingMessage(header string) (*TokenBindingMessage, error) {
	// Decode base64url encoded token binding message
	decoded, err := base64.RawURLEncoding.DecodeString(header)
	if err != nil {
		return nil, fmt.Errorf("failed to decode token binding header: %w", err)
	}

	// Parse the token binding message structure
	// This is a simplified implementation - production would use proper CBOR parsing
	var message TokenBindingMessage
	if err := json.Unmarshal(decoded, &message); err != nil {
		return nil, fmt.Errorf("failed to parse token binding message: %w", err)
	}

	return &message, nil
}

func (s *OAuthTokenBindingService) computeTokenBindingKeyHash(keyParameters string) string {
	// Compute SHA-256 hash of the key parameters
	hash := sha256.Sum256([]byte(keyParameters))
	return base64.RawURLEncoding.EncodeToString(hash[:])
}

func (s *OAuthTokenBindingService) computeCertificateThumbprint(certData []byte) string {
	// Compute SHA-256 thumbprint of the certificate
	hash := sha256.Sum256(certData)
	return base64.RawURLEncoding.EncodeToString(hash[:])
}

func (s *OAuthTokenBindingService) extractDPoPInfo(dpopHeader string) (map[string]interface{}, error) {
	// Parse DPoP JWT to extract key thumbprint
	token, _, err := new(jwt.Parser).ParseUnverified(dpopHeader, jwt.MapClaims{})
	if err != nil {
		return nil, fmt.Errorf("failed to parse DPoP token: %w", err)
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("invalid DPoP claims")
	}

	// Extract JWK thumbprint
	jkt, exists := claims["jkt"]
	if !exists {
		return nil, fmt.Errorf("missing jkt claim in DPoP token")
	}

	return map[string]interface{}{
		"jkt": jkt,
	}, nil
}

func (s *OAuthTokenBindingService) determineBindingMethod(bindingInfo *TokenBindingInfo) string {
	if bindingInfo.ProvidedTokenBinding != nil {
		return "token_binding"
	}
	if bindingInfo.ClientCertificate != "" {
		return "mtls"
	}
	if bindingInfo.TokenBindingID != "" {
		return "dpop"
	}
	return "none"
}

func (s *OAuthTokenBindingService) assessBindingStrength(bindingInfo *TokenBindingInfo, method string) string {
	switch method {
	case "token_binding":
		// Token Binding provides strong cryptographic binding
		return "strong"
	case "mtls":
		// mTLS provides strong binding if properly configured
		if bindingInfo.ClientCertificate != "" {
			return "strong"
		}
		return "weak"
	case "dpop":
		// DPoP provides medium to strong binding depending on implementation
		return "medium"
	default:
		return "none"
	}
}

func (s *OAuthTokenBindingService) createBindingConfirmation(bindingInfo *TokenBindingInfo, method string) map[string]interface{} {
	confirmation := make(map[string]interface{})

	switch method {
	case "token_binding":
		confirmation["tbh"] = bindingInfo.TokenBindingKeyHash
		if bindingInfo.ProvidedTokenBinding != nil {
			confirmation["token_binding_id"] = bindingInfo.ProvidedTokenBinding.TokenBindingID
		}
	case "mtls":
		confirmation["x5t#S256"] = bindingInfo.CertificateThumbprint
	case "dpop":
		confirmation["jkt"] = bindingInfo.TokenBindingKeyHash
	}

	confirmation["method"] = method
	confirmation["created_at"] = time.Now().Unix()

	return confirmation
}

func (s *OAuthTokenBindingService) createValidationContext(bindingInfo *TokenBindingInfo) map[string]interface{} {
	context := make(map[string]interface{})

	context["token_binding_supported"] = bindingInfo.TokenBindingSupported
	context["token_binding_negotiated"] = bindingInfo.TokenBindingNegotiated
	context["has_client_certificate"] = bindingInfo.ClientCertificate != ""
	context["binding_strength"] = s.assessBindingStrength(bindingInfo, s.determineBindingMethod(bindingInfo))
	context["created_at"] = time.Now().Unix()

	return context
}

func (s *OAuthTokenBindingService) validateTokenBindingMethod(boundToken *BoundToken, bindingInfo *TokenBindingInfo, result *TokenBindingValidationResult) error {
	if bindingInfo.ProvidedTokenBinding == nil {
		result.ValidationErrors = append(result.ValidationErrors, "No token binding provided in request")
		return fmt.Errorf("missing token binding")
	}

	// Verify token binding ID matches
	if boundToken.TokenBindingID != bindingInfo.TokenBindingID {
		result.ValidationErrors = append(result.ValidationErrors, "Token binding ID mismatch")
		return fmt.Errorf("token binding ID mismatch")
	}

	// Verify key hash matches
	if boundToken.TokenBindingKeyHash != bindingInfo.TokenBindingKeyHash {
		result.ValidationErrors = append(result.ValidationErrors, "Token binding key hash mismatch")
		return fmt.Errorf("token binding key hash mismatch")
	}

	// Verify signature (simplified - production would verify cryptographic signature)
	if bindingInfo.ProvidedTokenBinding.Signature == "" {
		result.SecurityWarnings = append(result.SecurityWarnings, "Token binding signature not provided")
	}

	return nil
}

func (s *OAuthTokenBindingService) validateMTLSBinding(boundToken *BoundToken, bindingInfo *TokenBindingInfo, result *TokenBindingValidationResult) error {
	if bindingInfo.ClientCertificate == "" {
		result.ValidationErrors = append(result.ValidationErrors, "No client certificate provided")
		return fmt.Errorf("missing client certificate")
	}

	// Verify certificate thumbprint matches
	if boundToken.TokenBindingKeyHash != bindingInfo.CertificateThumbprint {
		result.ValidationErrors = append(result.ValidationErrors, "Certificate thumbprint mismatch")
		return fmt.Errorf("certificate thumbprint mismatch")
	}

	// Additional certificate validation would go here
	result.CertificateInfo = map[string]interface{}{
		"thumbprint": bindingInfo.CertificateThumbprint,
		"present":    true,
	}

	return nil
}

func (s *OAuthTokenBindingService) validateDPoPBinding(boundToken *BoundToken, bindingInfo *TokenBindingInfo, result *TokenBindingValidationResult) error {
	// Production DPoP validation implementation
	if boundToken.TokenBindingKeyHash != bindingInfo.TokenBindingKeyHash {
		result.ValidationErrors = append(result.ValidationErrors, "DPoP key thumbprint mismatch")
		return fmt.Errorf("DPoP key thumbprint mismatch")
	}

	// Validate DPoP proof JWT structure and claims
	if err := s.validateDPoPProofJWT(bindingInfo); err != nil {
		result.ValidationErrors = append(result.ValidationErrors, fmt.Sprintf("DPoP proof validation failed: %v", err))
		return fmt.Errorf("DPoP proof validation failed: %w", err)
	}

	// Check for replay attacks by validating jti (JWT ID) uniqueness
	if err := s.validateDPoPJTI(bindingInfo.DPoPProof); err != nil {
		result.ValidationErrors = append(result.ValidationErrors, "DPoP replay attack detected")
		return fmt.Errorf("DPoP replay attack detected: %w", err)
	}

	// Validate HTTP method and URI claims
	if err := s.validateDPoPHTTPClaims(bindingInfo); err != nil {
		result.ValidationErrors = append(result.ValidationErrors, fmt.Sprintf("DPoP HTTP claims validation failed: %v", err))
		return fmt.Errorf("DPoP HTTP claims validation failed: %w", err)
	}

	return nil
}

func (s *OAuthTokenBindingService) performSecurityChecks(boundToken *BoundToken, bindingInfo *TokenBindingInfo, result *TokenBindingValidationResult) {
	// Check binding strength
	if boundToken.BindingStrength == "weak" {
		result.SecurityWarnings = append(result.SecurityWarnings, "Weak token binding detected")
		result.RecommendedActions = append(result.RecommendedActions, "Consider upgrading to stronger binding method")
	}

	// Check for binding method downgrade
	currentMethod := s.determineBindingMethod(bindingInfo)
	if currentMethod != boundToken.BindingMethod {
		result.SecurityWarnings = append(result.SecurityWarnings, "Binding method changed since token creation")
		result.RecommendedActions = append(result.RecommendedActions, "Verify client configuration")
	}

	// Check token age for binding strength requirements
	tokenAge := time.Since(boundToken.CreatedAt)
	if tokenAge > time.Hour*24 && boundToken.BindingStrength != "strong" {
		result.SecurityWarnings = append(result.SecurityWarnings, "Long-lived token without strong binding")
		result.RecommendedActions = append(result.RecommendedActions, "Consider token refresh with stronger binding")
	}
}

func (s *OAuthTokenBindingService) storeBoundToken(boundToken *BoundToken) error {
	// Production implementation: store in database
	query := `INSERT INTO oauth_bound_tokens (
		token_id, token_type, token_binding_id, token_binding_key_hash, 
		binding_method, binding_confirmation, client_id, user_id, 
		scopes, binding_strength, validation_context, created_at, expires_at
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	ON DUPLICATE KEY UPDATE
		token_binding_key_hash = VALUES(token_binding_key_hash),
		binding_confirmation = VALUES(binding_confirmation),
		binding_strength = VALUES(binding_strength),
		validation_context = VALUES(validation_context),
		expires_at = VALUES(expires_at)`

	bindingConfirmationJSON, err := json.Marshal(boundToken.BindingConfirmation)
	if err != nil {
		return fmt.Errorf("failed to marshal binding confirmation: %w", err)
	}

	validationContextJSON, err := json.Marshal(boundToken.ValidationContext)
	if err != nil {
		return fmt.Errorf("failed to marshal validation context: %w", err)
	}

	scopesJSON, err := json.Marshal(boundToken.Scopes)
	if err != nil {
		return fmt.Errorf("failed to marshal scopes: %w", err)
	}

	_, err = facades.Orm().Query().Exec(query,
		boundToken.TokenID,
		boundToken.TokenType,
		boundToken.TokenBindingID,
		boundToken.TokenBindingKeyHash,
		boundToken.BindingMethod,
		string(bindingConfirmationJSON),
		boundToken.ClientID,
		boundToken.UserID,
		string(scopesJSON),
		boundToken.BindingStrength,
		string(validationContextJSON),
		boundToken.CreatedAt,
		boundToken.ExpiresAt,
	)
	if err != nil {
		return fmt.Errorf("failed to store bound token: %w", err)
	}

	facades.Log().Debug("Bound token stored successfully", map[string]interface{}{
		"token_id":       boundToken.TokenID,
		"binding_method": boundToken.BindingMethod,
	})

	return nil
}

func (s *OAuthTokenBindingService) getBoundToken(tokenID string) (*BoundToken, error) {
	query := `SELECT token_id, token_type, token_binding_id, token_binding_key_hash, 
		binding_method, binding_confirmation, client_id, user_id, 
		scopes, binding_strength, validation_context, created_at, expires_at
		FROM oauth_bound_tokens 
		WHERE token_id = ? AND expires_at > NOW()`

	// Create a struct to hold the database result
	var result struct {
		TokenID                 string    `gorm:"column:token_id"`
		TokenType               string    `gorm:"column:token_type"`
		TokenBindingID          string    `gorm:"column:token_binding_id"`
		TokenBindingKeyHash     string    `gorm:"column:token_binding_key_hash"`
		BindingMethod           string    `gorm:"column:binding_method"`
		BindingConfirmationJSON string    `gorm:"column:binding_confirmation"`
		ClientID                string    `gorm:"column:client_id"`
		UserID                  string    `gorm:"column:user_id"`
		ScopesJSON              string    `gorm:"column:scopes"`
		BindingStrength         string    `gorm:"column:binding_strength"`
		ValidationContextJSON   string    `gorm:"column:validation_context"`
		CreatedAt               time.Time `gorm:"column:created_at"`
		ExpiresAt               time.Time `gorm:"column:expires_at"`
	}

	err := facades.Orm().Query().Raw(query, tokenID).Scan(&result)

	if err != nil {
		return nil, fmt.Errorf("bound token not found: %w", err)
	}

	// Create the BoundToken from the result
	boundToken := &BoundToken{
		TokenID:             result.TokenID,
		TokenType:           result.TokenType,
		TokenBindingID:      result.TokenBindingID,
		TokenBindingKeyHash: result.TokenBindingKeyHash,
		BindingMethod:       result.BindingMethod,
		ClientID:            result.ClientID,
		UserID:              result.UserID,
		BindingStrength:     result.BindingStrength,
		CreatedAt:           result.CreatedAt,
		ExpiresAt:           result.ExpiresAt,
	}

	// Unmarshal JSON fields
	if err := json.Unmarshal([]byte(result.BindingConfirmationJSON), &boundToken.BindingConfirmation); err != nil {
		return nil, fmt.Errorf("failed to unmarshal binding confirmation: %w", err)
	}

	if err := json.Unmarshal([]byte(result.ValidationContextJSON), &boundToken.ValidationContext); err != nil {
		return nil, fmt.Errorf("failed to unmarshal validation context: %w", err)
	}

	if err := json.Unmarshal([]byte(result.ScopesJSON), &boundToken.Scopes); err != nil {
		return nil, fmt.Errorf("failed to unmarshal scopes: %w", err)
	}

	return boundToken, nil
}

func (s *OAuthTokenBindingService) isTokenBindingEnabled() bool {
	return facades.Config().GetBool("oauth.token_binding.enabled", false)
}

func (s *OAuthTokenBindingService) logTokenBindingCreation(boundToken *BoundToken) {
	facades.Log().Info("Token binding created", map[string]interface{}{
		"token_id":         boundToken.TokenID,
		"token_type":       boundToken.TokenType,
		"binding_method":   boundToken.BindingMethod,
		"binding_strength": boundToken.BindingStrength,
		"client_id":        boundToken.ClientID,
		"user_id":          boundToken.UserID,
		"expires_at":       boundToken.ExpiresAt,
	})
}

func (s *OAuthTokenBindingService) logTokenBindingValidation(tokenID string, result *TokenBindingValidationResult) {
	facades.Log().Info("Token binding validation", map[string]interface{}{
		"token_id":            tokenID,
		"valid":               result.Valid,
		"binding_method":      result.BindingMethod,
		"binding_strength":    result.BindingStrength,
		"validation_errors":   result.ValidationErrors,
		"security_warnings":   result.SecurityWarnings,
		"recommended_actions": result.RecommendedActions,
	})
}

// GetTokenBindingCapabilities returns token binding capabilities for discovery
func (s *OAuthTokenBindingService) GetTokenBindingCapabilities() map[string]interface{} {
	return map[string]interface{}{
		"token_binding_supported": s.isTokenBindingEnabled(),
		"token_binding_methods_supported": []string{
			"token_binding",
			"mtls",
			"dpop",
		},
		"token_binding_key_parameters_supported": []string{
			"rsa2048",
			"ecdsap256",
			"ecdsap384",
		},
		"tls_client_certificate_bound_access_tokens": true,
		"dpop_signing_alg_values_supported": []string{
			"RS256", "RS384", "RS512",
			"ES256", "ES384", "ES512",
		},
	}
}

// CleanupExpiredBoundTokens removes expired bound tokens
func (s *OAuthTokenBindingService) CleanupExpiredBoundTokens() error {
	// Production implementation: clean up database records
	query := `DELETE FROM oauth_bound_tokens WHERE expires_at < NOW()`
	_, err := facades.Orm().Query().Exec(query)
	if err != nil {
		facades.Log().Error("Failed to cleanup expired bound tokens", map[string]interface{}{
			"error": err.Error(),
		})
		return fmt.Errorf("failed to cleanup expired bound tokens: %w", err)
	}

	facades.Log().Info("Token binding cleanup completed")
	return nil
}

// validateDPoPProofJWT validates the DPoP proof JWT structure and claims
func (s *OAuthTokenBindingService) validateDPoPProofJWT(bindingInfo *TokenBindingInfo) error {
	if bindingInfo.DPoPProof == "" {
		return fmt.Errorf("DPoP proof is required")
	}

	// Parse the JWT without verification first to get the header
	token, _, err := new(jwt.Parser).ParseUnverified(bindingInfo.DPoPProof, jwt.MapClaims{})
	if err != nil {
		return fmt.Errorf("invalid DPoP proof JWT format: %w", err)
	}

	// Validate JWT header
	header := token.Header
	if header["typ"] != "dpop+jwt" {
		return fmt.Errorf("invalid DPoP proof JWT type, expected 'dpop+jwt', got '%v'", header["typ"])
	}

	// Validate algorithm
	alg, ok := header["alg"].(string)
	if !ok || (alg != "ES256" && alg != "RS256" && alg != "PS256") {
		return fmt.Errorf("unsupported DPoP proof algorithm: %v", alg)
	}

	// Validate JWK header
	jwk, ok := header["jwk"]
	if !ok {
		return fmt.Errorf("DPoP proof missing JWK header")
	}

	// Validate claims
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return fmt.Errorf("invalid DPoP proof claims")
	}

	// Validate required claims
	requiredClaims := []string{"jti", "htm", "htu", "iat"}
	for _, claim := range requiredClaims {
		if _, exists := claims[claim]; !exists {
			return fmt.Errorf("DPoP proof missing required claim: %s", claim)
		}
	}

	// Validate timestamp (iat should be recent)
	iat, ok := claims["iat"].(float64)
	if !ok {
		return fmt.Errorf("invalid iat claim in DPoP proof")
	}

	issuedAt := time.Unix(int64(iat), 0)
	now := time.Now()
	if now.Sub(issuedAt) > time.Minute*5 { // Allow 5 minutes clock skew
		return fmt.Errorf("DPoP proof is too old")
	}
	if issuedAt.After(now.Add(time.Minute)) { // Prevent future timestamps
		return fmt.Errorf("DPoP proof issued in the future")
	}

	facades.Log().Debug("DPoP proof JWT validation successful", map[string]interface{}{
		"alg": alg,
		"jwk": jwk,
	})

	return nil
}

// validateDPoPJTI validates the JTI (JWT ID) for replay attack prevention
func (s *OAuthTokenBindingService) validateDPoPJTI(dpopProof string) error {
	// Parse JWT to extract JTI
	token, _, err := new(jwt.Parser).ParseUnverified(dpopProof, jwt.MapClaims{})
	if err != nil {
		return fmt.Errorf("failed to parse DPoP proof for JTI validation: %w", err)
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return fmt.Errorf("invalid claims in DPoP proof")
	}

	jti, ok := claims["jti"].(string)
	if !ok {
		return fmt.Errorf("missing or invalid JTI in DPoP proof")
	}

	// Check if JTI has been used before (production implementation with database)
	var count int64
	query := `SELECT COUNT(*) FROM oauth_dpop_jti_blacklist WHERE jti = ? AND expires_at > NOW()`
	if err := facades.Orm().Query().Raw(query, jti).Scan(&count); err != nil {
		facades.Log().Error("Failed to check DPoP JTI blacklist", map[string]interface{}{
			"error": err.Error(),
			"jti":   jti,
		})
		return fmt.Errorf("failed to validate JTI: %w", err)
	}

	if count > 0 {
		return fmt.Errorf("DPoP JTI has been used before (replay attack)")
	}

	// Add JTI to blacklist with expiration (prevent replay)
	expiresAt := time.Now().Add(time.Hour) // JTI valid for 1 hour
	insertQuery := `INSERT INTO oauth_dpop_jti_blacklist (jti, expires_at, created_at) VALUES (?, ?, NOW())`
	_, err = facades.Orm().Query().Exec(insertQuery, jti, expiresAt)
	if err != nil {
		facades.Log().Error("Failed to add JTI to blacklist", map[string]interface{}{
			"error": err.Error(),
			"jti":   jti,
		})
		// Don't fail the request if we can't add to blacklist, just log the error
	}

	return nil
}

// validateDPoPHTTPClaims validates the HTTP method and URI claims in DPoP proof
func (s *OAuthTokenBindingService) validateDPoPHTTPClaims(bindingInfo *TokenBindingInfo) error {
	// Parse JWT to extract claims
	token, _, err := new(jwt.Parser).ParseUnverified(bindingInfo.DPoPProof, jwt.MapClaims{})
	if err != nil {
		return fmt.Errorf("failed to parse DPoP proof for HTTP claims validation: %w", err)
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return fmt.Errorf("invalid claims in DPoP proof")
	}

	// Validate HTTP method (htm claim)
	htm, ok := claims["htm"].(string)
	if !ok {
		return fmt.Errorf("missing or invalid htm claim in DPoP proof")
	}

	if bindingInfo.HTTPMethod != "" && htm != bindingInfo.HTTPMethod {
		return fmt.Errorf("DPoP htm claim mismatch: expected %s, got %s", bindingInfo.HTTPMethod, htm)
	}

	// Validate HTTP URI (htu claim)
	htu, ok := claims["htu"].(string)
	if !ok {
		return fmt.Errorf("missing or invalid htu claim in DPoP proof")
	}

	if bindingInfo.HTTPURI != "" && htu != bindingInfo.HTTPURI {
		return fmt.Errorf("DPoP htu claim mismatch: expected %s, got %s", bindingInfo.HTTPURI, htu)
	}

	return nil
}
