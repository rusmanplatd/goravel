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
	return &OAuthTokenBindingService{
		oauthService: NewOAuthService(),
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
	// DPoP validation would be more complex in production
	if boundToken.TokenBindingKeyHash != bindingInfo.TokenBindingKeyHash {
		result.ValidationErrors = append(result.ValidationErrors, "DPoP key thumbprint mismatch")
		return fmt.Errorf("DPoP key thumbprint mismatch")
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
	// In production, this would store in database
	// For now, use cache with TTL
	key := fmt.Sprintf("bound_token_%s", boundToken.TokenID)
	ttl := time.Until(boundToken.ExpiresAt)

	data, err := json.Marshal(boundToken)
	if err != nil {
		return fmt.Errorf("failed to marshal bound token: %w", err)
	}

	facades.Cache().Put(key, string(data), ttl)
	return nil
}

func (s *OAuthTokenBindingService) getBoundToken(tokenID string) (*BoundToken, error) {
	key := fmt.Sprintf("bound_token_%s", tokenID)
	data := facades.Cache().Get(key)
	if data == nil {
		return nil, fmt.Errorf("bound token not found")
	}

	var boundToken BoundToken
	if err := json.Unmarshal([]byte(data.(string)), &boundToken); err != nil {
		return nil, fmt.Errorf("failed to unmarshal bound token: %w", err)
	}

	return &boundToken, nil
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
	// In production, this would clean up database records
	// For cache-based storage, expired entries are automatically cleaned up
	facades.Log().Info("Token binding cleanup completed")
	return nil
}
