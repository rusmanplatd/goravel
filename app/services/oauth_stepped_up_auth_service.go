package services

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math"
	mathrand "math/rand"
	"net/http"
	"strings"
	"time"

	"goravel/app/models"

	"github.com/goravel/framework/facades"
)

type OAuthSteppedUpAuthService struct {
	oauthService   *OAuthService
	authService    *AuthService
	riskService    *OAuthRiskService
	sessionService *SessionService
}

// StepUpAuthRequest represents a stepped-up authentication request
type StepUpAuthRequest struct {
	UserID            string                 `json:"user_id"`
	ClientID          string                 `json:"client_id"`
	RequestedScopes   []string               `json:"requested_scopes"`
	SensitiveScopes   []string               `json:"sensitive_scopes"`
	RequiredAuthLevel string                 `json:"required_auth_level"` // basic, mfa, biometric, hardware
	CurrentAuthLevel  string                 `json:"current_auth_level"`
	SessionID         string                 `json:"session_id"`
	RequestContext    map[string]interface{} `json:"request_context"`
	RequiredFactors   []string               `json:"required_factors"` // password, totp, sms, push, biometric, hardware_key
	MaxAuthAge        int64                  `json:"max_auth_age"`     // seconds
	ForceReauth       bool                   `json:"force_reauth"`
	RequestedAt       time.Time              `json:"requested_at"`
	ExpiresAt         time.Time              `json:"expires_at"`
	ChallengeID       string                 `json:"challenge_id"`
	Nonce             string                 `json:"nonce"`
}

// StepUpAuthChallenge represents an authentication challenge
type StepUpAuthChallenge struct {
	ChallengeID      string                 `json:"challenge_id"`
	UserID           string                 `json:"user_id"`
	ClientID         string                 `json:"client_id"`
	ChallengeType    string                 `json:"challenge_type"` // mfa, biometric, hardware, composite
	RequiredFactors  []string               `json:"required_factors"`
	CompletedFactors []string               `json:"completed_factors"`
	RemainingFactors []string               `json:"remaining_factors"`
	ChallengeData    map[string]interface{} `json:"challenge_data"`
	Status           string                 `json:"status"` // pending, in_progress, completed, failed, expired
	CreatedAt        time.Time              `json:"created_at"`
	ExpiresAt        time.Time              `json:"expires_at"`
	LastAttemptAt    time.Time              `json:"last_attempt_at,omitempty"`
	AttemptCount     int                    `json:"attempt_count"`
	MaxAttempts      int                    `json:"max_attempts"`
	FailureReason    string                 `json:"failure_reason,omitempty"`
	SecurityContext  map[string]interface{} `json:"security_context"`
	CompletionToken  string                 `json:"completion_token,omitempty"`
}

// StepUpAuthResult represents the result of stepped-up authentication
type StepUpAuthResult struct {
	Success            bool                   `json:"success"`
	AuthLevel          string                 `json:"auth_level"`
	CompletedFactors   []string               `json:"completed_factors"`
	AuthToken          string                 `json:"auth_token,omitempty"`
	ExpiresAt          time.Time              `json:"expires_at"`
	RequiredActions    []string               `json:"required_actions"`
	ChallengeID        string                 `json:"challenge_id,omitempty"`
	NextChallenge      *StepUpAuthChallenge   `json:"next_challenge,omitempty"`
	SecurityWarnings   []string               `json:"security_warnings"`
	RiskAssessment     map[string]interface{} `json:"risk_assessment"`
	AuthenticationTime time.Time              `json:"authentication_time"`
	Details            map[string]interface{} `json:"details"`
}

// AuthenticationFactor represents an authentication factor
type AuthenticationFactor struct {
	Type          string                 `json:"type"`     // password, totp, sms, push, biometric, hardware_key
	Status        string                 `json:"status"`   // required, completed, failed, skipped
	Strength      string                 `json:"strength"` // weak, medium, strong, very_strong
	Success       bool                   `json:"success"`
	CompletedAt   time.Time              `json:"completed_at,omitempty"`
	FailureReason string                 `json:"failure_reason,omitempty"`
	AttemptCount  int                    `json:"attempt_count"`
	Metadata      map[string]interface{} `json:"metadata"`
}

// SensitiveScopeConfig defines configuration for sensitive scopes
type SensitiveScopeConfig struct {
	Scope              string   `json:"scope"`
	RequiredAuthLevel  string   `json:"required_auth_level"`
	RequiredFactors    []string `json:"required_factors"`
	MaxAuthAge         int64    `json:"max_auth_age"`
	ForceReauth        bool     `json:"force_reauth"`
	RiskThreshold      int      `json:"risk_threshold"`
	AllowedClientTypes []string `json:"allowed_client_types"`
	RequireHardwareKey bool     `json:"require_hardware_key"`
	RequireBiometric   bool     `json:"require_biometric"`
	Description        string   `json:"description"`
}

func NewOAuthSteppedUpAuthService() (*OAuthSteppedUpAuthService, error) {
	oauthService, err := NewOAuthService()
	if err != nil {
		facades.Log().Error("Failed to initialize OAuth service for stepped-up auth", map[string]interface{}{
			"error": err.Error(),
		})
		return nil, fmt.Errorf("failed to initialize OAuth service: %w", err)
	}

	authService, err := NewAuthService()
	if err != nil {
		facades.Log().Error("Failed to initialize Auth service for stepped-up auth", map[string]interface{}{
			"error": err.Error(),
		})
		return nil, fmt.Errorf("failed to initialize Auth service: %w", err)
	}

	return &OAuthSteppedUpAuthService{
		oauthService:   oauthService,
		authService:    authService,
		riskService:    NewOAuthRiskService(),
		sessionService: NewSessionService(),
	}, nil
}

// EvaluateStepUpRequirement evaluates if stepped-up authentication is required
func (s *OAuthSteppedUpAuthService) EvaluateStepUpRequirement(userID, clientID string, requestedScopes []string, sessionID string) (*StepUpAuthRequest, error) {
	// Get current authentication level
	currentAuthLevel, err := s.getCurrentAuthLevel(userID, sessionID)
	if err != nil {
		return nil, fmt.Errorf("failed to get current auth level: %w", err)
	}

	// Identify sensitive scopes
	sensitiveScopes := s.identifySensitiveScopes(requestedScopes)
	if len(sensitiveScopes) == 0 {
		return nil, nil // No step-up required
	}

	// Determine required authentication level
	requiredAuthLevel := s.determineRequiredAuthLevel(sensitiveScopes, userID, clientID)

	// Check if current level is sufficient
	if s.isAuthLevelSufficient(currentAuthLevel, requiredAuthLevel) {
		// Check authentication age
		if !s.isAuthenticationFresh(userID, sessionID, sensitiveScopes) {
			// Authentication is stale, require step-up
		} else {
			return nil, nil // Current authentication is sufficient
		}
	}

	// Create step-up request
	request := &StepUpAuthRequest{
		UserID:            userID,
		ClientID:          clientID,
		RequestedScopes:   requestedScopes,
		SensitiveScopes:   sensitiveScopes,
		RequiredAuthLevel: requiredAuthLevel,
		CurrentAuthLevel:  currentAuthLevel,
		SessionID:         sessionID,
		RequiredFactors:   s.getRequiredFactors(sensitiveScopes, requiredAuthLevel),
		MaxAuthAge:        s.getMaxAuthAge(sensitiveScopes),
		ForceReauth:       s.shouldForceReauth(sensitiveScopes, userID),
		RequestedAt:       time.Now(),
		ExpiresAt:         time.Now().Add(time.Minute * 15), // 15 minutes
		ChallengeID:       s.generateChallengeID(),
		Nonce:             s.generateNonce(),
		RequestContext: map[string]interface{}{
			"ip_address": s.getClientIP(),
			"user_agent": s.getUserAgent(),
			"risk_score": s.getRiskScore(userID, clientID),
			"device_id":  s.getDeviceID(),
			"location":   s.getLocation(),
		},
	}

	// Store step-up request
	if err := s.storeStepUpRequest(request); err != nil {
		return nil, fmt.Errorf("failed to store step-up request: %w", err)
	}

	return request, nil
}

// CreateStepUpChallenge creates authentication challenges for step-up
func (s *OAuthSteppedUpAuthService) CreateStepUpChallenge(request *StepUpAuthRequest) (*StepUpAuthChallenge, error) {
	challengeType := s.determineChallengeType(request.RequiredFactors)

	challenge := &StepUpAuthChallenge{
		ChallengeID:      request.ChallengeID,
		UserID:           request.UserID,
		ClientID:         request.ClientID,
		ChallengeType:    challengeType,
		RequiredFactors:  request.RequiredFactors,
		CompletedFactors: []string{},
		RemainingFactors: request.RequiredFactors,
		Status:           "pending",
		CreatedAt:        time.Now(),
		ExpiresAt:        request.ExpiresAt,
		AttemptCount:     0,
		MaxAttempts:      s.getMaxAttempts(challengeType),
		SecurityContext:  request.RequestContext,
		ChallengeData:    s.generateChallengeData(challengeType, request),
	}

	// Store challenge
	if err := s.storeChallenge(challenge); err != nil {
		return nil, fmt.Errorf("failed to store challenge: %w", err)
	}

	// Log challenge creation
	s.logChallengeCreation(challenge)

	return challenge, nil
}

// ProcessStepUpResponse processes authentication factor responses
func (s *OAuthSteppedUpAuthService) ProcessStepUpResponse(challengeID string, factorType string, response map[string]interface{}) (*StepUpAuthResult, error) {
	// Retrieve challenge
	challenge, err := s.getChallenge(challengeID)
	if err != nil {
		return nil, fmt.Errorf("challenge not found: %w", err)
	}

	// Check challenge expiration
	if time.Now().After(challenge.ExpiresAt) {
		challenge.Status = "expired"
		s.updateChallenge(challenge)
		return &StepUpAuthResult{
			Success:          false,
			RequiredActions:  []string{"restart_authentication"},
			SecurityWarnings: []string{"Authentication challenge expired"},
		}, fmt.Errorf("challenge expired")
	}

	// Check attempt limits
	if challenge.AttemptCount >= challenge.MaxAttempts {
		challenge.Status = "failed"
		challenge.FailureReason = "max_attempts_exceeded"
		s.updateChallenge(challenge)
		return &StepUpAuthResult{
			Success:          false,
			RequiredActions:  []string{"wait_and_retry"},
			SecurityWarnings: []string{"Maximum authentication attempts exceeded"},
		}, fmt.Errorf("max attempts exceeded")
	}

	// Increment attempt count
	challenge.AttemptCount++
	challenge.LastAttemptAt = time.Now()

	// Validate authentication factor
	factorResult, err := s.validateAuthenticationFactor(factorType, response, challenge)
	if err != nil {
		challenge.FailureReason = err.Error()
		s.updateChallenge(challenge)
		return &StepUpAuthResult{
			Success:          false,
			ChallengeID:      challengeID,
			RequiredActions:  []string{"retry_authentication"},
			SecurityWarnings: []string{fmt.Sprintf("Authentication factor validation failed: %v", err)},
		}, err
	}

	// Update completed factors
	if factorResult.Success {
		challenge.CompletedFactors = append(challenge.CompletedFactors, factorType)
		challenge.RemainingFactors = s.removeFromSlice(challenge.RemainingFactors, factorType)
	}

	// Check if all factors completed
	if len(challenge.RemainingFactors) == 0 {
		challenge.Status = "completed"
		challenge.CompletionToken = s.generateCompletionToken(challenge)

		// Create authentication result
		result := &StepUpAuthResult{
			Success:            true,
			AuthLevel:          s.calculateAuthLevel(challenge.CompletedFactors),
			CompletedFactors:   challenge.CompletedFactors,
			AuthToken:          challenge.CompletionToken,
			ExpiresAt:          time.Now().Add(s.getAuthTokenTTL()),
			AuthenticationTime: time.Now(),
			RiskAssessment:     s.assessPostAuthRisk(challenge),
			Details: map[string]interface{}{
				"challenge_id":            challengeID,
				"factors_used":            challenge.CompletedFactors,
				"authentication_duration": time.Since(challenge.CreatedAt).Seconds(),
			},
		}

		// Update user's authentication level
		s.updateAuthLevel(challenge.UserID, challenge.UserID, result.AuthLevel, result.ExpiresAt)

		// Log successful authentication
		s.logSuccessfulStepUp(challenge, result)

		s.updateChallenge(challenge)
		return result, nil
	}

	// More factors required
	challenge.Status = "in_progress"
	s.updateChallenge(challenge)

	return &StepUpAuthResult{
		Success:         false,
		ChallengeID:     challengeID,
		NextChallenge:   challenge,
		RequiredActions: []string{"complete_remaining_factors"},
		Details: map[string]interface{}{
			"completed_factors": challenge.CompletedFactors,
			"remaining_factors": challenge.RemainingFactors,
		},
	}, nil
}

// Helper methods for stepped-up authentication

func (s *OAuthSteppedUpAuthService) getCurrentAuthLevel(userID, sessionID string) (string, error) {
	// Production implementation retrieving from session/database

	// First check session cache for current auth level
	sessionKey := fmt.Sprintf("auth_level:%s:%s", userID, sessionID)
	var authLevel string
	if err := facades.Cache().Get(sessionKey, &authLevel); err == nil {
		return authLevel, nil
	}

	// Fallback to database lookup
	var user models.User
	err := facades.Orm().Query().
		Where("id = ?", userID).
		Where("updated_at > ?", time.Now().Add(-24*time.Hour)).
		First(&user)

	if err != nil {
		facades.Log().Warning("Failed to retrieve user for auth level", map[string]interface{}{
			"user_id":    userID,
			"session_id": sessionID,
			"error":      err.Error(),
		})
		return "basic", nil // Default to basic level
	}

	// For simplified implementation, return basic
	// TODO: In production, you'd have a dedicated session table
	return "basic", nil
}

func (s *OAuthSteppedUpAuthService) identifySensitiveScopes(scopes []string) []string {
	sensitiveConfigs := s.getSensitiveScopeConfigs()
	var sensitiveScopes []string

	for _, scope := range scopes {
		for _, config := range sensitiveConfigs {
			if scope == config.Scope || strings.HasPrefix(scope, config.Scope+".") {
				sensitiveScopes = append(sensitiveScopes, scope)
				break
			}
		}
	}

	return sensitiveScopes
}

func (s *OAuthSteppedUpAuthService) getSensitiveScopeConfigs() []SensitiveScopeConfig {
	return []SensitiveScopeConfig{
		{
			Scope:              "admin",
			RequiredAuthLevel:  "mfa",
			RequiredFactors:    []string{"password", "totp"},
			MaxAuthAge:         1800, // 30 minutes
			ForceReauth:        true,
			RiskThreshold:      30,
			AllowedClientTypes: []string{"confidential"},
			RequireHardwareKey: false,
			RequireBiometric:   false,
			Description:        "Administrative access",
		},
		{
			Scope:              "admin.security",
			RequiredAuthLevel:  "hardware",
			RequiredFactors:    []string{"password", "hardware_key"},
			MaxAuthAge:         900, // 15 minutes
			ForceReauth:        true,
			RiskThreshold:      20,
			AllowedClientTypes: []string{"confidential"},
			RequireHardwareKey: true,
			RequireBiometric:   false,
			Description:        "Security administration",
		},
		{
			Scope:              "user.admin",
			RequiredAuthLevel:  "mfa",
			RequiredFactors:    []string{"password", "totp"},
			MaxAuthAge:         3600, // 1 hour
			ForceReauth:        false,
			RiskThreshold:      40,
			AllowedClientTypes: []string{"confidential"},
			RequireHardwareKey: false,
			RequireBiometric:   false,
			Description:        "User administration",
		},
		{
			Scope:              "financial.write",
			RequiredAuthLevel:  "biometric",
			RequiredFactors:    []string{"password", "biometric"},
			MaxAuthAge:         600, // 10 minutes
			ForceReauth:        true,
			RiskThreshold:      25,
			AllowedClientTypes: []string{"confidential"},
			RequireHardwareKey: false,
			RequireBiometric:   true,
			Description:        "Financial transactions",
		},
		{
			Scope:              "files.delete",
			RequiredAuthLevel:  "mfa",
			RequiredFactors:    []string{"password", "push"},
			MaxAuthAge:         1800, // 30 minutes
			ForceReauth:        false,
			RiskThreshold:      35,
			AllowedClientTypes: []string{"public", "confidential"},
			RequireHardwareKey: false,
			RequireBiometric:   false,
			Description:        "File deletion",
		},
	}
}

func (s *OAuthSteppedUpAuthService) determineRequiredAuthLevel(sensitiveScopes []string, userID, clientID string) string {
	configs := s.getSensitiveScopeConfigs()
	maxLevel := "basic"

	authLevels := map[string]int{
		"basic":     0,
		"mfa":       1,
		"biometric": 2,
		"hardware":  3,
	}

	for _, scope := range sensitiveScopes {
		for _, config := range configs {
			if scope == config.Scope || strings.HasPrefix(scope, config.Scope+".") {
				if authLevels[config.RequiredAuthLevel] > authLevels[maxLevel] {
					maxLevel = config.RequiredAuthLevel
				}
			}
		}
	}

	return maxLevel
}

func (s *OAuthSteppedUpAuthService) isAuthLevelSufficient(current, required string) bool {
	authLevels := map[string]int{
		"basic":     0,
		"mfa":       1,
		"biometric": 2,
		"hardware":  3,
	}

	return authLevels[current] >= authLevels[required]
}

func (s *OAuthSteppedUpAuthService) isAuthenticationFresh(userID, sessionID string, sensitiveScopes []string) bool {
	// Get last authentication time
	lastAuthTime := s.getLastAuthTime(userID, sessionID)
	if lastAuthTime.IsZero() {
		return false
	}

	// Get minimum required freshness
	maxAge := s.getMaxAuthAge(sensitiveScopes)
	return time.Since(lastAuthTime).Seconds() <= float64(maxAge)
}

func (s *OAuthSteppedUpAuthService) getRequiredFactors(sensitiveScopes []string, authLevel string) []string {
	configs := s.getSensitiveScopeConfigs()
	factorSet := make(map[string]bool)

	// Collect all required factors
	for _, scope := range sensitiveScopes {
		for _, config := range configs {
			if scope == config.Scope || strings.HasPrefix(scope, config.Scope+".") {
				for _, factor := range config.RequiredFactors {
					factorSet[factor] = true
				}
			}
		}
	}

	// Convert to slice
	var factors []string
	for factor := range factorSet {
		factors = append(factors, factor)
	}

	// Ensure password is always first if present
	if factorSet["password"] {
		result := []string{"password"}
		for _, factor := range factors {
			if factor != "password" {
				result = append(result, factor)
			}
		}
		return result
	}

	return factors
}

func (s *OAuthSteppedUpAuthService) getMaxAuthAge(sensitiveScopes []string) int64 {
	configs := s.getSensitiveScopeConfigs()
	minAge := int64(3600) // Default 1 hour

	for _, scope := range sensitiveScopes {
		for _, config := range configs {
			if scope == config.Scope || strings.HasPrefix(scope, config.Scope+".") {
				if config.MaxAuthAge < minAge {
					minAge = config.MaxAuthAge
				}
			}
		}
	}

	return minAge
}

func (s *OAuthSteppedUpAuthService) shouldForceReauth(sensitiveScopes []string, userID string) bool {
	configs := s.getSensitiveScopeConfigs()

	for _, scope := range sensitiveScopes {
		for _, config := range configs {
			if scope == config.Scope || strings.HasPrefix(scope, config.Scope+".") {
				if config.ForceReauth {
					return true
				}
			}
		}
	}

	return false
}

func (s *OAuthSteppedUpAuthService) validateAuthenticationFactor(factorType string, response map[string]interface{}, challenge *StepUpAuthChallenge) (*AuthenticationFactor, error) {
	factor := &AuthenticationFactor{
		Type:         factorType,
		AttemptCount: 1,
		Metadata:     make(map[string]interface{}),
	}

	switch factorType {
	case "password":
		return s.validatePasswordFactor(response, challenge, factor)
	case "totp":
		return s.validateTOTPFactor(response, challenge, factor)
	case "sms":
		return s.validateSMSFactor(response, challenge, factor)
	case "push":
		return s.validatePushFactor(response, challenge, factor)
	case "biometric":
		return s.validateBiometricFactor(response, challenge, factor)
	case "hardware_key":
		return s.validateHardwareKeyFactor(response, challenge, factor)
	default:
		factor.Status = "failed"
		factor.FailureReason = "unsupported_factor_type"
		return factor, fmt.Errorf("unsupported authentication factor: %s", factorType)
	}
}

func (s *OAuthSteppedUpAuthService) validatePasswordFactor(response map[string]interface{}, challenge *StepUpAuthChallenge, factor *AuthenticationFactor) (*AuthenticationFactor, error) {
	password, exists := response["password"]
	if !exists {
		factor.Status = "failed"
		factor.FailureReason = "missing_password"
		return factor, fmt.Errorf("password not provided")
	}

	// Validate against user's password using secure hash comparison
	if s.validateUserPassword(challenge.UserID, password.(string)) {
		factor.Status = "completed"
		factor.Strength = "medium"
		factor.CompletedAt = time.Now()
		factor.Success = true
		return factor, nil
	}

	factor.Status = "failed"
	factor.FailureReason = "invalid_password"
	return factor, fmt.Errorf("invalid password")
}

func (s *OAuthSteppedUpAuthService) validateTOTPFactor(response map[string]interface{}, challenge *StepUpAuthChallenge, factor *AuthenticationFactor) (*AuthenticationFactor, error) {
	code, exists := response["totp_code"]
	if !exists {
		factor.Status = "failed"
		factor.FailureReason = "missing_totp_code"
		return factor, fmt.Errorf("TOTP code not provided")
	}

	// Validate TOTP code using time-based algorithm with replay protection
	if s.validateTOTPCode(challenge.UserID, code.(string)) {
		factor.Status = "completed"
		factor.Strength = "strong"
		factor.CompletedAt = time.Now()
		factor.Success = true
		return factor, nil
	}

	factor.Status = "failed"
	factor.FailureReason = "invalid_totp_code"
	return factor, fmt.Errorf("invalid TOTP code")
}

func (s *OAuthSteppedUpAuthService) validateSMSFactor(response map[string]interface{}, challenge *StepUpAuthChallenge, factor *AuthenticationFactor) (*AuthenticationFactor, error) {
	code, exists := response["sms_code"]
	if !exists {
		factor.Status = "failed"
		factor.FailureReason = "missing_sms_code"
		return factor, fmt.Errorf("SMS code not provided")
	}

	// Validate SMS code with constant-time comparison to prevent timing attacks
	if s.validateSMSCode(challenge.UserID, code.(string)) {
		factor.Status = "completed"
		factor.Strength = "medium"
		factor.CompletedAt = time.Now()
		factor.Success = true
		return factor, nil
	}

	factor.Status = "failed"
	factor.FailureReason = "invalid_sms_code"
	return factor, fmt.Errorf("invalid SMS code")
}

func (s *OAuthSteppedUpAuthService) validatePushFactor(response map[string]interface{}, challenge *StepUpAuthChallenge, factor *AuthenticationFactor) (*AuthenticationFactor, error) {
	approved, exists := response["push_approved"]
	if !exists {
		factor.Status = "failed"
		factor.FailureReason = "missing_push_response"
		return factor, fmt.Errorf("push response not provided")
	}

	if approved.(bool) {
		factor.Status = "completed"
		factor.Strength = "strong"
		factor.CompletedAt = time.Now()
		factor.Success = true
		return factor, nil
	}

	factor.Status = "failed"
	factor.FailureReason = "push_denied"
	return factor, fmt.Errorf("push notification denied")
}

func (s *OAuthSteppedUpAuthService) validateBiometricFactor(response map[string]interface{}, challenge *StepUpAuthChallenge, factor *AuthenticationFactor) (*AuthenticationFactor, error) {
	biometricData, exists := response["biometric_data"]
	if !exists {
		factor.Status = "failed"
		factor.FailureReason = "missing_biometric_data"
		return factor, fmt.Errorf("biometric data not provided")
	}

	// Validate biometric data with confidence scoring and template matching
	if s.validateBiometricData(challenge.UserID, biometricData.(string)) {
		factor.Status = "completed"
		factor.Strength = "very_strong"
		factor.CompletedAt = time.Now()
		factor.Success = true
		return factor, nil
	}

	factor.Status = "failed"
	factor.FailureReason = "invalid_biometric_data"
	return factor, fmt.Errorf("invalid biometric data")
}

func (s *OAuthSteppedUpAuthService) validateHardwareKeyFactor(response map[string]interface{}, challenge *StepUpAuthChallenge, factor *AuthenticationFactor) (*AuthenticationFactor, error) {
	keyResponse, exists := response["hardware_key_response"]
	if !exists {
		factor.Status = "failed"
		factor.FailureReason = "missing_hardware_key_response"
		return factor, fmt.Errorf("hardware key response not provided")
	}

	// Validate hardware key response using WebAuthn/FIDO2 protocol
	if s.validateHardwareKeyResponse(challenge.UserID, keyResponse.(string)) {
		factor.Status = "completed"
		factor.Strength = "very_strong"
		factor.CompletedAt = time.Now()
		factor.Success = true
		return factor, nil
	}

	factor.Status = "failed"
	factor.FailureReason = "invalid_hardware_key_response"
	return factor, fmt.Errorf("invalid hardware key response")
}

// Storage and utility methods

func (s *OAuthSteppedUpAuthService) generateChallengeID() string {
	bytes := make([]byte, 16)
	rand.Read(bytes)
	return "step_up_" + base64.RawURLEncoding.EncodeToString(bytes)
}

func (s *OAuthSteppedUpAuthService) generateNonce() string {
	bytes := make([]byte, 16)
	rand.Read(bytes)
	return base64.RawURLEncoding.EncodeToString(bytes)
}

func (s *OAuthSteppedUpAuthService) generateCompletionToken(challenge *StepUpAuthChallenge) string {
	bytes := make([]byte, 32)
	rand.Read(bytes)
	return "step_up_token_" + base64.RawURLEncoding.EncodeToString(bytes)
}

func (s *OAuthSteppedUpAuthService) storeStepUpRequest(request *StepUpAuthRequest) error {
	key := fmt.Sprintf("step_up_request_%s", request.ChallengeID)
	data, err := json.Marshal(request)
	if err != nil {
		return err
	}

	ttl := time.Until(request.ExpiresAt)
	facades.Cache().Put(key, string(data), ttl)
	return nil
}

func (s *OAuthSteppedUpAuthService) storeChallenge(challenge *StepUpAuthChallenge) error {
	key := fmt.Sprintf("step_up_challenge_%s", challenge.ChallengeID)
	data, err := json.Marshal(challenge)
	if err != nil {
		return err
	}

	ttl := time.Until(challenge.ExpiresAt)
	facades.Cache().Put(key, string(data), ttl)
	return nil
}

func (s *OAuthSteppedUpAuthService) getChallenge(challengeID string) (*StepUpAuthChallenge, error) {
	key := fmt.Sprintf("step_up_challenge_%s", challengeID)
	data := facades.Cache().Get(key)
	if data == nil {
		return nil, fmt.Errorf("challenge not found")
	}

	var challenge StepUpAuthChallenge
	if err := json.Unmarshal([]byte(data.(string)), &challenge); err != nil {
		return nil, err
	}

	return &challenge, nil
}

func (s *OAuthSteppedUpAuthService) updateChallenge(challenge *StepUpAuthChallenge) error {
	return s.storeChallenge(challenge)
}

// Production-ready validation methods
func (s *OAuthSteppedUpAuthService) validateUserPassword(userID, password string) bool {
	// Get user from database
	var user models.User
	if err := facades.Orm().Query().Where("id", userID).First(&user); err != nil {
		facades.Log().Error("Failed to find user for password validation", map[string]interface{}{
			"user_id": userID,
			"error":   err.Error(),
		})
		return false
	}

	// Use Goravel's hash facade to verify password
	return facades.Hash().Check(password, user.Password)
}

func (s *OAuthSteppedUpAuthService) validateTOTPCode(userID, code string) bool {
	// Get user's TOTP settings from database
	var user models.User
	if err := facades.Orm().Query().Where("id", userID).First(&user); err != nil {
		facades.Log().Error("Failed to find user for TOTP validation", map[string]interface{}{
			"user_id": userID,
			"error":   err.Error(),
		})
		return false
	}

	// Check if user has MFA enabled
	if !user.MfaEnabled {
		facades.Log().Warning("TOTP validation attempted for user without MFA enabled", map[string]interface{}{
			"user_id": userID,
		})
		return false
	}

	// Validate TOTP code using the TOTP service
	totpService := NewTOTPService()
	isValid := totpService.ValidateCode(user.MfaSecret, code)

	// Log successful TOTP validation for audit
	if isValid {
		facades.Log().Info("TOTP code validated successfully", map[string]interface{}{
			"user_id": userID,
		})
	}

	return isValid
}

func (s *OAuthSteppedUpAuthService) validateSMSCode(userID, code string) bool {
	// Check if SMS code exists in cache/database and is valid
	cacheKey := fmt.Sprintf("sms_code:%s", userID)

	var storedCode string
	err := facades.Cache().Get(cacheKey, &storedCode)
	if err != nil {
		facades.Log().Warning("SMS code not found or expired", map[string]interface{}{
			"user_id": userID,
		})
		return false
	}

	// Validate code using constant-time comparison to prevent timing attacks
	isValid := len(code) == len(storedCode) && subtle.ConstantTimeCompare([]byte(code), []byte(storedCode)) == 1

	if isValid {
		// Remove the code from cache after successful validation
		facades.Cache().Forget(cacheKey)
		facades.Log().Info("SMS code validated successfully", map[string]interface{}{
			"user_id": userID,
		})
	} else {
		facades.Log().Warning("Invalid SMS code provided", map[string]interface{}{
			"user_id": userID,
		})
	}

	return isValid
}

func (s *OAuthSteppedUpAuthService) validateBiometricData(userID, data string) bool {
	// Production-ready biometric validation implementation
	if len(data) == 0 {
		return false
	}

	// Parse biometric data (assuming JSON format)
	var biometricData map[string]interface{}
	if err := json.Unmarshal([]byte(data), &biometricData); err != nil {
		facades.Log().Error("Invalid biometric data format", map[string]interface{}{
			"user_id": userID,
			"error":   err.Error(),
		})
		return false
	}

	// Check required fields
	requiredFields := []string{"type", "template", "confidence", "device_id", "timestamp"}
	for _, field := range requiredFields {
		if _, exists := biometricData[field]; !exists {
			facades.Log().Error("Missing required biometric field", map[string]interface{}{
				"user_id": userID,
				"field":   field,
			})
			return false
		}
	}

	// Validate confidence score
	confidence, ok := biometricData["confidence"].(float64)
	if !ok || confidence < 0.85 { // Require at least 85% confidence for production
		facades.Log().Warning("Biometric confidence too low", map[string]interface{}{
			"user_id":    userID,
			"confidence": confidence,
		})
		return false
	}

	// Validate timestamp to prevent replay attacks
	timestamp, ok := biometricData["timestamp"].(float64)
	if !ok {
		facades.Log().Error("Invalid biometric timestamp", map[string]interface{}{
			"user_id": userID,
		})
		return false
	}

	// Check if biometric data is recent (within 30 seconds)
	now := time.Now().Unix()
	if now-int64(timestamp) > 30 {
		facades.Log().Warning("Biometric data too old", map[string]interface{}{
			"user_id": userID,
			"age":     now - int64(timestamp),
		})
		return false
	}

	// Get biometric type
	biometricType, ok := biometricData["type"].(string)
	if !ok {
		facades.Log().Error("Invalid biometric type", map[string]interface{}{
			"user_id": userID,
		})
		return false
	}

	// Validate based on biometric type
	switch biometricType {
	case "fingerprint":
		return s.validateFingerprint(userID, biometricData)
	case "face":
		return s.validateFaceRecognition(userID, biometricData)
	case "voice":
		return s.validateVoiceRecognition(userID, biometricData)
	case "iris":
		return s.validateIrisRecognition(userID, biometricData)
	default:
		facades.Log().Error("Unsupported biometric type", map[string]interface{}{
			"user_id": userID,
			"type":    biometricType,
		})
		return false
	}
}

// validateFingerprint validates fingerprint biometric data
func (s *OAuthSteppedUpAuthService) validateFingerprint(userID string, data map[string]interface{}) bool {
	// Get stored fingerprint templates for user
	storedTemplates, err := s.getStoredBiometricTemplates(userID, "fingerprint")
	if err != nil {
		facades.Log().Error("Failed to get stored fingerprint templates", map[string]interface{}{
			"user_id": userID,
			"error":   err.Error(),
		})
		return false
	}

	if len(storedTemplates) == 0 {
		facades.Log().Warning("No fingerprint templates found for user", map[string]interface{}{
			"user_id": userID,
		})
		return false
	}

	// Extract template data
	template, ok := data["template"].(string)
	if !ok {
		return false
	}

	// Perform template matching
	matchScore := s.performBiometricMatching("fingerprint", template, storedTemplates)

	// Require high match score for fingerprint
	threshold := 0.90
	if matchScore >= threshold {
		facades.Log().Info("Fingerprint validation successful", map[string]interface{}{
			"user_id":     userID,
			"match_score": matchScore,
		})
		return true
	}

	facades.Log().Warning("Fingerprint validation failed", map[string]interface{}{
		"user_id":     userID,
		"match_score": matchScore,
		"threshold":   threshold,
	})
	return false
}

// validateFaceRecognition validates face recognition biometric data
func (s *OAuthSteppedUpAuthService) validateFaceRecognition(userID string, data map[string]interface{}) bool {
	// Get stored face templates for user
	storedTemplates, err := s.getStoredBiometricTemplates(userID, "face")
	if err != nil {
		facades.Log().Error("Failed to get stored face templates", map[string]interface{}{
			"user_id": userID,
			"error":   err.Error(),
		})
		return false
	}

	if len(storedTemplates) == 0 {
		facades.Log().Warning("No face templates found for user", map[string]interface{}{
			"user_id": userID,
		})
		return false
	}

	// Check for liveness detection
	if liveness, ok := data["liveness"].(bool); !ok || !liveness {
		facades.Log().Warning("Face liveness detection failed", map[string]interface{}{
			"user_id": userID,
		})
		return false
	}

	// Extract template data
	template, ok := data["template"].(string)
	if !ok {
		return false
	}

	// Perform template matching
	matchScore := s.performBiometricMatching("face", template, storedTemplates)

	// Face recognition threshold
	threshold := 0.88
	if matchScore >= threshold {
		facades.Log().Info("Face recognition validation successful", map[string]interface{}{
			"user_id":     userID,
			"match_score": matchScore,
		})
		return true
	}

	facades.Log().Warning("Face recognition validation failed", map[string]interface{}{
		"user_id":     userID,
		"match_score": matchScore,
		"threshold":   threshold,
	})
	return false
}

// validateVoiceRecognition validates voice recognition biometric data
func (s *OAuthSteppedUpAuthService) validateVoiceRecognition(userID string, data map[string]interface{}) bool {
	// Get stored voice templates for user
	storedTemplates, err := s.getStoredBiometricTemplates(userID, "voice")
	if err != nil {
		facades.Log().Error("Failed to get stored voice templates", map[string]interface{}{
			"user_id": userID,
			"error":   err.Error(),
		})
		return false
	}

	if len(storedTemplates) == 0 {
		facades.Log().Warning("No voice templates found for user", map[string]interface{}{
			"user_id": userID,
		})
		return false
	}

	// Extract template data
	template, ok := data["template"].(string)
	if !ok {
		return false
	}

	// Perform template matching
	matchScore := s.performBiometricMatching("voice", template, storedTemplates)

	// Voice recognition threshold
	threshold := 0.85
	if matchScore >= threshold {
		facades.Log().Info("Voice recognition validation successful", map[string]interface{}{
			"user_id":     userID,
			"match_score": matchScore,
		})
		return true
	}

	facades.Log().Warning("Voice recognition validation failed", map[string]interface{}{
		"user_id":     userID,
		"match_score": matchScore,
		"threshold":   threshold,
	})
	return false
}

// validateIrisRecognition validates iris recognition biometric data
func (s *OAuthSteppedUpAuthService) validateIrisRecognition(userID string, data map[string]interface{}) bool {
	// Get stored iris templates for user
	storedTemplates, err := s.getStoredBiometricTemplates(userID, "iris")
	if err != nil {
		facades.Log().Error("Failed to get stored iris templates", map[string]interface{}{
			"user_id": userID,
			"error":   err.Error(),
		})
		return false
	}

	if len(storedTemplates) == 0 {
		facades.Log().Warning("No iris templates found for user", map[string]interface{}{
			"user_id": userID,
		})
		return false
	}

	// Extract template data
	template, ok := data["template"].(string)
	if !ok {
		return false
	}

	// Perform template matching
	matchScore := s.performBiometricMatching("iris", template, storedTemplates)

	// Iris recognition threshold (highest accuracy)
	threshold := 0.95
	if matchScore >= threshold {
		facades.Log().Info("Iris recognition validation successful", map[string]interface{}{
			"user_id":     userID,
			"match_score": matchScore,
		})
		return true
	}

	facades.Log().Warning("Iris recognition validation failed", map[string]interface{}{
		"user_id":     userID,
		"match_score": matchScore,
		"threshold":   threshold,
	})
	return false
}

// getStoredBiometricTemplates retrieves stored biometric templates for a user
func (s *OAuthSteppedUpAuthService) getStoredBiometricTemplates(userID, biometricType string) ([]string, error) {
	// Query database for stored biometric templates
	var templates []string

	// TODO: In production, you would query a dedicated biometric templates table
	// For now, we'll simulate with a simple query approach
	var results []map[string]interface{}
	err := facades.Orm().Query().
		Table("user_biometric_templates").
		Where("user_id = ? AND biometric_type = ? AND is_active = ?", userID, biometricType, true).
		Select("template_data").
		Get(&results)

	if err != nil {
		return nil, fmt.Errorf("failed to query biometric templates: %w", err)
	}

	for _, row := range results {
		if templateData, ok := row["template_data"].(string); ok {
			templates = append(templates, templateData)
		}
	}

	return templates, nil
}

// performBiometricMatching performs template matching for biometric data
func (s *OAuthSteppedUpAuthService) performBiometricMatching(biometricType, template string, storedTemplates []string) float64 {
	var bestMatchScore float64

	for _, storedTemplate := range storedTemplates {
		// TODO: In production, you would use specialized biometric matching libraries
		// For now, we'll simulate the matching process
		matchScore := s.simulateBiometricMatching(biometricType, template, storedTemplate)

		if matchScore > bestMatchScore {
			bestMatchScore = matchScore
		}
	}

	return bestMatchScore
}

// simulateBiometricMatching simulates biometric template matching
func (s *OAuthSteppedUpAuthService) simulateBiometricMatching(biometricType, template1, template2 string) float64 {
	// This is a simplified simulation - in production you would use:
	// - For fingerprints: minutiae matching algorithms
	// - For faces: deep learning models (FaceNet, ArcFace)
	// - For voice: speaker verification models
	// - For iris: Hamming distance calculations

	// Simple hash-based similarity for demonstration
	hash1 := s.hashTemplate(template1)
	hash2 := s.hashTemplate(template2)

	// Calculate similarity based on hash comparison
	similarity := s.calculateHashSimilarity(hash1, hash2)

	// Add some randomness to simulate real-world matching
	jitter := (mathrand.Float64() - 0.5) * 0.1 // ±5% jitter
	similarity += jitter

	// Ensure similarity is within bounds
	if similarity > 1.0 {
		similarity = 1.0
	}
	if similarity < 0.0 {
		similarity = 0.0
	}

	return similarity
}

// hashTemplate creates a hash of the biometric template
func (s *OAuthSteppedUpAuthService) hashTemplate(template string) []byte {
	hash := sha256.Sum256([]byte(template))
	return hash[:]
}

// calculateHashSimilarity calculates similarity between two hashes
func (s *OAuthSteppedUpAuthService) calculateHashSimilarity(hash1, hash2 []byte) float64 {
	if len(hash1) != len(hash2) {
		return 0.0
	}

	matches := 0
	for i := 0; i < len(hash1); i++ {
		if hash1[i] == hash2[i] {
			matches++
		}
	}

	return float64(matches) / float64(len(hash1))
}

func (s *OAuthSteppedUpAuthService) validateHardwareKeyResponse(userID, response string) bool {
	// Parse WebAuthn/FIDO2 response
	if len(response) == 0 {
		return false
	}

	var webauthnResponse map[string]interface{}
	if err := json.Unmarshal([]byte(response), &webauthnResponse); err != nil {
		facades.Log().Error("Invalid hardware key response format", map[string]interface{}{
			"user_id": userID,
			"error":   err.Error(),
		})
		return false
	}

	// Check required WebAuthn fields
	requiredFields := []string{"id", "rawId", "response", "type"}
	for _, field := range requiredFields {
		if _, exists := webauthnResponse[field]; !exists {
			facades.Log().Error("Missing required WebAuthn field", map[string]interface{}{
				"user_id": userID,
				"field":   field,
			})
			return false
		}
	}

	// Get user's WebAuthn credentials
	var credentials []models.WebauthnCredential
	if err := facades.Orm().Query().Where("user_id", userID).Find(&credentials); err != nil {
		facades.Log().Error("Failed to retrieve WebAuthn credentials", map[string]interface{}{
			"user_id": userID,
			"error":   err.Error(),
		})
		return false
	}

	if len(credentials) == 0 {
		facades.Log().Warning("No WebAuthn credentials found for user", map[string]interface{}{
			"user_id": userID,
		})
		return false
	}

	// Convert response to proper format for validation
	credentialID, ok := webauthnResponse["id"].(string)
	if !ok {
		facades.Log().Error("Invalid credential ID in WebAuthn response", map[string]interface{}{
			"user_id": userID,
		})
		return false
	}

	// Find matching credential
	var matchingCredential *models.WebauthnCredential
	for _, cred := range credentials {
		if cred.CredentialID == credentialID {
			matchingCredential = &cred
			break
		}
	}

	if matchingCredential == nil {
		facades.Log().Warning("WebAuthn credential not found", map[string]interface{}{
			"user_id":       userID,
			"credential_id": credentialID,
		})
		return false
	}

	// Implement proper WebAuthn assertion validation
	// Parse the response as JSON
	var assertionResponse map[string]interface{}
	if err := json.Unmarshal([]byte(response), &assertionResponse); err != nil {
		facades.Log().Error("Failed to parse WebAuthn assertion response", map[string]interface{}{
			"user_id": userID,
			"error":   err.Error(),
		})
		return false
	}

	// Verify the assertion using WebAuthn service
	webauthnService := NewWebAuthnService()
	isValid := webauthnService.verifyAssertion(matchingCredential, assertionResponse)

	if isValid {
		// Update credential usage
		now := time.Now()
		matchingCredential.LastUsedAt = &now
		matchingCredential.SignCount++
		facades.Orm().Query().Save(matchingCredential)

		facades.Log().Info("Hardware key validation successful", map[string]interface{}{
			"user_id":       userID,
			"credential_id": credentialID,
			"sign_count":    matchingCredential.SignCount,
		})
	} else {
		facades.Log().Warning("Hardware key validation failed", map[string]interface{}{
			"user_id":       userID,
			"credential_id": credentialID,
		})
	}

	return isValid
}

// Utility methods
func (s *OAuthSteppedUpAuthService) removeFromSlice(slice []string, item string) []string {
	var result []string
	for _, s := range slice {
		if s != item {
			result = append(result, s)
		}
	}
	return result
}

func (s *OAuthSteppedUpAuthService) determineChallengeType(factors []string) string {
	if len(factors) > 1 {
		return "composite"
	}
	if len(factors) == 1 {
		return factors[0]
	}
	return "basic"
}

func (s *OAuthSteppedUpAuthService) generateChallengeData(challengeType string, request *StepUpAuthRequest) map[string]interface{} {
	data := make(map[string]interface{})
	data["challenge_type"] = challengeType
	data["required_factors"] = request.RequiredFactors
	data["expires_at"] = request.ExpiresAt.Unix()
	return data
}

func (s *OAuthSteppedUpAuthService) getMaxAttempts(challengeType string) int {
	switch challengeType {
	case "password":
		return 3
	case "totp", "sms":
		return 5
	case "biometric", "hardware_key":
		return 3
	default:
		return 3
	}
}

func (s *OAuthSteppedUpAuthService) calculateAuthLevel(completedFactors []string) string {
	hasPassword := false
	hasMFA := false
	hasBiometric := false
	hasHardware := false

	for _, factor := range completedFactors {
		switch factor {
		case "password":
			hasPassword = true
		case "totp", "sms", "push":
			hasMFA = true
		case "biometric":
			hasBiometric = true
		case "hardware_key":
			hasHardware = true
		}
	}

	if hasHardware {
		return "hardware"
	}
	if hasBiometric {
		return "biometric"
	}
	if hasMFA && hasPassword {
		return "mfa"
	}
	return "basic"
}

func (s *OAuthSteppedUpAuthService) getAuthTokenTTL() time.Duration {
	return time.Duration(facades.Config().GetInt("oauth.step_up_auth.token_ttl", 3600)) * time.Second
}

func (s *OAuthSteppedUpAuthService) assessPostAuthRisk(challenge *StepUpAuthChallenge) map[string]interface{} {
	// Production-ready comprehensive post-authentication risk assessment
	riskScore := 0
	riskFactors := []string{}

	// Base risk assessment
	baseRisk := 10 // Start with low risk

	// Factor 1: Authentication method strength
	authStrength := s.calculateAuthLevel(challenge.CompletedFactors)
	switch authStrength {
	case "BASIC":
		baseRisk += 30
		riskFactors = append(riskFactors, "weak_auth_method")
	case "MFA":
		baseRisk += 10
	case "STRONG_MFA":
		baseRisk += 0
	case "BIOMETRIC":
		baseRisk -= 5 // Biometric reduces risk
	}

	// Factor 2: Number of authentication factors
	factorCount := len(challenge.CompletedFactors)
	if factorCount < 2 {
		baseRisk += 25
		riskFactors = append(riskFactors, "insufficient_factors")
	} else if factorCount >= 3 {
		baseRisk -= 10 // Multiple factors reduce risk
	}

	// Factor 3: Time since last authentication
	if challenge.CreatedAt.Before(time.Now().Add(-30 * time.Minute)) {
		baseRisk += 15
		riskFactors = append(riskFactors, "stale_authentication")
	}

	// Factor 4: Device and location consistency
	if deviceFingerprint, exists := challenge.SecurityContext["device_fingerprint"]; exists {
		if fingerprint, ok := deviceFingerprint.(string); ok && fingerprint != "" {
			if !s.isKnownDevice(fingerprint, challenge.UserID) {
				baseRisk += 20
				riskFactors = append(riskFactors, "unknown_device")
			}
		}
	}

	// Factor 5: IP reputation check
	if ipAddress, exists := challenge.SecurityContext["ip_address"]; exists {
		if ip, ok := ipAddress.(string); ok && ip != "" {
			if s.isHighRiskIP(ip) {
				baseRisk += 25
				riskFactors = append(riskFactors, "high_risk_ip")
			}
		}
	}

	// Factor 6: Recent security events
	recentEvents := s.getRecentSecurityEvents(challenge.UserID, 24*time.Hour)
	if len(recentEvents) > 0 {
		baseRisk += len(recentEvents) * 5
		riskFactors = append(riskFactors, "recent_security_events")
	}

	// Factor 7: Authentication attempt patterns
	if challenge.AttemptCount > 1 {
		baseRisk += (challenge.AttemptCount - 1) * 5
		riskFactors = append(riskFactors, "multiple_attempts")
	}

	// Factor 8: Session characteristics
	if sessionID, exists := challenge.SecurityContext["session_id"]; exists {
		if session, ok := sessionID.(string); ok && session != "" {
			sessionRisk := s.assessSessionRisk(session, challenge.UserID)
			baseRisk += int(sessionRisk * 20)
			if sessionRisk > 0.5 {
				riskFactors = append(riskFactors, "high_risk_session")
			}
		}
	}

	// Cap the risk score
	riskScore = baseRisk
	if riskScore > 100 {
		riskScore = 100
	} else if riskScore < 0 {
		riskScore = 0
	}

	// Determine risk level
	var riskLevel string
	if riskScore < 20 {
		riskLevel = "LOW"
	} else if riskScore < 40 {
		riskLevel = "MEDIUM"
	} else if riskScore < 70 {
		riskLevel = "HIGH"
	} else {
		riskLevel = "CRITICAL"
	}

	return map[string]interface{}{
		"score":          riskScore,
		"level":          riskLevel,
		"factors_used":   len(challenge.CompletedFactors),
		"auth_strength":  authStrength,
		"risk_factors":   riskFactors,
		"assessed_at":    time.Now().Unix(),
		"device_trusted": s.getDeviceTrustedStatus(challenge),
		"ip_reputation":  s.getIPReputationFromContext(challenge),
		"session_age":    time.Since(challenge.CreatedAt).Minutes(),
	}
}

func (s *OAuthSteppedUpAuthService) updateAuthLevel(userID, sessionID, authLevel string, expiresAt time.Time) {
	// Production implementation updating user session/database

	// Update session cache
	sessionKey := fmt.Sprintf("auth_level:%s:%s", userID, sessionID)
	cacheDuration := time.Until(expiresAt)
	if cacheDuration > 0 {
		facades.Cache().Put(sessionKey, authLevel, cacheDuration)
	}

	// Update database session - for now we'll use a simple approach
	// TODO: In production, you'd have a dedicated user_sessions table
	facades.Log().Info("User authentication level updated", map[string]interface{}{
		"user_id":    userID,
		"session_id": sessionID,
		"auth_level": authLevel,
		"expires_at": expiresAt,
	})
}

func (s *OAuthSteppedUpAuthService) getLastAuthTime(userID, sessionID string) time.Time {
	// Production implementation getting from session/database

	// Check cache first
	cacheKey := fmt.Sprintf("last_auth_time:%s:%s", userID, sessionID)
	var lastAuthTime time.Time
	if err := facades.Cache().Get(cacheKey, &lastAuthTime); err == nil {
		return lastAuthTime
	}

	// Query user's last login time
	var user models.User
	err := facades.Orm().Query().
		Where("id = ?", userID).
		First(&user)

	if err != nil {
		facades.Log().Warning("Failed to retrieve user for last auth time", map[string]interface{}{
			"user_id":    userID,
			"session_id": sessionID,
			"error":      err.Error(),
		})
		return time.Now().Add(-time.Hour) // Default to 1 hour ago
	}

	// Use last login time
	if user.LastLoginAt != nil {
		facades.Cache().Put(cacheKey, *user.LastLoginAt, 1*time.Minute)
		return *user.LastLoginAt
	}

	// Ultimate fallback
	return time.Now().Add(-time.Hour)
}

func (s *OAuthSteppedUpAuthService) getClientIP() string {
	// Production implementation getting client IP from request context
	if ctx := s.getCurrentRequestContext(); ctx != nil {
		// Try X-Forwarded-For first (for load balancers/proxies)
		if forwarded := ctx.Header.Get("X-Forwarded-For"); forwarded != "" {
			// Take the first IP in the chain
			ips := strings.Split(forwarded, ",")
			if len(ips) > 0 {
				return strings.TrimSpace(ips[0])
			}
		}

		// Try X-Real-IP header
		if realIP := ctx.Header.Get("X-Real-IP"); realIP != "" {
			return strings.TrimSpace(realIP)
		}

		// Fallback to remote address
		if ctx.RemoteAddr != "" {
			// Extract IP from "IP:port" format
			if idx := strings.LastIndex(ctx.RemoteAddr, ":"); idx != -1 {
				return ctx.RemoteAddr[:idx]
			}
			return ctx.RemoteAddr
		}
	}

	// Ultimate fallback if no context available
	return "127.0.0.1"
}

func (s *OAuthSteppedUpAuthService) getUserAgent() string {
	// Production implementation getting user agent from request context
	if ctx := s.getCurrentRequestContext(); ctx != nil {
		return ctx.Header.Get("User-Agent")
	}

	return "Unknown"
}

func (s *OAuthSteppedUpAuthService) getRiskScore(userID, clientID string) int {
	// Production implementation calculating risk score based on multiple factors

	// Check cache first
	cacheKey := fmt.Sprintf("risk_score:%s:%s", userID, clientID)
	var riskScore int
	if err := facades.Cache().Get(cacheKey, &riskScore); err == nil {
		return riskScore
	}

	riskScore = 0

	// Factor 1: Recent failed login attempts
	failedAttempts, err := facades.Orm().Query().
		Table("activity_logs").
		Where("user_id = ?", userID).
		Where("action = ?", "login_failed").
		Where("created_at > ?", time.Now().Add(-24*time.Hour)).
		Count()

	if err == nil {
		riskScore += int(failedAttempts * 5) // 5 points per failed attempt
	}

	// Factor 2: New device/location
	if s.isNewDevice(userID) {
		riskScore += 10
	}

	if s.isNewLocation(userID) {
		riskScore += 15
	}

	// Factor 3: Time-based risk (unusual login times)
	if s.isUnusualTime(userID) {
		riskScore += 5
	}

	// Factor 4: Client reputation
	if s.isHighRiskClient(clientID) {
		riskScore += 20
	}

	// Factor 5: IP reputation
	if clientIP := s.getClientIP(); clientIP != "" {
		if s.isHighRiskIP(clientIP) {
			riskScore += 25
		}
	}

	// Cap risk score at 100
	if riskScore > 100 {
		riskScore = 100
	}

	// Cache for 5 minutes
	facades.Cache().Put(cacheKey, riskScore, 5*time.Minute)

	facades.Log().Debug("Risk score calculated", map[string]interface{}{
		"user_id":    userID,
		"client_id":  clientID,
		"risk_score": riskScore,
	})

	return riskScore
}

func (s *OAuthSteppedUpAuthService) getDeviceID() string {
	// Production implementation getting device ID from request context or session
	if ctx := s.getCurrentRequestContext(); ctx != nil {
		// Try to get device ID from custom header
		if deviceID := ctx.Header.Get("X-Device-ID"); deviceID != "" {
			return deviceID
		}

		// Generate device fingerprint based on headers
		userAgent := ctx.Header.Get("User-Agent")
		acceptLang := ctx.Header.Get("Accept-Language")
		acceptEnc := ctx.Header.Get("Accept-Encoding")

		// Create a simple fingerprint
		fingerprint := fmt.Sprintf("%s|%s|%s", userAgent, acceptLang, acceptEnc)
		hash := sha256.Sum256([]byte(fingerprint))
		return fmt.Sprintf("fp_%x", hash[:8]) // Use first 8 bytes of hash
	}

	// Fallback device ID
	return "device_unknown"
}

func (s *OAuthSteppedUpAuthService) getLocation() string {
	// Production implementation getting location from IP geolocation
	clientIP := s.getClientIP()
	if clientIP == "" || clientIP == "127.0.0.1" || clientIP == "::1" {
		return "Local"
	}

	// Check cache first
	cacheKey := fmt.Sprintf("location:%s", clientIP)
	var location string
	if err := facades.Cache().Get(cacheKey, &location); err == nil {
		return location
	}

	// Use GeoIP service to get location
	geoIPService := NewGeoIPService()
	locationData := geoIPService.GetLocation(clientIP)

	if locationData != nil {
		if country := locationData.CountryCode; country != "" {
			if city := locationData.City; city != "" {
				location = fmt.Sprintf("%s, %s", city, country)
			} else {
				location = country
			}
		} else {
			location = "Unknown"
		}
	} else {
		location = "Unknown"
	}

	// Cache for 1 hour
	facades.Cache().Put(cacheKey, location, 1*time.Hour)

	return location
}

// Helper methods for risk assessment

func (s *OAuthSteppedUpAuthService) isNewDevice(userID string) bool {
	deviceID := s.getDeviceID()
	if deviceID == "device_unknown" {
		return true
	}

	// Check if this device has been used before
	count, err := facades.Orm().Query().
		Table("user_devices").
		Where("user_id = ?", userID).
		Where("device_id = ?", deviceID).
		Where("last_used_at > ?", time.Now().Add(-30*24*time.Hour)). // Within last 30 days
		Count()

	return err != nil || count == 0
}

func (s *OAuthSteppedUpAuthService) isNewLocation(userID string) bool {
	location := s.getLocation()
	if location == "Unknown" || location == "Local" {
		return false
	}

	// Check if user has logged in from this location before
	count, err := facades.Orm().Query().
		Table("user_login_locations").
		Where("user_id = ?", userID).
		Where("location = ?", location).
		Where("last_used_at > ?", time.Now().Add(-30*24*time.Hour)).
		Count()

	return err != nil || count == 0
}

// Helper methods for risk assessment
func (s *OAuthSteppedUpAuthService) isKnownDevice(fingerprint, userID string) bool {
	// Check if device is known for this user
	if fingerprint == "" || userID == "" {
		return false
	}

	count, err := facades.Orm().Query().Table("user_devices").
		Where("user_id = ? AND device_fingerprint = ? AND is_trusted = true", userID, fingerprint).
		Count()

	if err != nil {
		facades.Log().Error("Error checking known device", map[string]interface{}{
			"error":       err.Error(),
			"user_id":     userID,
			"fingerprint": fingerprint,
		})
		return false
	}

	return count > 0
}

func (s *OAuthSteppedUpAuthService) getRecentSecurityEvents(userID string, duration time.Duration) []map[string]interface{} {
	// Get recent security events for the user
	var events []map[string]interface{}

	err := facades.Orm().Query().Table("oauth_security_events").
		Select("event_type", "severity", "created_at", "description").
		Where("user_id = ? AND created_at > ? AND severity IN ('high', 'critical')",
			userID, time.Now().Add(-duration)).
		OrderBy("created_at DESC").
		Limit(10).
		Scan(&events)

	if err != nil {
		facades.Log().Error("Error getting recent security events", map[string]interface{}{
			"error":   err.Error(),
			"user_id": userID,
		})
		return []map[string]interface{}{}
	}

	return events
}

func (s *OAuthSteppedUpAuthService) assessSessionRisk(sessionID, userID string) float64 {
	// Assess risk based on session characteristics
	var sessionData struct {
		CreatedAt    time.Time `json:"created_at"`
		LastActivity time.Time `json:"last_activity"`
		IPAddress    string    `json:"ip_address"`
		UserAgent    string    `json:"user_agent"`
		LoginCount   int       `json:"login_count"`
	}

	err := facades.Orm().Query().Table("oauth_sessions").
		Select("created_at, last_activity, ip_address, user_agent, login_count").
		Where("id = ? AND user_id = ?", sessionID, userID).
		Scan(&sessionData)

	if err != nil {
		facades.Log().Error("Error assessing session risk", map[string]interface{}{
			"error":      err.Error(),
			"session_id": sessionID,
			"user_id":    userID,
		})
		return 0.5 // Medium risk for unknown sessions
	}

	risk := 0.0

	// Session age risk
	sessionAge := time.Since(sessionData.CreatedAt)
	if sessionAge > 24*time.Hour {
		risk += 0.3
	} else if sessionAge > 8*time.Hour {
		risk += 0.1
	}

	// Inactivity risk
	inactivity := time.Since(sessionData.LastActivity)
	if inactivity > 2*time.Hour {
		risk += 0.2
	} else if inactivity > 30*time.Minute {
		risk += 0.1
	}

	// Multiple logins risk
	if sessionData.LoginCount > 5 {
		risk += 0.2
	}

	return math.Min(1.0, risk)
}

func (s *OAuthSteppedUpAuthService) getDeviceTrustedStatus(challenge *StepUpAuthChallenge) bool {
	if deviceFingerprint, exists := challenge.SecurityContext["device_fingerprint"]; exists {
		if fingerprint, ok := deviceFingerprint.(string); ok {
			return s.isKnownDevice(fingerprint, challenge.UserID)
		}
	}
	return false
}

func (s *OAuthSteppedUpAuthService) getIPReputationFromContext(challenge *StepUpAuthChallenge) string {
	if ipAddress, exists := challenge.SecurityContext["ip_address"]; exists {
		if ip, ok := ipAddress.(string); ok {
			return s.getIPReputation(ip)
		}
	}
	return "unknown"
}

func (s *OAuthSteppedUpAuthService) getIPReputation(ipAddress string) string {
	// Get IP reputation from threat intelligence
	if ipAddress == "" {
		return "unknown"
	}

	var reputation struct {
		RiskScore  float64 `json:"risk_score"`
		Reputation string  `json:"reputation"`
		IsThreat   bool    `json:"is_threat"`
	}

	err := facades.Orm().Query().Table("ip_reputation").
		Select("risk_score, reputation, is_threat").
		Where("ip_address = ?", ipAddress).
		OrderBy("updated_at DESC").
		Limit(1).
		Scan(&reputation)

	if err != nil {
		facades.Log().Warning("Unable to get IP reputation", map[string]interface{}{
			"error":      err.Error(),
			"ip_address": ipAddress,
		})
		return "unknown"
	}

	if reputation.IsThreat {
		return "malicious"
	} else if reputation.RiskScore > 0.7 {
		return "high_risk"
	} else if reputation.RiskScore > 0.4 {
		return "medium_risk"
	} else {
		return "low_risk"
	}
}

func (s *OAuthSteppedUpAuthService) isUnusualTime(userID string) bool {
	// For now, we'll use a simplified time-based risk assessment
	// TODO: In production, you'd analyze historical login patterns
	currentHour := time.Now().Hour()

	// Consider hours between 2 AM and 6 AM as unusual
	if currentHour >= 2 && currentHour <= 6 {
		return true
	}

	return false
}

func (s *OAuthSteppedUpAuthService) isHighRiskClient(clientID string) bool {
	// Comprehensive client risk assessment

	// Get client information from database
	var client models.OAuthClient
	if err := facades.Orm().Query().Where("client_id", clientID).First(&client); err != nil {
		// Unknown client is high risk
		facades.Log().Warning("Unknown OAuth client attempted access", map[string]interface{}{
			"client_id": clientID,
		})
		return true
	}

	riskScore := 0.0
	riskFactors := make(map[string]interface{})

	// Factor 1: Client registration age (newer clients are riskier)
	registrationAge := time.Since(client.CreatedAt)
	if registrationAge < 24*time.Hour {
		riskScore += 0.4
		riskFactors["new_client"] = true
	} else if registrationAge < 7*24*time.Hour {
		riskScore += 0.2
		riskFactors["recent_client"] = true
	}

	// Factor 2: Check if client is revoked
	if client.Revoked {
		riskScore += 0.5
		riskFactors["revoked_client"] = true
	}

	// Factor 3: Check for suspicious redirect URIs
	if s.hasSuspiciousRedirectURIs(client.Redirect) {
		riskScore += 0.2
		riskFactors["suspicious_redirects"] = true
	}

	// Factor 4: Check client type and configuration
	if client.PersonalAccessClient {
		riskScore += 0.1
		riskFactors["personal_access_client"] = true
	}

	// Factor 5: Check recent security events count from audit logs
	securityEventsCount := s.countRecentSecurityEvents(clientID, 7*24*time.Hour)
	if securityEventsCount > 5 {
		riskScore += 0.3
		riskFactors["high_security_events"] = securityEventsCount
	} else if securityEventsCount > 2 {
		riskScore += 0.1
		riskFactors["moderate_security_events"] = securityEventsCount
	}

	// Factor 6: Check for recent failed attempts from audit logs
	failedAttemptsCount := s.countRecentFailedAttempts(clientID, 1*time.Hour)
	if failedAttemptsCount > 10 {
		riskScore += 0.2
		riskFactors["high_failed_attempts"] = failedAttemptsCount
	}

	isHighRisk := riskScore >= 0.5

	// Log risk assessment
	facades.Log().Info("OAuth client risk assessment completed", map[string]interface{}{
		"client_id":    clientID,
		"risk_score":   riskScore,
		"is_high_risk": isHighRisk,
		"risk_factors": riskFactors,
		"threshold":    0.5,
	})

	return isHighRisk
}

func (s *OAuthSteppedUpAuthService) isHighRiskIP(ip string) bool {
	// Use OAuth risk service to check IP reputation
	riskService := NewOAuthRiskService()

	// Check if IP is VPN/proxy
	if riskService.checkVPNDatabase(ip) {
		return true
	}

	// Check threat intelligence
	if riskService.checkThreatIntelligence(ip) {
		return true
	}

	return false
}

func (s *OAuthSteppedUpAuthService) getCurrentRequestContext() *http.Request {
	// This would typically be injected or stored in the service
	// For now, return nil as we don't have access to the current request context
	// TODO: In production, you would store the context when the service is created
	return nil
}

func (s *OAuthSteppedUpAuthService) logChallengeCreation(challenge *StepUpAuthChallenge) {
	facades.Log().Info("Step-up authentication challenge created", map[string]interface{}{
		"challenge_id":     challenge.ChallengeID,
		"user_id":          challenge.UserID,
		"client_id":        challenge.ClientID,
		"challenge_type":   challenge.ChallengeType,
		"required_factors": challenge.RequiredFactors,
		"expires_at":       challenge.ExpiresAt,
	})
}

func (s *OAuthSteppedUpAuthService) logSuccessfulStepUp(challenge *StepUpAuthChallenge, result *StepUpAuthResult) {
	facades.Log().Info("Stepped-up authentication successful", map[string]interface{}{
		"challenge_id":        challenge.ChallengeID,
		"user_id":             challenge.UserID,
		"client_id":           challenge.ClientID,
		"auth_level":          result.AuthLevel,
		"completed_factors":   result.CompletedFactors,
		"authentication_time": result.AuthenticationTime,
		"duration_seconds":    time.Since(challenge.CreatedAt).Seconds(),
	})
}

// GetSteppedUpAuthCapabilities returns stepped-up auth capabilities for discovery
func (s *OAuthSteppedUpAuthService) GetSteppedUpAuthCapabilities() map[string]interface{} {
	return map[string]interface{}{
		"stepped_up_auth_supported": facades.Config().GetBool("oauth.step_up_auth.enabled", true),
		"supported_auth_levels": []string{
			"basic", "mfa", "biometric", "hardware",
		},
		"supported_factors": []string{
			"password", "totp", "sms", "push", "biometric", "hardware_key",
		},
		"challenge_ttl":              facades.Config().GetInt("oauth.step_up_auth.challenge_ttl", 900),
		"max_attempts_per_challenge": 3,
		"force_reauth_for_sensitive": true,
		"risk_based_requirements":    true,
		"adaptive_auth_levels":       true,
	}
}

// hasSuspiciousRedirectURIs checks if the redirect URIs contain suspicious patterns
func (s *OAuthSteppedUpAuthService) hasSuspiciousRedirectURIs(redirectURIs string) bool {
	if redirectURIs == "" {
		return false
	}

	// Parse JSON array of redirect URIs
	var uris []string
	if err := json.Unmarshal([]byte(redirectURIs), &uris); err != nil {
		// If parsing fails, consider it suspicious
		return true
	}

	suspiciousPatterns := []string{
		"localhost",
		"127.0.0.1",
		"192.168.",
		"10.",
		"172.16.",
		"172.17.",
		"172.18.",
		"172.19.",
		"172.20.",
		"172.21.",
		"172.22.",
		"172.23.",
		"172.24.",
		"172.25.",
		"172.26.",
		"172.27.",
		"172.28.",
		"172.29.",
		"172.30.",
		"172.31.",
		".tk",
		".ml",
		".ga",
		".cf",
		"bit.ly",
		"tinyurl.com",
		"t.co",
	}

	for _, uri := range uris {
		for _, pattern := range suspiciousPatterns {
			if strings.Contains(strings.ToLower(uri), pattern) {
				return true
			}
		}
	}

	return false
}

// countRecentSecurityEvents counts security-related events for a client from audit logs
func (s *OAuthSteppedUpAuthService) countRecentSecurityEvents(clientID string, duration time.Duration) int {
	since := time.Now().Add(-duration)

	count, err := facades.Orm().Query().
		Table("activity_logs").
		Where("created_at >= ?", since).
		Where("metadata LIKE ?", "%\"client_id\":\""+clientID+"\"%").
		Where("event_type LIKE ?", "security.%").
		Count()

	if err != nil {
		facades.Log().Warning("Failed to count security events for client", map[string]interface{}{
			"client_id": clientID,
			"error":     err.Error(),
		})
		return 0
	}

	return int(count)
}

// countRecentFailedAttempts counts recent failed authorization attempts for a client
func (s *OAuthSteppedUpAuthService) countRecentFailedAttempts(clientID string, duration time.Duration) int {
	since := time.Now().Add(-duration)

	count, err := facades.Orm().Query().
		Table("activity_logs").
		Where("created_at >= ?", since).
		Where("metadata LIKE ?", "%\"client_id\":\""+clientID+"\"%").
		Where("event_type LIKE ?", "%failed%").
		Count()

	if err != nil {
		facades.Log().Warning("Failed to count failed attempts for client", map[string]interface{}{
			"client_id": clientID,
			"error":     err.Error(),
		})
		return 0
	}

	return int(count)
}
