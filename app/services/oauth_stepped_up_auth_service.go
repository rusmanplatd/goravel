package services

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

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

func NewOAuthSteppedUpAuthService() *OAuthSteppedUpAuthService {
	return &OAuthSteppedUpAuthService{
		oauthService:   NewOAuthService(),
		authService:    NewAuthService(),
		riskService:    NewOAuthRiskService(),
		sessionService: NewSessionService(),
	}
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
		s.updateUserAuthLevel(challenge.UserID, "", result.AuthLevel, result.ExpiresAt)

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
	// Simplified - in production, retrieve from session/database
	// For now, return basic level
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

	// In production, validate against user's password
	// This is a simplified validation
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

	// In production, validate TOTP code
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

	// In production, validate SMS code
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

	// In production, validate biometric data
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

	// In production, validate hardware key response
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

// Simplified validation methods (in production, these would be more robust)
func (s *OAuthSteppedUpAuthService) validateUserPassword(userID, password string) bool {
	// Simplified password validation
	return len(password) >= 8
}

func (s *OAuthSteppedUpAuthService) validateTOTPCode(userID, code string) bool {
	// Simplified TOTP validation
	return len(code) == 6
}

func (s *OAuthSteppedUpAuthService) validateSMSCode(userID, code string) bool {
	// Simplified SMS validation
	return len(code) == 6
}

func (s *OAuthSteppedUpAuthService) validateBiometricData(userID, data string) bool {
	// Simplified biometric validation
	return len(data) > 0
}

func (s *OAuthSteppedUpAuthService) validateHardwareKeyResponse(userID, response string) bool {
	// Simplified hardware key validation
	return len(response) > 0
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
	// Simplified risk assessment
	return map[string]interface{}{
		"score":         10,
		"level":         "LOW",
		"factors_used":  len(challenge.CompletedFactors),
		"auth_strength": s.calculateAuthLevel(challenge.CompletedFactors),
		"assessed_at":   time.Now().Unix(),
	}
}

func (s *OAuthSteppedUpAuthService) updateUserAuthLevel(userID, sessionID, authLevel string, expiresAt time.Time) {
	// In production, update user session/database
	facades.Log().Info("User authentication level updated", map[string]interface{}{
		"user_id":    userID,
		"session_id": sessionID,
		"auth_level": authLevel,
		"expires_at": expiresAt,
	})
}

func (s *OAuthSteppedUpAuthService) getLastAuthTime(userID, sessionID string) time.Time {
	// Simplified - in production, get from session/database
	return time.Now().Add(-time.Hour) // Assume 1 hour ago
}

func (s *OAuthSteppedUpAuthService) getClientIP() string {
	return "127.0.0.1" // Simplified
}

func (s *OAuthSteppedUpAuthService) getUserAgent() string {
	return "Mozilla/5.0" // Simplified
}

func (s *OAuthSteppedUpAuthService) getRiskScore(userID, clientID string) int {
	return 15 // Simplified
}

func (s *OAuthSteppedUpAuthService) getDeviceID() string {
	return "device_123" // Simplified
}

func (s *OAuthSteppedUpAuthService) getLocation() string {
	return "US" // Simplified
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
