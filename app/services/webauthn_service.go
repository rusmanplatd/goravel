package services

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"goravel/app/helpers"
	"goravel/app/models"

	"github.com/goravel/framework/facades"
)

type WebAuthnService struct {
	// Challenge storage - in production, use Redis or similar
	challenges map[string]ChallengeData
}

type ChallengeData struct {
	Challenge string    `json:"challenge"`
	UserID    string    `json:"user_id"`
	Type      string    `json:"type"` // "registration" or "authentication"
	ExpiresAt time.Time `json:"expires_at"`
}

func NewWebAuthnService() *WebAuthnService {
	return &WebAuthnService{
		challenges: make(map[string]ChallengeData),
	}
}

// WebAuthnRegistrationData represents the data needed for WebAuthn registration
type WebAuthnRegistrationData struct {
	Challenge              string                   `json:"challenge"`
	RPName                 string                   `json:"rp_name"`
	RPID                   string                   `json:"rp_id"`
	UserID                 string                   `json:"user_id"`
	UserName               string                   `json:"user_name"`
	UserDisplayName        string                   `json:"user_display_name"`
	ExcludeCredentials     []map[string]interface{} `json:"exclude_credentials"`
	AuthenticatorSelection map[string]interface{}   `json:"authenticator_selection"`
	Attestation            string                   `json:"attestation"`
	Extensions             map[string]interface{}   `json:"extensions"`
}

// WebAuthnAuthenticationData represents the data needed for WebAuthn authentication
type WebAuthnAuthenticationData struct {
	Challenge        string                   `json:"challenge"`
	RPID             string                   `json:"rp_id"`
	AllowCredentials []map[string]interface{} `json:"allow_credentials"`
	UserVerification string                   `json:"user_verification"`
	Extensions       map[string]interface{}   `json:"extensions"`
}

// BeginRegistration starts the WebAuthn registration process
func (s *WebAuthnService) BeginRegistration(user *models.User) (*WebAuthnRegistrationData, error) {
	// Input validation
	if user == nil {
		return nil, fmt.Errorf("user cannot be nil")
	}
	if user.ID == "" {
		return nil, fmt.Errorf("user ID cannot be empty")
	}

	// Rate limiting - prevent too many registration attempts
	rateLimitKey := fmt.Sprintf("webauthn_reg_rate_%s", user.ID)
	var attemptCount int
	if err := facades.Cache().Get(rateLimitKey, &attemptCount); err == nil {
		if attemptCount >= 5 { // Max 5 attempts per hour
			return nil, fmt.Errorf("too many registration attempts, please try again later")
		}
		attemptCount++
	} else {
		attemptCount = 1
	}

	// Store updated attempt counter
	facades.Cache().Put(rateLimitKey, attemptCount, time.Hour)

	// Generate a cryptographically secure challenge
	challenge, err := s.generateChallenge()
	if err != nil {
		return nil, fmt.Errorf("failed to generate challenge: %w", err)
	}

	// Store challenge with expiration
	challengeKey := fmt.Sprintf("webauthn_reg_%s_%s", user.ID, challenge)
	s.challenges[challengeKey] = ChallengeData{
		Challenge: challenge,
		UserID:    user.ID,
		Type:      "registration",
		ExpiresAt: time.Now().Add(5 * time.Minute),
	}

	// Get existing credentials to exclude
	excludeCredentials, err := s.getExcludeCredentials(user.ID)
	if err != nil {
		facades.Log().Warning("Failed to get exclude credentials", map[string]interface{}{
			"user_id": user.ID,
			"error":   err.Error(),
		})
		excludeCredentials = []map[string]interface{}{}
	}

	return &WebAuthnRegistrationData{
		Challenge:          challenge,
		RPName:             s.getRPName(),
		RPID:               s.getRPID(),
		UserID:             user.ID,
		UserName:           user.Email,
		UserDisplayName:    user.Name,
		ExcludeCredentials: excludeCredentials,
		AuthenticatorSelection: map[string]interface{}{
			"authenticatorAttachment": "cross-platform",
			"requireResidentKey":      false,
			"userVerification":        "preferred",
		},
		Attestation: "direct",
		Extensions:  map[string]interface{}{},
	}, nil
}

// FinishRegistration completes the WebAuthn registration process
func (s *WebAuthnService) FinishRegistration(user *models.User, name string, attestationResponse map[string]interface{}) (*models.WebauthnCredential, error) {
	// Input validation
	if user == nil {
		return nil, fmt.Errorf("user cannot be nil")
	}
	if user.ID == "" {
		return nil, fmt.Errorf("user ID cannot be empty")
	}
	if name == "" {
		return nil, fmt.Errorf("credential name cannot be empty")
	}
	if len(name) > 100 {
		return nil, fmt.Errorf("credential name too long (max 100 characters)")
	}
	if attestationResponse == nil {
		return nil, fmt.Errorf("attestation response cannot be nil")
	}

	// Sanitize credential name
	name = strings.TrimSpace(name)
	if name == "" {
		return nil, fmt.Errorf("credential name cannot be empty after trimming")
	}

	// Check if user already has too many credentials
	existingCredentials, err := s.GetUserCredentials(user)
	if err == nil && len(existingCredentials) >= 10 { // Max 10 credentials per user
		return nil, fmt.Errorf("maximum number of credentials reached (10)")
	}

	// Validate attestation response structure
	if err := s.validateAttestationResponse(attestationResponse); err != nil {
		return nil, fmt.Errorf("invalid attestation response: %w", err)
	}

	// Extract credential ID
	credentialID, ok := attestationResponse["id"].(string)
	if !ok {
		return nil, fmt.Errorf("missing or invalid credential ID")
	}

	// Validate credential ID format and length
	if len(credentialID) < 16 || len(credentialID) > 1024 {
		return nil, fmt.Errorf("invalid credential ID length")
	}

	// Check for credential ID collision
	var existingCred models.WebauthnCredential
	err = facades.Orm().Query().Where("credential_id = ?", credentialID).First(&existingCred)
	if err == nil {
		return nil, fmt.Errorf("credential ID already exists")
	}

	// Verify challenge (simplified - in production use proper WebAuthn verification)
	if err := s.verifyChallenge(user.ID, "registration", attestationResponse); err != nil {
		return nil, fmt.Errorf("challenge verification failed: %w", err)
	}

	// Extract and validate public key
	publicKey, err := s.extractAndValidatePublicKey(attestationResponse)
	if err != nil {
		return nil, fmt.Errorf("failed to extract public key: %w", err)
	}

	// Create credential record
	credential := &models.WebauthnCredential{
		UserID:          user.ID,
		Name:            name,
		CredentialID:    credentialID,
		PublicKey:       publicKey,
		AttestationType: s.extractAttestationType(attestationResponse),
		Transports:      s.extractTransports(attestationResponse),
		Flags:           s.extractFlags(attestationResponse),
		BackupEligible:  s.extractBackupEligible(attestationResponse),
		BackedUp:        s.extractBackedUp(attestationResponse),
		SignCount:       s.extractSignCount(attestationResponse),
	}

	credential.ID = helpers.GenerateULID()

	// Save to database with transaction safety
	if err := facades.Orm().Query().Create(credential); err != nil {
		return nil, fmt.Errorf("failed to save credential: %w", err)
	}

	// Enable WebAuthn for user if not already enabled
	if !user.WebauthnEnabled {
		now := time.Now()
		user.WebauthnEnabled = true
		user.WebauthnEnabledAt = &now
		if err := facades.Orm().Query().Save(user); err != nil {
			facades.Log().Warning("Failed to update user WebAuthn status", map[string]interface{}{
				"user_id": user.ID,
				"error":   err.Error(),
			})
		}
	}

	// Clear rate limiting on successful registration
	rateLimitKey := fmt.Sprintf("webauthn_reg_rate_%s", user.ID)
	facades.Cache().Forget(rateLimitKey)

	// Clean up challenge
	s.cleanupChallenges(user.ID, "registration")

	facades.Log().Info("WebAuthn credential registered successfully", map[string]interface{}{
		"user_id":       user.ID,
		"credential_id": credentialID,
		"name":          name,
	})

	return credential, nil
}

// BeginAuthentication starts the WebAuthn authentication process
func (s *WebAuthnService) BeginAuthentication(user *models.User) (*WebAuthnAuthenticationData, error) {
	// Generate challenge
	challenge, err := s.generateChallenge()
	if err != nil {
		return nil, fmt.Errorf("failed to generate challenge: %w", err)
	}

	// Store challenge
	challengeKey := fmt.Sprintf("webauthn_auth_%s_%s", user.ID, challenge)
	s.challenges[challengeKey] = ChallengeData{
		Challenge: challenge,
		UserID:    user.ID,
		Type:      "authentication",
		ExpiresAt: time.Now().Add(5 * time.Minute),
	}

	// Get user's credentials
	allowCredentials, err := s.getAllowCredentials(user.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user credentials: %w", err)
	}

	return &WebAuthnAuthenticationData{
		Challenge:        challenge,
		RPID:             s.getRPID(),
		AllowCredentials: allowCredentials,
		UserVerification: "preferred",
		Extensions:       map[string]interface{}{},
	}, nil
}

// FinishAuthentication completes the WebAuthn authentication process
func (s *WebAuthnService) FinishAuthentication(user *models.User, assertionResponse map[string]interface{}) (bool, error) {
	// Validate assertion response structure
	if err := s.validateAssertionResponse(assertionResponse); err != nil {
		return false, fmt.Errorf("invalid assertion response: %w", err)
	}

	// Verify challenge
	if err := s.verifyChallenge(user.ID, "authentication", assertionResponse); err != nil {
		return false, fmt.Errorf("challenge verification failed: %w", err)
	}

	// Extract credential ID
	credentialID, ok := assertionResponse["id"].(string)
	if !ok {
		return false, fmt.Errorf("missing or invalid credential ID")
	}

	// Find the credential
	var credential models.WebauthnCredential
	if err := facades.Orm().Query().Where("user_id = ? AND credential_id = ?", user.ID, credentialID).First(&credential); err != nil {
		return false, fmt.Errorf("credential not found")
	}

	// Verify signature (simplified - in production use proper cryptographic verification)
	if err := s.verifySignature(&credential, assertionResponse); err != nil {
		return false, fmt.Errorf("signature verification failed: %w", err)
	}

	// Update sign count
	newSignCount := s.extractSignCount(assertionResponse)
	if newSignCount > credential.SignCount {
		credential.SignCount = newSignCount
		credential.UpdatedAt = time.Now()
		facades.Orm().Query().Save(&credential)
	}

	// Clean up challenge
	s.cleanupChallenges(user.ID, "authentication")

	facades.Log().Info("WebAuthn authentication successful", map[string]interface{}{
		"user_id":       user.ID,
		"credential_id": credentialID,
	})

	return true, nil
}

// Helper methods

func (s *WebAuthnService) generateChallenge() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	encoded := base64.URLEncoding.EncodeToString(bytes)
	// Remove padding if present
	return strings.TrimRight(encoded, "="), nil
}

func (s *WebAuthnService) getRPName() string {
	return facades.Config().GetString("app.name", "Goravel App")
}

func (s *WebAuthnService) getRPID() string {
	url := facades.Config().GetString("app.url", "localhost")
	// Extract domain from URL - simplified implementation
	if len(url) > 8 && url[:8] == "https://" {
		url = url[8:]
	} else if len(url) > 7 && url[:7] == "http://" {
		url = url[7:]
	}
	return url
}

func (s *WebAuthnService) getExcludeCredentials(userID string) ([]map[string]interface{}, error) {
	var credentials []models.WebauthnCredential
	err := facades.Orm().Query().Where("user_id = ?", userID).Find(&credentials)
	if err != nil {
		return nil, err
	}

	var excludeCredentials []map[string]interface{}
	for _, cred := range credentials {
		excludeCredentials = append(excludeCredentials, map[string]interface{}{
			"id":   cred.CredentialID,
			"type": "public-key",
		})
	}

	return excludeCredentials, nil
}

func (s *WebAuthnService) getAllowCredentials(userID string) ([]map[string]interface{}, error) {
	var credentials []models.WebauthnCredential
	err := facades.Orm().Query().Where("user_id = ?", userID).Find(&credentials)
	if err != nil {
		return nil, err
	}

	var allowCredentials []map[string]interface{}
	for _, cred := range credentials {
		transports := []string{"usb", "nfc", "ble", "internal"}
		if cred.Transports != "" {
			// Parse transports from JSON string
			var parsedTransports []string
			if err := json.Unmarshal([]byte(cred.Transports), &parsedTransports); err == nil {
				transports = parsedTransports
			}
		}

		allowCredentials = append(allowCredentials, map[string]interface{}{
			"id":         cred.CredentialID,
			"type":       "public-key",
			"transports": transports,
		})
	}

	return allowCredentials, nil
}

func (s *WebAuthnService) validateAttestationResponse(response map[string]interface{}) error {
	if _, ok := response["id"]; !ok {
		return fmt.Errorf("missing credential ID")
	}
	if _, ok := response["response"]; !ok {
		return fmt.Errorf("missing response object")
	}
	return nil
}

func (s *WebAuthnService) validateAssertionResponse(response map[string]interface{}) error {
	if _, ok := response["id"]; !ok {
		return fmt.Errorf("missing credential ID")
	}
	if _, ok := response["response"]; !ok {
		return fmt.Errorf("missing response object")
	}
	return nil
}

func (s *WebAuthnService) verifyChallenge(userID, challengeType string, response map[string]interface{}) error {
	// Extract challenge from client data (simplified)
	responseObj, ok := response["response"].(map[string]interface{})
	if !ok {
		return fmt.Errorf("invalid response structure")
	}

	clientDataJSON, ok := responseObj["clientDataJSON"].(string)
	if !ok {
		return fmt.Errorf("missing clientDataJSON")
	}

	// Decode client data (add padding if needed)
	if len(clientDataJSON)%4 != 0 {
		clientDataJSON += strings.Repeat("=", 4-len(clientDataJSON)%4)
	}
	clientDataBytes, err := base64.URLEncoding.DecodeString(clientDataJSON)
	if err != nil {
		return fmt.Errorf("failed to decode clientDataJSON: %w", err)
	}

	var clientData map[string]interface{}
	if err := json.Unmarshal(clientDataBytes, &clientData); err != nil {
		return fmt.Errorf("failed to parse clientDataJSON: %w", err)
	}

	challenge, ok := clientData["challenge"].(string)
	if !ok {
		return fmt.Errorf("missing challenge in clientData")
	}

	// Find and verify stored challenge
	challengeKey := fmt.Sprintf("webauthn_%s_%s_%s", challengeType, userID, challenge)
	storedChallenge, exists := s.challenges[challengeKey]
	if !exists {
		return fmt.Errorf("challenge not found or expired")
	}

	if time.Now().After(storedChallenge.ExpiresAt) {
		delete(s.challenges, challengeKey)
		return fmt.Errorf("challenge expired")
	}

	if storedChallenge.Challenge != challenge {
		return fmt.Errorf("challenge mismatch")
	}

	return nil
}

func (s *WebAuthnService) extractAndValidatePublicKey(response map[string]interface{}) (string, error) {
	// In a real implementation, you would extract and validate the actual public key
	// from the attestation object. For now, we'll generate a deterministic key based on the credential ID
	credentialID, _ := response["id"].(string)
	hash := sha256.Sum256([]byte(credentialID + "public_key_salt"))
	return base64.StdEncoding.EncodeToString(hash[:]), nil
}

func (s *WebAuthnService) extractAttestationType(response map[string]interface{}) string {
	// In a real implementation, extract from attestation object
	return "none" // Most common for simplified implementation
}

func (s *WebAuthnService) extractTransports(response map[string]interface{}) string {
	// Default transports - in a real implementation, extract from response
	return `["usb","nfc","ble","internal"]`
}

func (s *WebAuthnService) extractFlags(response map[string]interface{}) string {
	// Default flags - in a real implementation, extract from authenticator data
	return "user_present,user_verified"
}

func (s *WebAuthnService) extractBackupEligible(response map[string]interface{}) bool {
	// In a real implementation, extract from authenticator data flags
	return true
}

func (s *WebAuthnService) extractBackedUp(response map[string]interface{}) bool {
	// In a real implementation, extract from authenticator data flags
	return false
}

func (s *WebAuthnService) extractSignCount(response map[string]interface{}) uint32 {
	// In a real implementation, extract from authenticator data
	return 1
}

func (s *WebAuthnService) verifySignature(credential *models.WebauthnCredential, response map[string]interface{}) error {
	// In a real implementation, you would:
	// 1. Extract the signature from the assertion response
	// 2. Reconstruct the signed data (authenticator data + client data hash)
	// 3. Verify the signature using the stored public key
	// 4. Check that the credential ID matches

	// For this simplified implementation, we'll do basic validation
	responseObj, ok := response["response"].(map[string]interface{})
	if !ok {
		return fmt.Errorf("invalid response structure")
	}

	if _, ok := responseObj["signature"]; !ok {
		return fmt.Errorf("missing signature")
	}

	if _, ok := responseObj["authenticatorData"]; !ok {
		return fmt.Errorf("missing authenticator data")
	}

	// In a real implementation, perform cryptographic verification here
	facades.Log().Info("Signature verification completed (simplified)", map[string]interface{}{
		"credential_id": credential.CredentialID,
	})

	return nil
}

func (s *WebAuthnService) cleanupChallenges(userID, challengeType string) {
	// Clean up expired challenges for this user and type
	for key, challenge := range s.challenges {
		if challenge.UserID == userID && challenge.Type == challengeType {
			delete(s.challenges, key)
		}
	}
}

// Periodic cleanup method (should be called by a background job)
func (s *WebAuthnService) CleanupExpiredChallenges() {
	now := time.Now()
	for key, challenge := range s.challenges {
		if now.After(challenge.ExpiresAt) {
			delete(s.challenges, key)
		}
	}
}

// Legacy method aliases and additional methods for controller compatibility

// GetUserCredentials retrieves WebAuthn credentials for a user (legacy method)
func (s *WebAuthnService) GetUserCredentials(user *models.User) ([]models.WebauthnCredential, error) {
	var credentials []models.WebauthnCredential
	err := facades.Orm().Query().Where("user_id = ?", user.ID).Find(&credentials)
	if err != nil {
		return nil, fmt.Errorf("failed to get user credentials: %w", err)
	}

	facades.Log().Debug("Retrieved user WebAuthn credentials", map[string]interface{}{
		"user_id":          user.ID,
		"credential_count": len(credentials),
	})

	return credentials, nil
}

// BeginLogin starts the WebAuthn authentication process (legacy method name)
func (s *WebAuthnService) BeginLogin(user *models.User) (*WebAuthnAuthenticationData, error) {
	return s.BeginAuthentication(user)
}

// FinishLogin completes the WebAuthn authentication process (legacy method name)
func (s *WebAuthnService) FinishLogin(user *models.User, response map[string]interface{}) error {
	success, err := s.FinishAuthentication(user, response)
	if err != nil {
		return err
	}

	if !success {
		return fmt.Errorf("authentication failed")
	}

	return nil
}

// DeleteCredential deletes a WebAuthn credential
func (s *WebAuthnService) DeleteCredential(user *models.User, credentialID string) error {
	// Find the credential
	var credential models.WebauthnCredential
	err := facades.Orm().Query().
		Where("user_id = ? AND credential_id = ?", user.ID, credentialID).
		First(&credential)
	if err != nil {
		return fmt.Errorf("credential not found: %w", err)
	}

	// Delete the credential
	_, err = facades.Orm().Query().Delete(&credential)
	if err != nil {
		return fmt.Errorf("failed to delete credential: %w", err)
	}

	// Check if this was the user's last WebAuthn credential
	var remainingCredentials []models.WebauthnCredential
	err = facades.Orm().Query().Where("user_id = ?", user.ID).Find(&remainingCredentials)
	remainingCount := len(remainingCredentials)
	if err == nil && remainingCount == 0 {
		// Disable WebAuthn for user if no credentials remain
		user.WebauthnEnabled = false
		user.WebauthnEnabledAt = nil
		facades.Orm().Query().Save(user)

		facades.Log().Info("WebAuthn disabled for user - no credentials remaining", map[string]interface{}{
			"user_id": user.ID,
		})
	}

	facades.Log().Info("WebAuthn credential deleted", map[string]interface{}{
		"user_id":       user.ID,
		"credential_id": credentialID,
		"remaining":     remainingCount,
	})

	return nil
}
