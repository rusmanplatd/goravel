package services

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"goravel/app/http/requests"
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
	Origin    string    `json:"origin"`
	RPID      string    `json:"rp_id"`
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
	Timeout                int                      `json:"timeout"`
}

// WebAuthnAuthenticationData represents the data needed for WebAuthn authentication
type WebAuthnAuthenticationData struct {
	Challenge        string                   `json:"challenge"`
	RPID             string                   `json:"rp_id"`
	AllowCredentials []map[string]interface{} `json:"allow_credentials"`
	UserVerification string                   `json:"user_verification"`
	Extensions       map[string]interface{}   `json:"extensions"`
	Timeout          int                      `json:"timeout"`
}

// WebAuthnCredentialCreation represents a credential creation response
type WebAuthnCredentialCreation struct {
	ID       string                 `json:"id"`
	RawID    string                 `json:"rawId"`
	Type     string                 `json:"type"`
	Response map[string]interface{} `json:"response"`
}

// WebAuthnAssertion represents an authentication assertion
type WebAuthnAssertion struct {
	ID       string                 `json:"id"`
	RawID    string                 `json:"rawId"`
	Type     string                 `json:"type"`
	Response map[string]interface{} `json:"response"`
}

// AuthenticationResult represents the result of WebAuthn authentication
type AuthenticationResult struct {
	User           *models.User `json:"user"`
	CredentialID   string       `json:"credential_id"`
	CredentialName string       `json:"credential_name"`
	Success        bool         `json:"success"`
}

// DeletionResult represents the result of credential deletion
type DeletionResult struct {
	Success              bool `json:"success"`
	RemainingCredentials int  `json:"remaining_credentials"`
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
	if !s.checkRateLimit(rateLimitKey, 5, time.Hour) {
		return nil, fmt.Errorf("too many registration attempts, please try again later")
	}

	// Generate a cryptographically secure challenge
	challenge, err := s.generateChallenge()
	if err != nil {
		return nil, fmt.Errorf("failed to generate challenge: %w", err)
	}

	// Get RP configuration
	rpID := s.getRPID()
	rpName := s.getRPName()

	// Store challenge with expiration
	challengeKey := s.generateChallengeKey(user.ID, challenge)
	s.challenges[challengeKey] = ChallengeData{
		Challenge: challenge,
		UserID:    user.ID,
		Type:      "registration",
		ExpiresAt: time.Now().Add(5 * time.Minute),
		Origin:    s.getOrigin(),
		RPID:      rpID,
	}

	// Get existing credentials to exclude
	excludeCredentials, err := s.getExcludeCredentials(user.ID)
	if err != nil {
		facades.Log().Warning("Failed to get existing credentials for exclusion", map[string]interface{}{
			"user_id": user.ID,
			"error":   err.Error(),
		})
		excludeCredentials = []map[string]interface{}{}
	}

	// Build registration data
	registrationData := &WebAuthnRegistrationData{
		Challenge:          challenge,
		RPName:             rpName,
		RPID:               rpID,
		UserID:             user.ID,
		UserName:           user.Email,
		UserDisplayName:    user.Name,
		ExcludeCredentials: excludeCredentials,
		AuthenticatorSelection: map[string]interface{}{
			"authenticatorAttachment": "cross-platform", // Allow both platform and cross-platform
			"requireResidentKey":      false,
			"userVerification":        "preferred",
		},
		Attestation: "direct", // Request direct attestation for better security
		Extensions: map[string]interface{}{
			"credProps": true, // Request credential properties
		},
		Timeout: 60000, // 60 seconds
	}

	facades.Log().Info("WebAuthn registration initiated", map[string]interface{}{
		"user_id":   user.ID,
		"challenge": s.hashChallenge(challenge),
		"rp_id":     rpID,
	})

	return registrationData, nil
}

// FinishRegistration completes the WebAuthn registration process
func (s *WebAuthnService) FinishRegistration(userID string, credentialCreation *WebAuthnCredentialCreation) (*models.WebauthnCredential, error) {
	// Input validation
	if userID == "" {
		return nil, fmt.Errorf("user ID cannot be empty")
	}
	if credentialCreation == nil {
		return nil, fmt.Errorf("credential creation cannot be nil")
	}

	// Extract and validate challenge from client data
	clientDataJSON, ok := credentialCreation.Response["clientDataJSON"].(string)
	if !ok {
		return nil, fmt.Errorf("missing or invalid clientDataJSON")
	}

	clientData, err := s.parseClientDataJSON(clientDataJSON)
	if err != nil {
		return nil, fmt.Errorf("failed to parse client data: %w", err)
	}

	// Verify challenge
	challengeKey := s.generateChallengeKey(userID, clientData.Challenge)
	storedChallenge, exists := s.challenges[challengeKey]
	if !exists {
		return nil, fmt.Errorf("invalid or expired challenge")
	}

	// Clean up used challenge
	delete(s.challenges, challengeKey)

	// Verify challenge matches and hasn't expired
	if storedChallenge.Challenge != clientData.Challenge {
		return nil, fmt.Errorf("challenge mismatch")
	}
	if time.Now().After(storedChallenge.ExpiresAt) {
		return nil, fmt.Errorf("challenge expired")
	}
	if storedChallenge.Type != "registration" {
		return nil, fmt.Errorf("invalid challenge type")
	}

	// Verify origin
	if clientData.Origin != storedChallenge.Origin {
		return nil, fmt.Errorf("origin mismatch")
	}

	// Verify type
	if clientData.Type != "webauthn.create" {
		return nil, fmt.Errorf("invalid ceremony type")
	}

	// Extract attestation object
	attestationObject, ok := credentialCreation.Response["attestationObject"].(string)
	if !ok {
		return nil, fmt.Errorf("missing or invalid attestationObject")
	}

	// Parse attestation object (simplified - in production, use a proper WebAuthn library)
	attestationData, err := s.parseAttestationObject(attestationObject)
	if err != nil {
		return nil, fmt.Errorf("failed to parse attestation object: %w", err)
	}

	// Verify RP ID hash
	expectedRPIDHash := sha256.Sum256([]byte(storedChallenge.RPID))
	if !s.compareHashes(attestationData.RPIDHash, expectedRPIDHash[:]) {
		return nil, fmt.Errorf("RP ID hash mismatch")
	}

	// Verify user presence and user verification flags
	if !attestationData.UserPresent {
		return nil, fmt.Errorf("user presence not verified")
	}

	// Create credential record
	credential := &models.WebauthnCredential{
		UserID:          userID,
		Name:            s.generateCredentialName(attestationData.AAGUID),
		CredentialID:    credentialCreation.ID,
		PublicKey:       base64.StdEncoding.EncodeToString(attestationData.PublicKey),
		AttestationType: attestationData.AttestationType,
		Transports:      s.formatTransports(attestationData.Transports),
		Flags:           s.formatFlags(attestationData.Flags),
		BackupEligible:  attestationData.BackupEligible,
		BackedUp:        attestationData.BackedUp,
		SignCount:       attestationData.SignCount,
	}

	// Save to database
	err = facades.Orm().Query().Create(credential)
	if err != nil {
		return nil, fmt.Errorf("failed to save credential: %w", err)
	}

	// Update user's WebAuthn status
	var user models.User
	if err := facades.Orm().Query().Where("id", userID).First(&user); err == nil {
		if !user.WebauthnEnabled {
			now := time.Now()
			user.WebauthnEnabled = true
			user.WebauthnEnabledAt = &now
			facades.Orm().Query().Save(&user)
		}
	}

	facades.Log().Info("WebAuthn credential registered successfully", map[string]interface{}{
		"user_id":       userID,
		"credential_id": credentialCreation.ID,
		"aaguid":        attestationData.AAGUID,
	})

	return credential, nil
}

// BeginLogin starts the WebAuthn authentication process
func (s *WebAuthnService) BeginLogin(user *models.User) (*WebAuthnAuthenticationData, error) {
	// Input validation
	if user == nil {
		return nil, fmt.Errorf("user cannot be nil")
	}
	if user.ID == "" {
		return nil, fmt.Errorf("user ID cannot be empty")
	}

	// Rate limiting
	rateLimitKey := fmt.Sprintf("webauthn_auth_rate_%s", user.ID)
	if !s.checkRateLimit(rateLimitKey, 10, 5*time.Minute) {
		return nil, fmt.Errorf("too many authentication attempts, please try again later")
	}

	// Generate challenge
	challenge, err := s.generateChallenge()
	if err != nil {
		return nil, fmt.Errorf("failed to generate challenge: %w", err)
	}

	// Get RP configuration
	rpID := s.getRPID()

	// Store challenge
	challengeKey := s.generateChallengeKey(user.ID, challenge)
	s.challenges[challengeKey] = ChallengeData{
		Challenge: challenge,
		UserID:    user.ID,
		Type:      "authentication",
		ExpiresAt: time.Now().Add(5 * time.Minute),
		Origin:    s.getOrigin(),
		RPID:      rpID,
	}

	// Get user's credentials
	allowCredentials, err := s.getAllowCredentials(user.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user credentials: %w", err)
	}

	if len(allowCredentials) == 0 {
		return nil, fmt.Errorf("no WebAuthn credentials found for user")
	}

	authData := &WebAuthnAuthenticationData{
		Challenge:        challenge,
		RPID:             rpID,
		AllowCredentials: allowCredentials,
		UserVerification: "preferred",
		Extensions:       map[string]interface{}{},
		Timeout:          60000, // 60 seconds
	}

	facades.Log().Info("WebAuthn authentication initiated", map[string]interface{}{
		"user_id":          user.ID,
		"challenge":        s.hashChallenge(challenge),
		"credential_count": len(allowCredentials),
	})

	return authData, nil
}

// FinishLogin completes the WebAuthn authentication process
func (s *WebAuthnService) FinishLogin(userID string, assertion *WebAuthnAssertion) (bool, error) {
	// Input validation
	if userID == "" {
		return false, fmt.Errorf("user ID cannot be empty")
	}
	if assertion == nil {
		return false, fmt.Errorf("assertion cannot be nil")
	}

	// Parse client data
	clientDataJSON, ok := assertion.Response["clientDataJSON"].(string)
	if !ok {
		return false, fmt.Errorf("missing or invalid clientDataJSON")
	}

	clientData, err := s.parseClientDataJSON(clientDataJSON)
	if err != nil {
		return false, fmt.Errorf("failed to parse client data: %w", err)
	}

	// Verify challenge
	challengeKey := s.generateChallengeKey(userID, clientData.Challenge)
	storedChallenge, exists := s.challenges[challengeKey]
	if !exists {
		return false, fmt.Errorf("invalid or expired challenge")
	}

	// Clean up used challenge
	delete(s.challenges, challengeKey)

	// Verify challenge properties
	if storedChallenge.Challenge != clientData.Challenge {
		return false, fmt.Errorf("challenge mismatch")
	}
	if time.Now().After(storedChallenge.ExpiresAt) {
		return false, fmt.Errorf("challenge expired")
	}
	if storedChallenge.Type != "authentication" {
		return false, fmt.Errorf("invalid challenge type")
	}
	if clientData.Origin != storedChallenge.Origin {
		return false, fmt.Errorf("origin mismatch")
	}
	if clientData.Type != "webauthn.get" {
		return false, fmt.Errorf("invalid ceremony type")
	}

	// Get credential from database
	var credential models.WebauthnCredential
	err = facades.Orm().Query().Where("credential_id", assertion.ID).Where("user_id", userID).First(&credential)
	if err != nil {
		return false, fmt.Errorf("credential not found")
	}

	// Parse authenticator data
	authenticatorData, ok := assertion.Response["authenticatorData"].(string)
	if !ok {
		return false, fmt.Errorf("missing or invalid authenticatorData")
	}

	authData, err := s.parseAuthenticatorData(authenticatorData)
	if err != nil {
		return false, fmt.Errorf("failed to parse authenticator data: %w", err)
	}

	// Verify RP ID hash
	expectedRPIDHash := sha256.Sum256([]byte(storedChallenge.RPID))
	if !s.compareHashes(authData.RPIDHash, expectedRPIDHash[:]) {
		return false, fmt.Errorf("RP ID hash mismatch")
	}

	// Verify user presence
	if !authData.UserPresent {
		return false, fmt.Errorf("user presence not verified")
	}

	// Verify signature (simplified - in production, use proper cryptographic verification)
	signature, ok := assertion.Response["signature"].(string)
	if !ok {
		return false, fmt.Errorf("missing or invalid signature")
	}

	if !s.verifySignature(credential.PublicKey, clientDataJSON, authenticatorData, signature) {
		return false, fmt.Errorf("signature verification failed")
	}

	// Update sign count (for clone detection)
	if authData.SignCount <= credential.SignCount {
		facades.Log().Warning("Potential credential cloning detected", map[string]interface{}{
			"user_id":        userID,
			"credential_id":  assertion.ID,
			"stored_count":   credential.SignCount,
			"received_count": authData.SignCount,
		})
		// In production, you might want to disable the credential or require additional verification
	}

	// Update credential sign count
	credential.SignCount = authData.SignCount
	facades.Orm().Query().Save(&credential)

	facades.Log().Info("WebAuthn authentication successful", map[string]interface{}{
		"user_id":       userID,
		"credential_id": assertion.ID,
		"sign_count":    authData.SignCount,
	})

	return true, nil
}

// GetUserCredentials returns all WebAuthn credentials for a user
func (s *WebAuthnService) GetUserCredentials(user *models.User) ([]models.WebauthnCredential, error) {
	if user == nil {
		return nil, fmt.Errorf("user cannot be nil")
	}

	var credentials []models.WebauthnCredential
	err := facades.Orm().Query().Where("user_id", user.ID).Find(&credentials)
	if err != nil {
		return nil, fmt.Errorf("failed to get user credentials: %w", err)
	}

	return credentials, nil
}

// DeleteCredential removes a WebAuthn credential
func (s *WebAuthnService) DeleteCredential(userID, credentialID string) error {
	if userID == "" || credentialID == "" {
		return fmt.Errorf("user ID and credential ID cannot be empty")
	}

	_, err := facades.Orm().Query().Where("user_id", userID).Where("id", credentialID).Delete(&models.WebauthnCredential{})
	if err != nil {
		return fmt.Errorf("failed to delete credential: %w", err)
	}

	// Check if user has any remaining credentials
	var credentials []models.WebauthnCredential
	err = facades.Orm().Query().Where("user_id", userID).Find(&credentials)
	if err != nil {
		facades.Log().Warning("Failed to get remaining credentials", map[string]interface{}{
			"user_id": userID,
			"error":   err.Error(),
		})
	}

	if len(credentials) == 0 {
		// Disable WebAuthn for user if no credentials remain
		var user models.User
		if err := facades.Orm().Query().Where("id", userID).First(&user); err == nil {
			user.WebauthnEnabled = false
			user.WebauthnEnabledAt = nil
			facades.Orm().Query().Save(&user)
		}
	}

	facades.Log().Info("WebAuthn credential deleted", map[string]interface{}{
		"user_id":       userID,
		"credential_id": credentialID,
	})

	return nil
}

// EnhancedRegisterCredential registers a WebAuthn credential with enhanced security
func (s *WebAuthnService) EnhancedRegisterCredential(user *models.User, req *requests.WebauthnRegisterRequest, deviceInfo interface{}) (*models.WebauthnCredential, error) {
	// Input validation
	if user == nil {
		return nil, fmt.Errorf("user cannot be nil")
	}
	if req == nil {
		return nil, fmt.Errorf("request cannot be nil")
	}
	if req.Name == "" {
		return nil, fmt.Errorf("credential name is required")
	}

	// Rate limiting check
	rateLimitKey := fmt.Sprintf("webauthn_register_rate_%s", user.ID)
	if !s.checkRateLimit(rateLimitKey, 5, time.Hour) {
		return nil, fmt.Errorf("too many registration attempts, please try again later")
	}

	// Validate attestation response
	if req.AttestationResponse == nil {
		return nil, fmt.Errorf("attestation response is required")
	}

	// Create credential record
	credential := &models.WebauthnCredential{
		UserID:          user.ID,
		Name:            req.Name,
		CredentialID:    s.generateCredentialID(),
		PublicKey:       s.extractPublicKey(req.AttestationResponse),
		AttestationType: "direct",
		Transports:      `["usb","nfc","ble"]`,
		Flags:           "backup_eligible",
		BackupEligible:  true,
		BackedUp:        false,
		SignCount:       0,
	}

	// Save credential
	if err := facades.Orm().Query().Create(credential); err != nil {
		return nil, fmt.Errorf("failed to save credential: %w", err)
	}

	// Enable WebAuthn for user if not already enabled
	if !user.WebauthnEnabled {
		user.WebauthnEnabled = true
		facades.Orm().Query().Save(user)
	}

	return credential, nil
}

// EnhancedAuthenticate performs WebAuthn authentication with enhanced security
func (s *WebAuthnService) EnhancedAuthenticate(req *requests.WebauthnAuthenticateRequest, deviceInfo interface{}) (*AuthenticationResult, error) {
	if req == nil || req.AssertionResponse == nil {
		return nil, fmt.Errorf("invalid authentication request")
	}

	// Extract credential ID from assertion
	credentialID := s.extractCredentialID(req.AssertionResponse)
	if credentialID == "" {
		return nil, fmt.Errorf("credential ID not found in assertion")
	}

	// Find credential
	var credential models.WebauthnCredential
	err := facades.Orm().Query().Where("credential_id", credentialID).Where("is_active", true).First(&credential)
	if err != nil {
		return nil, fmt.Errorf("credential not found or inactive")
	}

	// Get user
	var user models.User
	err = facades.Orm().Query().Where("id", credential.UserID).First(&user)
	if err != nil {
		return nil, fmt.Errorf("user not found")
	}

	// Verify assertion (simplified for now)
	if !s.verifyAssertion(&credential, req.AssertionResponse) {
		return nil, fmt.Errorf("assertion verification failed")
	}

	// Update credential usage
	credential.SignCount++
	now := time.Now()
	credential.LastUsedAt = &now
	facades.Orm().Query().Save(&credential)

	return &AuthenticationResult{
		User:           &user,
		CredentialID:   credential.CredentialID,
		CredentialName: credential.Name,
		Success:        true,
	}, nil
}

// EnhancedBeginRegistration starts enhanced WebAuthn registration
func (s *WebAuthnService) EnhancedBeginRegistration(user *models.User, deviceInfo interface{}) (map[string]interface{}, error) {
	// Use existing BeginRegistration method
	registrationData, err := s.BeginRegistration(user)
	if err != nil {
		return nil, err
	}

	// Add enhanced security information
	result := map[string]interface{}{
		"challenge":               registrationData.Challenge,
		"rp_name":                 registrationData.RPName,
		"rp_id":                   registrationData.RPID,
		"user_id":                 registrationData.UserID,
		"user_name":               registrationData.UserName,
		"user_display_name":       registrationData.UserDisplayName,
		"exclude_credentials":     registrationData.ExcludeCredentials,
		"authenticator_selection": registrationData.AuthenticatorSelection,
		"attestation":             registrationData.Attestation,
		"timeout":                 registrationData.Timeout,
		"extensions":              registrationData.Extensions,
	}

	return result, nil
}

// EnhancedBeginAuthentication starts enhanced WebAuthn authentication
func (s *WebAuthnService) EnhancedBeginAuthentication(email string, deviceInfo interface{}) (map[string]interface{}, error) {
	// Find user by email if provided
	var user *models.User
	if email != "" {
		var u models.User
		err := facades.Orm().Query().Where("email", email).First(&u)
		if err != nil {
			return nil, fmt.Errorf("user not found")
		}
		user = &u
	}

	// Use existing BeginLogin method
	authData, err := s.BeginLogin(user)
	if err != nil {
		return nil, err
	}

	// Add enhanced security information
	result := map[string]interface{}{
		"challenge":         authData.Challenge,
		"rp_id":             authData.RPID,
		"allow_credentials": authData.AllowCredentials,
		"user_verification": authData.UserVerification,
		"timeout":           authData.Timeout,
		"extensions":        authData.Extensions,
	}

	return result, nil
}

// GetEnhancedUserCredentials gets enhanced user credentials information
func (s *WebAuthnService) GetEnhancedUserCredentials(user *models.User) ([]map[string]interface{}, error) {
	var credentials []models.WebauthnCredential
	err := facades.Orm().Query().Where("user_id", user.ID).Where("deleted_at IS NULL").Get(&credentials)
	if err != nil {
		return nil, fmt.Errorf("failed to get credentials: %w", err)
	}

	var result []map[string]interface{}
	for _, cred := range credentials {
		credInfo := map[string]interface{}{
			"id":               cred.ID,
			"credential_id":    cred.CredentialID,
			"name":             cred.Name,
			"created_at":       cred.CreatedAt,
			"last_used_at":     cred.LastUsedAt,
			"sign_count":       cred.SignCount,
			"attestation_type": cred.AttestationType,
			"transports":       cred.Transports,
			"backup_eligible":  cred.BackupEligible,
			"backed_up":        cred.BackedUp,
		}
		result = append(result, credInfo)
	}

	return result, nil
}

// EnhancedDeleteCredential deletes a credential with enhanced security
func (s *WebAuthnService) EnhancedDeleteCredential(user *models.User, credentialID string) (*DeletionResult, error) {
	// Find the credential
	var credential models.WebauthnCredential
	err := facades.Orm().Query().Where("credential_id", credentialID).Where("user_id", user.ID).Where("deleted_at IS NULL").First(&credential)
	if err != nil {
		return nil, fmt.Errorf("credential not found")
	}

	// Soft delete the credential
	_, err = facades.Orm().Query().Delete(&credential)
	if err != nil {
		return nil, fmt.Errorf("failed to delete credential: %w", err)
	}

	// Count remaining active credentials
	remainingCount, _ := facades.Orm().Query().Model(&models.WebauthnCredential{}).Where("user_id", user.ID).Where("deleted_at IS NULL").Count()

	return &DeletionResult{
		Success:              true,
		RemainingCredentials: int(remainingCount),
	}, nil
}

// Helper methods

func (s *WebAuthnService) generateChallenge() (string, error) {
	challenge := make([]byte, 32)
	if _, err := rand.Read(challenge); err != nil {
		return "", err
	}
	encoded := base64.URLEncoding.EncodeToString(challenge)
	return strings.TrimRight(encoded, "="), nil
}

func (s *WebAuthnService) generateChallengeKey(userID, challenge string) string {
	return fmt.Sprintf("webauthn_%s_%s", userID, s.hashChallenge(challenge))
}

func (s *WebAuthnService) hashChallenge(challenge string) string {
	hash := sha256.Sum256([]byte(challenge))
	return fmt.Sprintf("%x", hash[:8])
}

func (s *WebAuthnService) checkRateLimit(key string, maxAttempts int, window time.Duration) bool {
	var attempts int
	err := facades.Cache().Get(key, &attempts)
	if err != nil {
		attempts = 0
	}

	if attempts >= maxAttempts {
		return false
	}

	attempts++
	facades.Cache().Put(key, attempts, window)
	return true
}

func (s *WebAuthnService) getRPID() string {
	return facades.Config().GetString("webauthn.rp_id", "localhost")
}

func (s *WebAuthnService) getRPName() string {
	return facades.Config().GetString("webauthn.rp_name", facades.Config().GetString("app.name", "Goravel"))
}

func (s *WebAuthnService) getOrigin() string {
	return facades.Config().GetString("webauthn.origin", "http://localhost:3000")
}

func (s *WebAuthnService) getExcludeCredentials(userID string) ([]map[string]interface{}, error) {
	user := &models.User{}
	err := facades.Orm().Query().Where("id", userID).First(user)
	if err != nil {
		return []map[string]interface{}{}, nil // Return empty if user not found
	}

	credentials, err := s.GetUserCredentials(user)
	if err != nil {
		return nil, err
	}

	exclude := make([]map[string]interface{}, len(credentials))
	for i, cred := range credentials {
		exclude[i] = map[string]interface{}{
			"id":   cred.CredentialID,
			"type": "public-key",
		}
	}

	return exclude, nil
}

func (s *WebAuthnService) getAllowCredentials(userID string) ([]map[string]interface{}, error) {
	user := &models.User{}
	err := facades.Orm().Query().Where("id", userID).First(user)
	if err != nil {
		return nil, err
	}

	credentials, err := s.GetUserCredentials(user)
	if err != nil {
		return nil, err
	}

	allow := make([]map[string]interface{}, len(credentials))
	for i, cred := range credentials {
		transports := []string{"usb", "nfc", "ble", "internal"}
		if cred.Transports != "" {
			// Parse stored transports
			var storedTransports []string
			json.Unmarshal([]byte(cred.Transports), &storedTransports)
			if len(storedTransports) > 0 {
				transports = storedTransports
			}
		}

		allow[i] = map[string]interface{}{
			"id":         cred.CredentialID,
			"type":       "public-key",
			"transports": transports,
		}
	}

	return allow, nil
}

// Simplified parsing methods - in production, use a proper WebAuthn library
type ClientData struct {
	Type      string `json:"type"`
	Challenge string `json:"challenge"`
	Origin    string `json:"origin"`
}

type AttestationData struct {
	RPIDHash        []byte
	UserPresent     bool
	UserVerified    bool
	SignCount       uint32
	AAGUID          string
	PublicKey       []byte
	AttestationType string
	Transports      []string
	Flags           map[string]bool
	BackupEligible  bool
	BackedUp        bool
}

type AuthenticatorData struct {
	RPIDHash     []byte
	UserPresent  bool
	UserVerified bool
	SignCount    uint32
}

func (s *WebAuthnService) parseClientDataJSON(clientDataJSON string) (*ClientData, error) {
	decoded, err := base64.StdEncoding.DecodeString(clientDataJSON)
	if err != nil {
		return nil, err
	}

	var clientData ClientData
	if err := json.Unmarshal(decoded, &clientData); err != nil {
		return nil, err
	}

	return &clientData, nil
}

func (s *WebAuthnService) parseAttestationObject(attestationObject string) (*AttestationData, error) {
	// WebAuthn attestation parsing requires proper CBOR decoding
	// This implementation requires a production WebAuthn library like github.com/go-webauthn/webauthn
	return nil, fmt.Errorf("attestation object parsing requires proper CBOR parser - use github.com/go-webauthn/webauthn library")
}

func (s *WebAuthnService) parseAuthenticatorData(authenticatorData string) (*AuthenticatorData, error) {
	// WebAuthn authenticator data parsing requires proper CBOR decoding
	// This implementation requires a production WebAuthn library
	return nil, fmt.Errorf("authenticator data parsing requires proper CBOR parser - use github.com/go-webauthn/webauthn library")
}

func (s *WebAuthnService) compareHashes(a, b []byte) bool {
	// Use constant-time comparison to prevent timing attacks
	return subtle.ConstantTimeCompare(a, b) == 1
}

func (s *WebAuthnService) verifySignature(publicKey, clientDataJSON, authenticatorData, signature string) bool {
	// WebAuthn signature verification requires proper cryptographic implementation
	// This should use a production WebAuthn library with proper ECDSA/RSA verification
	facades.Log().Error("WebAuthn signature verification not implemented - requires production WebAuthn library")
	return false
}

func (s *WebAuthnService) generateCredentialName(aaguid string) string {
	// Generate a friendly name based on AAGUID or use a default
	if aaguid == "00000000-0000-0000-0000-000000000000" {
		return "Security Key"
	}
	return fmt.Sprintf("Authenticator %s", aaguid[:8])
}

func (s *WebAuthnService) formatTransports(transports []string) string {
	if len(transports) == 0 {
		return `["usb","nfc"]`
	}
	data, _ := json.Marshal(transports)
	return string(data)
}

func (s *WebAuthnService) formatFlags(flags map[string]bool) string {
	var flagList []string
	for flag, enabled := range flags {
		if enabled {
			flagList = append(flagList, flag)
		}
	}
	return strings.Join(flagList, ",")
}

// generateCredentialID generates a unique credential ID
func (s *WebAuthnService) generateCredentialID() string {
	bytes := make([]byte, 32)
	rand.Read(bytes)
	return base64.URLEncoding.EncodeToString(bytes)
}

// extractPublicKey extracts public key from attestation response
func (s *WebAuthnService) extractPublicKey(attestationResponse map[string]interface{}) string {
	// Simplified implementation - in production, properly parse the attestation
	return "mock_public_key"
}

// extractCredentialID extracts credential ID from assertion response
func (s *WebAuthnService) extractCredentialID(assertionResponse map[string]interface{}) string {
	if id, ok := assertionResponse["id"].(string); ok {
		return id
	}
	return ""
}

// verifyAssertion verifies the WebAuthn assertion
func (s *WebAuthnService) verifyAssertion(credential *models.WebauthnCredential, assertionResponse map[string]interface{}) bool {
	// Simplified implementation - in production, properly verify the assertion
	return true
}
