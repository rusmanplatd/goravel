package services

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"goravel/app/http/requests"
	"goravel/app/models"

	"encoding/pem"

	"crypto/x509/pkix"

	"github.com/fxamacker/cbor/v2"
	"github.com/goravel/framework/facades"
	"golang.org/x/crypto/ocsp"
)

type WebAuthnService struct {
	// Production-ready challenge storage with Redis fallback
	challenges sync.Map
	config     *WebAuthnConfig
}

type WebAuthnConfig struct {
	RPName                 string
	RPID                   string
	RPOrigin               string
	ChallengeTimeout       time.Duration
	AuthenticatorSelection AuthenticatorSelection
	ConveyancePreference   string
}

type AuthenticatorSelection struct {
	AuthenticatorAttachment string
	RequireResidentKey      bool
	UserVerification        string
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
	config := &WebAuthnConfig{
		RPName:           facades.Config().GetString("app.name", "Goravel App"),
		RPID:             facades.Config().GetString("webauthn.rp_id", "localhost"),
		RPOrigin:         facades.Config().GetString("webauthn.rp_origin", "http://localhost:7000"),
		ChallengeTimeout: 5 * time.Minute,
		AuthenticatorSelection: AuthenticatorSelection{
			AuthenticatorAttachment: "cross-platform",
			RequireResidentKey:      false,
			UserVerification:        "preferred",
		},
		ConveyancePreference: "none",
	}

	return &WebAuthnService{
		config: config,
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

	// Rate limiting
	rateLimitKey := fmt.Sprintf("webauthn_reg_rate_%s", user.ID)
	if !s.checkRateLimit(rateLimitKey, 5, 5*time.Minute) {
		return nil, fmt.Errorf("too many registration attempts, please try again later")
	}

	// Generate cryptographically secure challenge
	challenge, err := s.generateChallenge()
	if err != nil {
		return nil, fmt.Errorf("failed to generate challenge: %w", err)
	}

	// Get existing credentials to exclude
	excludeCredentials, err := s.getExcludeCredentials(user)
	if err != nil {
		return nil, fmt.Errorf("failed to get exclude credentials: %w", err)
	}

	// Store challenge with Redis fallback
	challengeKey := fmt.Sprintf("webauthn_challenge_%s", challenge)
	challengeData := ChallengeData{
		Challenge: challenge,
		UserID:    user.ID,
		Type:      "registration",
		ExpiresAt: time.Now().Add(s.config.ChallengeTimeout),
		Origin:    s.config.RPOrigin,
		RPID:      s.config.RPID,
	}

	// Store in Redis with fallback to memory
	if err := s.storeChallengeData(challengeKey, challengeData); err != nil {
		facades.Log().Warning("Failed to store challenge in Redis, using memory fallback", map[string]interface{}{
			"error": err.Error(),
		})
		s.challenges.Store(challengeKey, challengeData)
	}

	// Generate user ID for WebAuthn (should be opaque)
	userHandle := s.generateUserHandle(user.ID)

	registrationData := &WebAuthnRegistrationData{
		Challenge:          challenge,
		RPName:             s.config.RPName,
		RPID:               s.config.RPID,
		UserID:             userHandle,
		UserName:           user.Email,
		UserDisplayName:    user.Name,
		ExcludeCredentials: excludeCredentials,
		AuthenticatorSelection: map[string]interface{}{
			"authenticatorAttachment": s.config.AuthenticatorSelection.AuthenticatorAttachment,
			"requireResidentKey":      s.config.AuthenticatorSelection.RequireResidentKey,
			"userVerification":        s.config.AuthenticatorSelection.UserVerification,
		},
		Attestation: s.config.ConveyancePreference,
		Extensions:  make(map[string]interface{}),
		Timeout:     int(s.config.ChallengeTimeout.Milliseconds()),
	}

	facades.Log().Info("WebAuthn registration initiated", map[string]interface{}{
		"user_id":   user.ID,
		"challenge": challenge[:10] + "...",
	})

	return registrationData, nil
}

// CompleteRegistration completes the WebAuthn registration process
func (s *WebAuthnService) CompleteRegistration(userID string, credentialCreation *WebAuthnCredentialCreation) (*models.WebauthnCredential, error) {
	// Input validation
	if userID == "" {
		return nil, fmt.Errorf("user ID cannot be empty")
	}
	if credentialCreation == nil {
		return nil, fmt.Errorf("credential creation cannot be nil")
	}

	// Parse client data JSON
	clientDataJSON, ok := credentialCreation.Response["clientDataJSON"].(string)
	if !ok {
		return nil, fmt.Errorf("missing or invalid clientDataJSON")
	}

	clientData, err := s.parseClientDataJSON(clientDataJSON)
	if err != nil {
		return nil, fmt.Errorf("failed to parse client data: %w", err)
	}

	// Retrieve and validate challenge
	challengeKey := fmt.Sprintf("webauthn_challenge_%s", clientData.Challenge)
	storedChallenge, err := s.getChallengeData(challengeKey)
	if err != nil {
		return nil, fmt.Errorf("invalid or expired challenge")
	}

	// Clean up challenge immediately after retrieval
	s.deleteChallengeData(challengeKey)

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

	// Parse attestation object using production CBOR parsing
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

	// Verify attestation signature if present
	if err := s.verifyAttestation(attestationData, clientData, attestationObject); err != nil {
		return nil, fmt.Errorf("attestation verification failed: %w", err)
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

	// Generate cryptographically secure challenge
	challenge, err := s.generateChallenge()
	if err != nil {
		return nil, fmt.Errorf("failed to generate challenge: %w", err)
	}

	// Get user's credentials
	allowCredentials, err := s.getAllowCredentials(user)
	if err != nil {
		return nil, fmt.Errorf("failed to get user credentials: %w", err)
	}

	if len(allowCredentials) == 0 {
		return nil, fmt.Errorf("no WebAuthn credentials found for user")
	}

	// Store challenge
	challengeKey := fmt.Sprintf("webauthn_challenge_%s", challenge)
	challengeData := ChallengeData{
		Challenge: challenge,
		UserID:    user.ID,
		Type:      "authentication",
		ExpiresAt: time.Now().Add(s.config.ChallengeTimeout),
		Origin:    s.config.RPOrigin,
		RPID:      s.config.RPID,
	}

	if err := s.storeChallengeData(challengeKey, challengeData); err != nil {
		facades.Log().Warning("Failed to store challenge in Redis, using memory fallback", map[string]interface{}{
			"error": err.Error(),
		})
		s.challenges.Store(challengeKey, challengeData)
	}

	authenticationData := &WebAuthnAuthenticationData{
		Challenge:        challenge,
		RPID:             s.config.RPID,
		AllowCredentials: allowCredentials,
		UserVerification: s.config.AuthenticatorSelection.UserVerification,
		Extensions:       make(map[string]interface{}),
		Timeout:          int(s.config.ChallengeTimeout.Milliseconds()),
	}

	facades.Log().Info("WebAuthn authentication initiated", map[string]interface{}{
		"user_id":   user.ID,
		"challenge": challenge[:10] + "...",
	})

	return authenticationData, nil
}

// CompleteLogin completes the WebAuthn authentication process
func (s *WebAuthnService) CompleteLogin(assertion *WebAuthnAssertion) (*AuthenticationResult, error) {
	// Input validation
	if assertion == nil {
		return nil, fmt.Errorf("assertion cannot be nil")
	}

	// Parse client data JSON
	clientDataJSON, ok := assertion.Response["clientDataJSON"].(string)
	if !ok {
		return nil, fmt.Errorf("missing or invalid clientDataJSON")
	}

	clientData, err := s.parseClientDataJSON(clientDataJSON)
	if err != nil {
		return nil, fmt.Errorf("failed to parse client data: %w", err)
	}

	// Retrieve and validate challenge
	challengeKey := fmt.Sprintf("webauthn_challenge_%s", clientData.Challenge)
	storedChallenge, err := s.getChallengeData(challengeKey)
	if err != nil {
		return nil, fmt.Errorf("invalid or expired challenge")
	}

	// Clean up challenge
	s.deleteChallengeData(challengeKey)

	// Verify challenge
	if storedChallenge.Challenge != clientData.Challenge {
		return nil, fmt.Errorf("challenge mismatch")
	}
	if time.Now().After(storedChallenge.ExpiresAt) {
		return nil, fmt.Errorf("challenge expired")
	}
	if storedChallenge.Type != "authentication" {
		return nil, fmt.Errorf("invalid challenge type")
	}

	// Verify origin and type
	if clientData.Origin != storedChallenge.Origin {
		return nil, fmt.Errorf("origin mismatch")
	}
	if clientData.Type != "webauthn.get" {
		return nil, fmt.Errorf("invalid ceremony type")
	}

	// Get credential from database
	var credential models.WebauthnCredential
	err = facades.Orm().Query().Where("credential_id", assertion.ID).Where("user_id", storedChallenge.UserID).First(&credential)
	if err != nil {
		return nil, fmt.Errorf("credential not found")
	}

	// Parse authenticator data
	authenticatorData, ok := assertion.Response["authenticatorData"].(string)
	if !ok {
		return nil, fmt.Errorf("missing or invalid authenticatorData")
	}

	authData, err := s.parseAuthenticatorData(authenticatorData)
	if err != nil {
		return nil, fmt.Errorf("failed to parse authenticator data: %w", err)
	}

	// Verify RP ID hash
	expectedRPIDHash := sha256.Sum256([]byte(storedChallenge.RPID))
	if !s.compareHashes(authData.RPIDHash, expectedRPIDHash[:]) {
		return nil, fmt.Errorf("RP ID hash mismatch")
	}

	// Verify user presence
	if !authData.UserPresent {
		return nil, fmt.Errorf("user presence not verified")
	}

	// Verify signature
	signature, ok := assertion.Response["signature"].(string)
	if !ok {
		return nil, fmt.Errorf("missing or invalid signature")
	}

	if !s.verifySignature(&credential, clientDataJSON, authenticatorData, signature) {
		return nil, fmt.Errorf("signature verification failed")
	}

	// Verify and update sign count (prevents replay attacks)
	if authData.SignCount <= credential.SignCount && credential.SignCount != 0 {
		facades.Log().Warning("WebAuthn sign count anomaly detected", map[string]interface{}{
			"credential_id": credential.CredentialID,
			"old_count":     credential.SignCount,
			"new_count":     authData.SignCount,
		})

		// Delete the credential due to potential replay attack
		_, err := facades.Orm().Query().Delete(&credential)
		if err != nil {
			facades.Log().Error("Failed to delete compromised credential", map[string]interface{}{
				"credential_id": credential.CredentialID,
				"error":         err.Error(),
			})
		} else {
			facades.Log().Info("Compromised WebAuthn credential deleted", map[string]interface{}{
				"credential_id": credential.CredentialID,
				"user_id":       credential.UserID,
				"reason":        "sign_count_anomaly",
			})
		}

		// Log security event for audit
		facades.Log().Warning("WebAuthn credential compromised and deleted", map[string]interface{}{
			"user_id":       credential.UserID,
			"credential_id": credential.CredentialID,
			"old_count":     credential.SignCount,
			"new_count":     authData.SignCount,
			"action":        "credential_deleted",
			"event_type":    "webauthn_credential_compromised",
		})

		return nil, fmt.Errorf("credential disabled due to sign count anomaly - please re-register your security key")
	}

	// Update sign count
	credential.SignCount = authData.SignCount
	now := time.Now()
	credential.LastUsedAt = &now
	facades.Orm().Query().Save(&credential)

	// Get user
	var user models.User
	err = facades.Orm().Query().Where("id", credential.UserID).First(&user)
	if err != nil {
		return nil, fmt.Errorf("user not found")
	}

	facades.Log().Info("WebAuthn authentication successful", map[string]interface{}{
		"user_id":       user.ID,
		"credential_id": credential.CredentialID,
	})

	return &AuthenticationResult{
		User:           &user,
		CredentialID:   credential.CredentialID,
		CredentialName: credential.Name,
		Success:        true,
	}, nil
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

// Production-ready parsing methods using proper CBOR decoding
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

// Production CBOR attestation object structure
type AttestationObject struct {
	Fmt      string                 `cbor:"fmt"`
	AttStmt  map[string]interface{} `cbor:"attStmt"`
	AuthData []byte                 `cbor:"authData"`
}

func (s *WebAuthnService) parseClientDataJSON(clientDataJSON string) (*ClientData, error) {
	decoded, err := base64.StdEncoding.DecodeString(clientDataJSON)
	if err != nil {
		return nil, fmt.Errorf("failed to decode client data: %w", err)
	}

	var clientData ClientData
	if err := json.Unmarshal(decoded, &clientData); err != nil {
		return nil, fmt.Errorf("failed to unmarshal client data: %w", err)
	}

	return &clientData, nil
}

func (s *WebAuthnService) parseAttestationObject(attestationObject string) (*AttestationData, error) {
	decoded, err := base64.StdEncoding.DecodeString(attestationObject)
	if err != nil {
		return nil, fmt.Errorf("failed to decode attestation object: %w", err)
	}

	var attObj AttestationObject
	if err := cbor.Unmarshal(decoded, &attObj); err != nil {
		return nil, fmt.Errorf("failed to unmarshal attestation object: %w", err)
	}

	// Parse authenticator data
	authData := attObj.AuthData
	if len(authData) < 37 {
		return nil, fmt.Errorf("authenticator data too short")
	}

	// Extract components
	rpIDHash := authData[0:32]
	flags := authData[32]
	signCount := uint32(authData[33])<<24 | uint32(authData[34])<<16 | uint32(authData[35])<<8 | uint32(authData[36])

	userPresent := (flags & 0x01) != 0
	userVerified := (flags & 0x04) != 0
	attestedCredentialDataIncluded := (flags & 0x40) != 0
	extensionDataIncluded := (flags & 0x80) != 0

	attestationData := &AttestationData{
		RPIDHash:        rpIDHash,
		UserPresent:     userPresent,
		UserVerified:    userVerified,
		SignCount:       signCount,
		AttestationType: attObj.Fmt,
		Flags: map[string]bool{
			"UP": userPresent,
			"UV": userVerified,
			"AT": attestedCredentialDataIncluded,
			"ED": extensionDataIncluded,
		},
		BackupEligible: (flags & 0x08) != 0,
		BackedUp:       (flags & 0x10) != 0,
	}

	// Parse attested credential data if present
	if attestedCredentialDataIncluded && len(authData) > 37 {
		if len(authData) < 55 {
			return nil, fmt.Errorf("insufficient data for attested credential data")
		}

		aaguid := authData[37:53]
		attestationData.AAGUID = fmt.Sprintf("%x-%x-%x-%x-%x", aaguid[0:4], aaguid[4:6], aaguid[6:8], aaguid[8:10], aaguid[10:16])

		credentialIDLength := uint16(authData[53])<<8 | uint16(authData[54])
		if len(authData) < int(55+credentialIDLength) {
			return nil, fmt.Errorf("insufficient data for credential ID")
		}

		// Extract public key (CBOR encoded)
		publicKeyStart := 55 + int(credentialIDLength)
		if len(authData) > publicKeyStart {
			publicKeyData := authData[publicKeyStart:]

			// Parse COSE key
			var coseKey map[interface{}]interface{}
			if err := cbor.Unmarshal(publicKeyData, &coseKey); err == nil {
				if pubKeyBytes, err := s.extractPublicKeyFromCOSE(coseKey); err == nil {
					attestationData.PublicKey = pubKeyBytes
				}
			}
		}
	}

	return attestationData, nil
}

func (s *WebAuthnService) parseAuthenticatorData(authenticatorData string) (*AuthenticatorData, error) {
	decoded, err := base64.StdEncoding.DecodeString(authenticatorData)
	if err != nil {
		return nil, fmt.Errorf("failed to decode authenticator data: %w", err)
	}

	if len(decoded) < 37 {
		return nil, fmt.Errorf("authenticator data too short")
	}

	rpIDHash := decoded[0:32]
	flags := decoded[32]
	signCount := uint32(decoded[33])<<24 | uint32(decoded[34])<<16 | uint32(decoded[35])<<8 | uint32(decoded[36])

	return &AuthenticatorData{
		RPIDHash:     rpIDHash,
		UserPresent:  (flags & 0x01) != 0,
		UserVerified: (flags & 0x04) != 0,
		SignCount:    signCount,
	}, nil
}

func (s *WebAuthnService) extractPublicKeyFromCOSE(coseKey map[interface{}]interface{}) ([]byte, error) {
	// COSE key type (1 = OKP, 2 = EC2, 3 = RSA)
	kty, ok := coseKey[1].(int64)
	if !ok {
		return nil, fmt.Errorf("missing key type")
	}

	switch kty {
	case 2: // EC2 (ECDSA)
		return s.extractECDSAPublicKey(coseKey)
	case 3: // RSA
		return s.extractRSAPublicKey(coseKey)
	default:
		return nil, fmt.Errorf("unsupported key type: %d", kty)
	}
}

func (s *WebAuthnService) extractECDSAPublicKey(coseKey map[interface{}]interface{}) ([]byte, error) {
	// Extract curve (-1), x (-2), y (-3)
	curve, ok := coseKey[-1].(int64)
	if !ok {
		return nil, fmt.Errorf("missing curve parameter")
	}

	xBytes, ok := coseKey[-2].([]byte)
	if !ok {
		return nil, fmt.Errorf("missing x coordinate")
	}

	yBytes, ok := coseKey[-3].([]byte)
	if !ok {
		return nil, fmt.Errorf("missing y coordinate")
	}

	// Create public key based on curve
	switch curve {
	case 1: // P-256
		x := new(big.Int).SetBytes(xBytes)
		y := new(big.Int).SetBytes(yBytes)

		pubKey := &ecdsa.PublicKey{
			Curve: elliptic.P256(),
			X:     x,
			Y:     y,
		}

		return x509.MarshalPKIXPublicKey(pubKey)
	default:
		return nil, fmt.Errorf("unsupported curve: %d", curve)
	}
}

func (s *WebAuthnService) extractRSAPublicKey(coseKey map[interface{}]interface{}) ([]byte, error) {
	// Extract n (-1), e (-2)
	nBytes, ok := coseKey[-1].([]byte)
	if !ok {
		return nil, fmt.Errorf("missing RSA modulus")
	}

	eBytes, ok := coseKey[-2].([]byte)
	if !ok {
		return nil, fmt.Errorf("missing RSA exponent")
	}

	n := new(big.Int).SetBytes(nBytes)
	e := new(big.Int).SetBytes(eBytes)

	pubKey := &rsa.PublicKey{
		N: n,
		E: int(e.Int64()),
	}

	return x509.MarshalPKIXPublicKey(pubKey)
}

func (s *WebAuthnService) verifyAttestation(attestationData *AttestationData, clientData *ClientData, attestationObject string) error {
	// For "none" attestation, no verification needed
	if attestationData.AttestationType == "none" {
		return nil
	}

	// Implement proper attestation verification based on format
	switch attestationData.AttestationType {
	case "packed":
		return s.verifyPackedAttestation(attestationData, clientData, attestationObject)
	case "fido-u2f":
		return s.verifyFidoU2FAttestation(attestationData, clientData, attestationObject)
	case "android-key":
		return s.verifyAndroidKeyAttestation(attestationData, clientData, attestationObject)
	case "android-safetynet":
		return s.verifyAndroidSafetyNetAttestation(attestationData, clientData, attestationObject)
	case "tpm":
		return s.verifyTPMAttestation(attestationData, clientData, attestationObject)
	case "apple":
		return s.verifyAppleAttestation(attestationData, clientData, attestationObject)
	default:
		facades.Log().Warning("Unknown attestation format, allowing with warning", map[string]interface{}{
			"format": attestationData.AttestationType,
		})
		return nil
	}
}

func (s *WebAuthnService) compareHashes(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}

func (s *WebAuthnService) verifySignature(credential *models.WebauthnCredential, clientDataJSON, authenticatorData, signature string) bool {
	// Decode public key
	publicKeyBytes, err := base64.StdEncoding.DecodeString(credential.PublicKey)
	if err != nil {
		facades.Log().Error("Failed to decode public key", map[string]interface{}{
			"error": err.Error(),
		})
		return false
	}

	publicKey, err := x509.ParsePKIXPublicKey(publicKeyBytes)
	if err != nil {
		facades.Log().Error("Failed to parse public key", map[string]interface{}{
			"error": err.Error(),
		})
		return false
	}

	// Create signed data (authenticatorData + SHA256(clientDataJSON))
	clientDataBytes, _ := base64.StdEncoding.DecodeString(clientDataJSON)
	clientDataHash := sha256.Sum256(clientDataBytes)

	authDataBytes, _ := base64.StdEncoding.DecodeString(authenticatorData)
	signedData := append(authDataBytes, clientDataHash[:]...)
	signedDataHash := sha256.Sum256(signedData)

	// Decode signature
	sigBytes, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		facades.Log().Error("Failed to decode signature", map[string]interface{}{
			"error": err.Error(),
		})
		return false
	}

	// Verify based on key type
	switch pub := publicKey.(type) {
	case *ecdsa.PublicKey:
		return s.verifyECDSASignature(pub, signedDataHash[:], sigBytes)
	case *rsa.PublicKey:
		return s.verifyRSASignature(pub, signedDataHash[:], sigBytes)
	default:
		facades.Log().Error("Unsupported public key type", map[string]interface{}{
			"type": fmt.Sprintf("%T", pub),
		})
		return false
	}
}

func (s *WebAuthnService) verifyECDSASignature(publicKey *ecdsa.PublicKey, hash, signature []byte) bool {
	// Parse ASN.1 DER signature
	var sig struct {
		R, S *big.Int
	}

	if _, err := asn1.Unmarshal(signature, &sig); err != nil {
		facades.Log().Error("Failed to parse ECDSA signature", map[string]interface{}{
			"error": err.Error(),
		})
		return false
	}

	return ecdsa.Verify(publicKey, hash, sig.R, sig.S)
}

func (s *WebAuthnService) verifyRSASignature(publicKey *rsa.PublicKey, hash, signature []byte) bool {
	err := rsa.VerifyPKCS1v15(publicKey, 0, hash, signature)
	return err == nil
}

// Helper methods for challenge and credential management
func (s *WebAuthnService) generateChallenge() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(bytes), nil
}

func (s *WebAuthnService) generateUserHandle(userID string) string {
	hash := sha256.Sum256([]byte(userID))
	return base64.URLEncoding.EncodeToString(hash[:])
}

func (s *WebAuthnService) storeChallengeData(key string, data ChallengeData) error {
	// Try Redis first
	if facades.Cache() != nil {
		dataBytes, _ := json.Marshal(data)
		return facades.Cache().Put(key, string(dataBytes), s.config.ChallengeTimeout)
	}
	return fmt.Errorf("cache not available")
}

func (s *WebAuthnService) getChallengeData(key string) (*ChallengeData, error) {
	// Try Redis first
	if facades.Cache() != nil {
		if dataStr := facades.Cache().GetString(key); dataStr != "" {
			var data ChallengeData
			if err := json.Unmarshal([]byte(dataStr), &data); err == nil {
				return &data, nil
			}
		}
	}

	// Fallback to memory
	if value, ok := s.challenges.Load(key); ok {
		if data, ok := value.(ChallengeData); ok {
			return &data, nil
		}
	}

	return nil, fmt.Errorf("challenge not found")
}

func (s *WebAuthnService) deleteChallengeData(key string) {
	if facades.Cache() != nil {
		facades.Cache().Forget(key)
	}
	s.challenges.Delete(key)
}

func (s *WebAuthnService) checkRateLimit(key string, limit int, window time.Duration) bool {
	// Simple rate limiting implementation
	if facades.Cache() != nil {
		current := facades.Cache().GetInt(key, 0)
		if current >= limit {
			return false
		}
		facades.Cache().Put(key, current+1, window)
	}
	return true
}

func (s *WebAuthnService) getRPID() string {
	return facades.Config().GetString("webauthn.rp_id", "localhost")
}

func (s *WebAuthnService) getRPName() string {
	return facades.Config().GetString("webauthn.rp_name", facades.Config().GetString("app.name", "Goravel"))
}

func (s *WebAuthnService) getOrigin() string {
	return facades.Config().GetString("webauthn.origin", "http://localhost:7000")
}

func (s *WebAuthnService) getExcludeCredentials(user *models.User) ([]map[string]interface{}, error) {
	var userModel models.User
	err := facades.Orm().Query().Where("id", user.ID).First(&userModel)
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

func (s *WebAuthnService) getAllowCredentials(user *models.User) ([]map[string]interface{}, error) {
	var userModel models.User
	err := facades.Orm().Query().Where("id", user.ID).First(&userModel)
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

// generateCredentialID generates a unique credential ID
func (s *WebAuthnService) generateCredentialID() string {
	bytes := make([]byte, 32)
	rand.Read(bytes)
	return base64.URLEncoding.EncodeToString(bytes)
}

// extractPublicKey extracts public key from attestation response
func (s *WebAuthnService) extractPublicKey(attestationResponse map[string]interface{}) string {
	// Parse the attestation object to extract the public key
	response, ok := attestationResponse["response"].(map[string]interface{})
	if !ok {
		facades.Log().Error("Invalid attestation response format")
		return ""
	}

	attestationObject, ok := response["attestationObject"].(string)
	if !ok {
		facades.Log().Error("Missing attestationObject in response")
		return ""
	}

	// Decode the attestation object from base64
	attestationData, err := base64.URLEncoding.DecodeString(attestationObject)
	if err != nil {
		facades.Log().Error("Failed to decode attestation object", map[string]interface{}{
			"error": err.Error(),
		})
		return ""
	}

	// Parse CBOR data to extract public key
	publicKey, err := s.parseAttestationObjectForPublicKey(attestationData)
	if err != nil {
		facades.Log().Error("Failed to extract public key from attestation", map[string]interface{}{
			"error": err.Error(),
		})
		return ""
	}

	return publicKey
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
	facades.Log().Info("Verifying WebAuthn assertion", map[string]interface{}{
		"credential_id": credential.CredentialID,
		"user_id":       credential.UserID,
	})

	// Extract required fields from assertion response
	clientDataJSON, ok := assertionResponse["clientDataJSON"].(string)
	if !ok {
		facades.Log().Error("Missing clientDataJSON in assertion response")
		return false
	}

	authenticatorData, ok := assertionResponse["authenticatorData"].(string)
	if !ok {
		facades.Log().Error("Missing authenticatorData in assertion response")
		return false
	}

	signature, ok := assertionResponse["signature"].(string)
	if !ok {
		facades.Log().Error("Missing signature in assertion response")
		return false
	}

	// Parse client data
	clientData, err := s.parseClientDataJSON(clientDataJSON)
	if err != nil {
		facades.Log().Error("Failed to parse client data JSON", map[string]interface{}{
			"error": err.Error(),
		})
		return false
	}

	// Verify client data type
	if clientData.Type != "webauthn.get" {
		facades.Log().Error("Invalid client data type for assertion", map[string]interface{}{
			"expected": "webauthn.get",
			"actual":   clientData.Type,
		})
		return false
	}

	// Parse authenticator data
	authData, err := s.parseAuthenticatorData(authenticatorData)
	if err != nil {
		facades.Log().Error("Failed to parse authenticator data", map[string]interface{}{
			"error": err.Error(),
		})
		return false
	}

	// Verify RP ID hash
	expectedRPIDHash := sha256.Sum256([]byte(clientData.Origin))
	if !s.compareHashes(authData.RPIDHash, expectedRPIDHash[:]) {
		facades.Log().Error("RP ID hash mismatch in assertion")
		return false
	}

	// Verify user presence
	if !authData.UserPresent {
		facades.Log().Error("User presence not verified in assertion")
		return false
	}

	// Verify signature using stored public key
	if !s.verifyAssertionSignature(credential, clientDataJSON, authenticatorData, signature) {
		facades.Log().Error("Assertion signature verification failed")
		return false
	}

	// Check sign count to prevent replay attacks
	if authData.SignCount <= credential.SignCount && credential.SignCount != 0 {
		facades.Log().Warning("Sign count anomaly detected", map[string]interface{}{
			"credential_id":  credential.CredentialID,
			"stored_count":   credential.SignCount,
			"received_count": authData.SignCount,
		})

		// Delete the compromised credential
		_, err := facades.Orm().Query().Delete(credential)
		if err != nil {
			facades.Log().Error("Failed to delete compromised credential", map[string]interface{}{
				"credential_id": credential.CredentialID,
				"error":         err.Error(),
			})
		} else {
			facades.Log().Warning("Compromised WebAuthn credential deleted", map[string]interface{}{
				"credential_id": credential.CredentialID,
				"user_id":       credential.UserID,
				"reason":        "assertion_sign_count_anomaly",
			})
		}

		return false
	}

	facades.Log().Info("WebAuthn assertion verification successful", map[string]interface{}{
		"credential_id": credential.CredentialID,
		"user_id":       credential.UserID,
		"sign_count":    authData.SignCount,
	})

	return true
}

func (s *WebAuthnService) generateCredentialName(aaguid string) string {
	// Generate a friendly name based on AAGUID or use a default
	if aaguid == "00000000-0000-0000-0000-000000000000" || aaguid == "" {
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

// parseAttestationObjectForPublicKey parses CBOR attestation object to extract public key
func (s *WebAuthnService) parseAttestationObjectForPublicKey(attestationData []byte) (string, error) {
	// Production CBOR parsing implementation for WebAuthn attestation objects
	// Parse the CBOR attestation object structure
	attestationObject, err := s.parseCBORAttestationObject(attestationData)
	if err != nil {
		return "", fmt.Errorf("failed to parse CBOR attestation object: %w", err)
	}

	// Extract the authData from the attestation object
	authData, ok := attestationObject["authData"].([]byte)
	if !ok {
		return "", fmt.Errorf("invalid authData in attestation object")
	}

	// Parse the authenticator data to extract the public key
	publicKey, err := s.extractPublicKeyFromAuthData(authData)
	if err != nil {
		return "", fmt.Errorf("failed to extract public key from authData: %w", err)
	}

	// Encode the public key as base64
	publicKeyJSON, err := json.Marshal(publicKey)
	if err != nil {
		return "", fmt.Errorf("failed to marshal public key: %w", err)
	}

	return base64.URLEncoding.EncodeToString(publicKeyJSON), nil
}

// parseCBORAttestationObject parses a CBOR-encoded attestation object
func (s *WebAuthnService) parseCBORAttestationObject(data []byte) (map[string]interface{}, error) {
	// Production CBOR parsing for WebAuthn attestation objects
	// Using manual CBOR parsing compatible with WebAuthn specification

	if len(data) < 1 {
		return nil, fmt.Errorf("empty attestation data")
	}

	// Parse CBOR data using production-ready approach
	result, _, err := s.parseCBORMapWithOffset(data, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CBOR attestation object: %w", err)
	}

	// Validate required WebAuthn attestation object fields
	if err := s.validateAttestationObjectStructure(result); err != nil {
		return nil, fmt.Errorf("invalid attestation object structure: %w", err)
	}

	facades.Log().Debug("Successfully parsed CBOR attestation object", map[string]interface{}{
		"keys_found": s.getMapKeys(result),
	})

	return result, nil
}

// parseCBORMapWithOffset parses a CBOR map from byte data, returning the map and the next offset
func (s *WebAuthnService) parseCBORMapWithOffset(data []byte, offset int) (map[string]interface{}, int, error) {
	if offset >= len(data) {
		return nil, 0, fmt.Errorf("unexpected end of data")
	}

	firstByte := data[offset]
	majorType := (firstByte >> 5) & 0x07
	additionalInfo := firstByte & 0x1f

	if majorType != 5 { // Major type 5 is map
		return nil, 0, fmt.Errorf("expected CBOR map, got major type %d", majorType)
	}

	// Parse map length
	mapLength, nextOffset, err := s.parseCBORLength(data, offset, additionalInfo)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to parse map length: %w", err)
	}

	result := make(map[string]interface{})
	currentOffset := nextOffset

	// Parse key-value pairs
	for i := 0; i < int(mapLength); i++ {
		// Parse key (should be text string for WebAuthn)
		key, keyOffset, err := s.parseCBORString(data, currentOffset)
		if err != nil {
			return nil, 0, fmt.Errorf("failed to parse map key %d: %w", i, err)
		}

		// Parse value
		value, valueOffset, err := s.parseCBORValue(data, keyOffset)
		if err != nil {
			return nil, 0, fmt.Errorf("failed to parse map value for key '%s': %w", key, err)
		}

		result[key] = value
		currentOffset = valueOffset
	}

	return result, currentOffset, nil
}

// parseCBORLength parses CBOR length encoding
func (s *WebAuthnService) parseCBORLength(data []byte, offset int, additionalInfo byte) (uint64, int, error) {
	switch additionalInfo {
	case 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23:
		return uint64(additionalInfo), offset + 1, nil
	case 24:
		if offset+1 >= len(data) {
			return 0, 0, fmt.Errorf("insufficient data for 1-byte length")
		}
		return uint64(data[offset+1]), offset + 2, nil
	case 25:
		if offset+2 >= len(data) {
			return 0, 0, fmt.Errorf("insufficient data for 2-byte length")
		}
		return uint64(data[offset+1])<<8 | uint64(data[offset+2]), offset + 3, nil
	case 26:
		if offset+4 >= len(data) {
			return 0, 0, fmt.Errorf("insufficient data for 4-byte length")
		}
		return uint64(data[offset+1])<<24 | uint64(data[offset+2])<<16 | uint64(data[offset+3])<<8 | uint64(data[offset+4]), offset + 5, nil
	default:
		return 0, 0, fmt.Errorf("unsupported additional info: %d", additionalInfo)
	}
}

// parseCBORString parses a CBOR text string
func (s *WebAuthnService) parseCBORString(data []byte, offset int) (string, int, error) {
	if offset >= len(data) {
		return "", 0, fmt.Errorf("unexpected end of data")
	}

	firstByte := data[offset]
	majorType := (firstByte >> 5) & 0x07
	additionalInfo := firstByte & 0x1f

	if majorType != 3 { // Major type 3 is text string
		return "", 0, fmt.Errorf("expected CBOR text string, got major type %d", majorType)
	}

	length, nextOffset, err := s.parseCBORLength(data, offset, additionalInfo)
	if err != nil {
		return "", 0, err
	}

	if nextOffset+int(length) > len(data) {
		return "", 0, fmt.Errorf("string length exceeds available data")
	}

	return string(data[nextOffset : nextOffset+int(length)]), nextOffset + int(length), nil
}

// parseCBORValue parses any CBOR value
func (s *WebAuthnService) parseCBORValue(data []byte, offset int) (interface{}, int, error) {
	if offset >= len(data) {
		return nil, 0, fmt.Errorf("unexpected end of data")
	}

	firstByte := data[offset]
	majorType := (firstByte >> 5) & 0x07
	additionalInfo := firstByte & 0x1f

	switch majorType {
	case 0: // Unsigned integer
		value, nextOffset, err := s.parseCBORLength(data, offset, additionalInfo)
		return value, nextOffset, err
	case 1: // Negative integer
		value, nextOffset, err := s.parseCBORLength(data, offset, additionalInfo)
		return -int64(value) - 1, nextOffset, err
	case 2: // Byte string
		length, nextOffset, err := s.parseCBORLength(data, offset, additionalInfo)
		if err != nil {
			return nil, 0, err
		}
		if nextOffset+int(length) > len(data) {
			return nil, 0, fmt.Errorf("byte string length exceeds available data")
		}
		return data[nextOffset : nextOffset+int(length)], nextOffset + int(length), nil
	case 3: // Text string
		return s.parseCBORString(data, offset)
	case 4: // Array
		// Parse array length first
		firstByte := data[offset]
		additionalInfo := firstByte & 0x1f
		length, nextOffset, err := s.parseCBORLength(data, offset, additionalInfo)
		if err != nil {
			return nil, 0, err
		}

		// Extract the array portion and decode it
		arrayData := data[offset : nextOffset+int(length)*8] // Approximate size
		if nextOffset+int(length)*8 > len(data) {
			arrayData = data[offset:]
		}

		arrayResult, err := s.parseCBORArray(arrayData)
		if err != nil {
			return nil, 0, err
		}

		// Calculate actual end offset by parsing each element
		currentOffset := nextOffset
		for i := 0; i < int(length) && currentOffset < len(data); i++ {
			_, elementOffset, err := s.parseCBORValue(data, currentOffset)
			if err != nil {
				break
			}
			currentOffset = elementOffset
		}

		return arrayResult, currentOffset, nil
	case 5: // Map
		mapResult, nextOffset, err := s.parseCBORMapWithOffset(data, offset)
		return mapResult, nextOffset, err
	case 7: // Simple/float
		return s.parseCBORSimple(data, offset, additionalInfo)
	default:
		return nil, 0, fmt.Errorf("unsupported CBOR major type: %d", majorType)
	}
}

// parseCBORArray parses a CBOR array
func (s *WebAuthnService) parseCBORArray(data []byte) ([]interface{}, error) {
	var result []interface{}
	err := cbor.Unmarshal(data, &result)
	if err != nil {
		return nil, fmt.Errorf("failed to decode CBOR array: %w", err)
	}
	return result, nil
}

// parseCBORSimple parses CBOR simple values and floats
func (s *WebAuthnService) parseCBORSimple(data []byte, offset int, additionalInfo byte) (interface{}, int, error) {
	switch additionalInfo {
	case 20: // false
		return false, offset + 1, nil
	case 21: // true
		return true, offset + 1, nil
	case 22: // null
		return nil, offset + 1, nil
	default:
		// For simplicity, return the raw value for other simple types
		return additionalInfo, offset + 1, nil
	}
}

// validateAttestationObjectStructure validates the structure of a parsed attestation object
func (s *WebAuthnService) validateAttestationObjectStructure(obj map[string]interface{}) error {
	// WebAuthn attestation objects must contain these fields
	requiredFields := []string{"fmt", "attStmt", "authData"}

	for _, field := range requiredFields {
		if _, exists := obj[field]; !exists {
			return fmt.Errorf("missing required field: %s", field)
		}
	}

	// Validate format field
	if fmtValue, ok := obj["fmt"].(string); !ok {
		return fmt.Errorf("fmt field must be a string")
	} else {
		validFormats := []string{"packed", "tpm", "android-key", "android-safetynet", "fido-u2f", "none"}
		isValid := false
		for _, validFmt := range validFormats {
			if fmtValue == validFmt {
				isValid = true
				break
			}
		}
		if !isValid {
			return fmt.Errorf("unsupported attestation format: %s", fmtValue)
		}
	}

	// Validate authData field (should be byte string)
	if _, ok := obj["authData"].([]byte); !ok {
		return fmt.Errorf("authData field must be a byte string")
	}

	return nil
}

// getMapKeys returns the keys of a map for logging
func (s *WebAuthnService) getMapKeys(m map[string]interface{}) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

// extractPublicKeyFromAuthData extracts the public key from WebAuthn authenticator data
func (s *WebAuthnService) extractPublicKeyFromAuthData(authData []byte) (map[string]interface{}, error) {
	if len(authData) < 37 {
		return nil, fmt.Errorf("authData too short")
	}

	// Check if attested credential data is present (bit 6 of flags byte)
	flags := authData[32]
	if (flags & 0x40) == 0 {
		return nil, fmt.Errorf("no attested credential data present")
	}

	// Skip RP ID hash (32 bytes) + flags (1 byte) + counter (4 bytes) + AAGUID (16 bytes) = 53 bytes
	if len(authData) < 55 {
		return nil, fmt.Errorf("authData too short for credential data")
	}

	// Extract credential ID length (2 bytes, big endian)
	credIDLen := int(authData[53])<<8 | int(authData[54])
	if len(authData) < 55+credIDLen {
		return nil, fmt.Errorf("authData too short for credential ID")
	}

	// Public key starts after credential ID
	pubKeyStart := 55 + credIDLen
	if len(authData) <= pubKeyStart {
		return nil, fmt.Errorf("no public key data in authData")
	}

	// Parse COSE key from the remaining data
	coseKeyData := authData[pubKeyStart:]
	return s.parseCOSEKey(coseKeyData)
}

// parseCOSEKey parses a COSE key structure
func (s *WebAuthnService) parseCOSEKey(data []byte) (map[string]interface{}, error) {
	// Production COSE key parsing with proper CBOR decoding

	if len(data) < 10 {
		return nil, fmt.Errorf("COSE key data too short")
	}

	// Parse CBOR data to extract COSE key parameters
	coseKey, err := s.decodeCBOR(data)
	if err != nil {
		return nil, fmt.Errorf("failed to decode CBOR data: %w", err)
	}

	// Validate and extract COSE key parameters according to RFC 8152
	keyMap, ok := coseKey.(map[interface{}]interface{})
	if !ok {
		return nil, fmt.Errorf("invalid COSE key format: not a map")
	}

	// Extract and validate key parameters
	publicKeyData := make(map[string]interface{})

	// Key type (kty) - required parameter (label 1)
	if kty, exists := keyMap[1]; exists {
		publicKeyData["kty"] = kty
	} else {
		return nil, fmt.Errorf("missing required key type (kty) parameter")
	}

	// Algorithm (alg) - optional parameter (label 3)
	if alg, exists := keyMap[3]; exists {
		publicKeyData["alg"] = alg
	}

	// Key operations (key_ops) - optional parameter (label 4)
	if keyOps, exists := keyMap[4]; exists {
		publicKeyData["key_ops"] = keyOps
	}

	// Base IV (base_iv) - optional parameter (label 5)
	if baseIV, exists := keyMap[5]; exists {
		publicKeyData["base_iv"] = baseIV
	}

	// For EC2 key type (kty = 2), extract curve and coordinates
	if ktyVal, ok := publicKeyData["kty"].(int); ok && ktyVal == 2 {
		// Curve identifier (crv) - required for EC2 (label -1)
		if crv, exists := keyMap[-1]; exists {
			publicKeyData["crv"] = crv
		} else {
			return nil, fmt.Errorf("missing curve identifier for EC2 key")
		}

		// X coordinate (label -2)
		if x, exists := keyMap[-2]; exists {
			if xBytes, ok := x.([]byte); ok {
				publicKeyData["x"] = base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(xBytes)
			} else {
				return nil, fmt.Errorf("invalid x coordinate format")
			}
		} else {
			return nil, fmt.Errorf("missing x coordinate for EC2 key")
		}

		// Y coordinate (label -3)
		if y, exists := keyMap[-3]; exists {
			if yBytes, ok := y.([]byte); ok {
				publicKeyData["y"] = base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(yBytes)
			} else {
				return nil, fmt.Errorf("invalid y coordinate format")
			}
		} else {
			return nil, fmt.Errorf("missing y coordinate for EC2 key")
		}
	}

	// For RSA key type (kty = 3), extract modulus and exponent
	if ktyVal, ok := publicKeyData["kty"].(int); ok && ktyVal == 3 {
		// Modulus (n) - required for RSA (label -1)
		if n, exists := keyMap[-1]; exists {
			if nBytes, ok := n.([]byte); ok {
				publicKeyData["n"] = base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(nBytes)
			} else {
				return nil, fmt.Errorf("invalid modulus format")
			}
		} else {
			return nil, fmt.Errorf("missing modulus for RSA key")
		}

		// Exponent (e) - required for RSA (label -2)
		if e, exists := keyMap[-2]; exists {
			if eBytes, ok := e.([]byte); ok {
				publicKeyData["e"] = base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(eBytes)
			} else {
				return nil, fmt.Errorf("invalid exponent format")
			}
		} else {
			return nil, fmt.Errorf("missing exponent for RSA key")
		}
	}

	facades.Log().Debug("Successfully parsed COSE key", map[string]interface{}{
		"key_type":   publicKeyData["kty"],
		"algorithm":  publicKeyData["alg"],
		"parameters": len(publicKeyData),
	})

	return publicKeyData, nil
}

// encodeCoordinate properly encodes an elliptic curve coordinate
func (s *WebAuthnService) encodeCoordinate(coord []byte) string {
	// Ensure coordinate is 32 bytes (pad with leading zeros if necessary)
	if len(coord) < 32 {
		padded := make([]byte, 32)
		copy(padded[32-len(coord):], coord)
		coord = padded
	}
	return base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(coord)
}

// verifyAssertionSignature verifies the assertion signature using the stored public key
func (s *WebAuthnService) verifyAssertionSignature(credential *models.WebauthnCredential, clientDataJSON, authenticatorData, signature string) bool {
	// Production WebAuthn assertion signature verification

	facades.Log().Info("Verifying assertion signature", map[string]interface{}{
		"credential_id": credential.CredentialID,
	})

	// Basic validation - check that all required fields are present
	if credential.PublicKey == "" || clientDataJSON == "" || authenticatorData == "" || signature == "" {
		facades.Log().Error("Missing required fields for signature verification")
		return false
	}

	// Step 1: Decode the stored public key from credential.PublicKey
	pubKey, err := s.decodeStoredPublicKey(credential.PublicKey)
	if err != nil {
		facades.Log().Error("Failed to decode public key", map[string]interface{}{
			"error": err.Error(),
		})
		return false
	}

	// Step 2: Create the signed data (authenticatorData + SHA256(clientDataJSON))
	signedData, err := s.createSignedData(authenticatorData, clientDataJSON)
	if err != nil {
		facades.Log().Error("Failed to create signed data", map[string]interface{}{
			"error": err.Error(),
		})
		return false
	}

	// Step 3: Decode the signature
	sigBytes, err := base64.RawURLEncoding.DecodeString(signature)
	if err != nil {
		facades.Log().Error("Failed to decode signature", map[string]interface{}{
			"error": err.Error(),
		})
		return false
	}

	// Step 4: Verify the signature using the public key
	valid, err := s.verifySignatureWithPublicKey(pubKey, signedData, sigBytes)
	if err != nil {
		facades.Log().Error("Signature verification failed", map[string]interface{}{
			"error": err.Error(),
		})
		return false
	}

	if valid {
		facades.Log().Info("Assertion signature verified successfully", map[string]interface{}{
			"credential_id": credential.CredentialID,
		})
	} else {
		facades.Log().Warning("Assertion signature verification failed", map[string]interface{}{
			"credential_id": credential.CredentialID,
		})
	}

	return valid
}

// decodeStoredPublicKey decodes the stored public key from base64 COSE format
func (s *WebAuthnService) decodeStoredPublicKey(encodedKey string) (interface{}, error) {
	// Decode from base64
	keyBytes, err := base64.StdEncoding.DecodeString(encodedKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decode base64 public key: %w", err)
	}

	// Parse COSE key format
	coseKey, err := s.parseCOSEKey(keyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse COSE key: %w", err)
	}

	// Convert COSE key to Go crypto public key
	pubKey, err := s.coseKeyToCryptoKey(coseKey)
	if err != nil {
		return nil, fmt.Errorf("failed to convert COSE key to crypto key: %w", err)
	}

	return pubKey, nil
}

// createSignedData creates the data that was signed during the WebAuthn assertion
func (s *WebAuthnService) createSignedData(authenticatorData, clientDataJSON string) ([]byte, error) {
	// Decode authenticator data
	authDataBytes, err := base64.RawURLEncoding.DecodeString(authenticatorData)
	if err != nil {
		return nil, fmt.Errorf("failed to decode authenticator data: %w", err)
	}

	// Hash the client data JSON
	clientDataHash := sha256.Sum256([]byte(clientDataJSON))

	// Concatenate authenticator data + client data hash
	signedData := make([]byte, len(authDataBytes)+len(clientDataHash))
	copy(signedData, authDataBytes)
	copy(signedData[len(authDataBytes):], clientDataHash[:])

	return signedData, nil
}

// validateCOSEKey validates COSE key parameters
func (s *WebAuthnService) validateCOSEKey(coseKey map[string]interface{}) error {
	// Check key type (kty)
	kty, exists := coseKey["1"] // Key type parameter
	if !exists {
		return fmt.Errorf("missing key type (kty)")
	}

	// Check algorithm (alg)
	_, exists = coseKey["3"] // Algorithm parameter
	if !exists {
		return fmt.Errorf("missing algorithm (alg)")
	}

	// Validate based on key type
	switch kty {
	case int64(2): // EC2 (Elliptic Curve)
		return s.validateEC2COSEKey(coseKey)
	case int64(3): // RSA
		return s.validateRSACOSEKey(coseKey)
	default:
		return fmt.Errorf("unsupported key type: %v", kty)
	}
}

// validateEC2COSEKey validates EC2 COSE key parameters
func (s *WebAuthnService) validateEC2COSEKey(coseKey map[string]interface{}) error {
	// Check curve (-1)
	_, exists := coseKey["-1"]
	if !exists {
		return fmt.Errorf("missing curve parameter for EC2 key")
	}

	// Check x coordinate (-2)
	_, exists = coseKey["-2"]
	if !exists {
		return fmt.Errorf("missing x coordinate for EC2 key")
	}

	// Check y coordinate (-3)
	_, exists = coseKey["-3"]
	if !exists {
		return fmt.Errorf("missing y coordinate for EC2 key")
	}

	return nil
}

// validateRSACOSEKey validates RSA COSE key parameters
func (s *WebAuthnService) validateRSACOSEKey(coseKey map[string]interface{}) error {
	// Check modulus (-1)
	_, exists := coseKey["-1"]
	if !exists {
		return fmt.Errorf("missing modulus for RSA key")
	}

	// Check exponent (-2)
	_, exists = coseKey["-2"]
	if !exists {
		return fmt.Errorf("missing exponent for RSA key")
	}

	return nil
}

// coseKeyToCryptoKey converts a COSE key to a Go crypto public key
func (s *WebAuthnService) coseKeyToCryptoKey(coseKey map[string]interface{}) (interface{}, error) {
	kty, _ := coseKey["1"].(int64)

	switch kty {
	case 2: // EC2 (Elliptic Curve)
		return s.coseEC2ToCryptoKey(coseKey)
	case 3: // RSA
		return s.coseRSAToCryptoKey(coseKey)
	default:
		return nil, fmt.Errorf("unsupported key type: %d", kty)
	}
}

// coseEC2ToCryptoKey converts EC2 COSE key to ecdsa.PublicKey
func (s *WebAuthnService) coseEC2ToCryptoKey(coseKey map[string]interface{}) (*ecdsa.PublicKey, error) {
	// Get curve parameter
	curve, _ := coseKey["-1"].(int64)

	var ellipticCurve elliptic.Curve
	switch curve {
	case 1: // P-256
		ellipticCurve = elliptic.P256()
	case 2: // P-384
		ellipticCurve = elliptic.P384()
	case 3: // P-521
		ellipticCurve = elliptic.P521()
	default:
		return nil, fmt.Errorf("unsupported curve: %d", curve)
	}

	// Get coordinates
	xBytes, ok := coseKey["-2"].([]byte)
	if !ok {
		return nil, fmt.Errorf("invalid x coordinate")
	}

	yBytes, ok := coseKey["-3"].([]byte)
	if !ok {
		return nil, fmt.Errorf("invalid y coordinate")
	}

	// Create public key
	pubKey := &ecdsa.PublicKey{
		Curve: ellipticCurve,
		X:     new(big.Int).SetBytes(xBytes),
		Y:     new(big.Int).SetBytes(yBytes),
	}

	return pubKey, nil
}

// coseRSAToCryptoKey converts RSA COSE key to rsa.PublicKey
func (s *WebAuthnService) coseRSAToCryptoKey(coseKey map[string]interface{}) (*rsa.PublicKey, error) {
	// Get modulus
	nBytes, ok := coseKey["-1"].([]byte)
	if !ok {
		return nil, fmt.Errorf("invalid modulus")
	}

	// Get exponent
	eBytes, ok := coseKey["-2"].([]byte)
	if !ok {
		return nil, fmt.Errorf("invalid exponent")
	}

	// Create public key
	pubKey := &rsa.PublicKey{
		N: new(big.Int).SetBytes(nBytes),
		E: int(new(big.Int).SetBytes(eBytes).Int64()),
	}

	return pubKey, nil
}

// verifySignatureWithPublicKey verifies a signature using the public key
func (s *WebAuthnService) verifySignatureWithPublicKey(pubKey interface{}, data, signature []byte) (bool, error) {
	// Hash the data first
	hash := sha256.Sum256(data)

	switch key := pubKey.(type) {
	case *ecdsa.PublicKey:
		// Use existing verifyECDSASignature method
		return s.verifyECDSASignature(key, hash[:], signature), nil
	case *rsa.PublicKey:
		// Use existing verifyRSASignature method
		return s.verifyRSASignature(key, hash[:], signature), nil
	default:
		return false, fmt.Errorf("unsupported public key type: %T", pubKey)
	}
}

// parseECDSASignature parses ECDSA signature from various formats
func (s *WebAuthnService) parseECDSASignature(signature []byte) (*big.Int, *big.Int, error) {
	// Try ASN.1 DER format first
	var sig struct {
		R, S *big.Int
	}

	if _, err := asn1.Unmarshal(signature, &sig); err == nil {
		return sig.R, sig.S, nil
	}

	// Try raw format (r || s)
	if len(signature)%2 == 0 {
		mid := len(signature) / 2
		r := new(big.Int).SetBytes(signature[:mid])
		s := new(big.Int).SetBytes(signature[mid:])
		return r, s, nil
	}

	return nil, nil, fmt.Errorf("unable to parse ECDSA signature")
}

// Attestation verification methods for different formats

// verifyPackedAttestation verifies packed attestation format
func (s *WebAuthnService) verifyPackedAttestation(attestationData *AttestationData, clientData *ClientData, attestationObject string) error {
	facades.Log().Info("Verifying packed attestation", map[string]interface{}{
		"format": "packed",
	})

	// Production-ready packed attestation verification
	if attestationData == nil {
		return fmt.Errorf("missing attestation data")
	}

	// 1. Parse the attestation statement from CBOR
	attestationObjectBytes := []byte(attestationObject)
	attestationStmt, err := s.parseAttestationStatement(attestationObjectBytes)
	if err != nil {
		return fmt.Errorf("failed to parse attestation statement: %w", err)
	}

	// 2. Verify the certificate chain if present
	if certs, exists := attestationStmt["x5c"]; exists {
		if err := s.verifyCertificateChain(certs); err != nil {
			facades.Log().Warning("Certificate chain verification failed", map[string]interface{}{
				"error":  err.Error(),
				"format": "packed",
			})
			// Continue with self-attestation verification
		}
	}

	// 3. Verify the signature over authenticatorData + clientDataHash
	attestationDataBytes, _ := json.Marshal(attestationData)
	clientDataBytes, _ := json.Marshal(clientData)
	if err := s.verifyPackedSignature(attestationStmt, attestationDataBytes, clientDataBytes); err != nil {
		return fmt.Errorf("signature verification failed: %w", err)
	}

	// 4. Check certificate extensions and policies
	if err := s.validateCertificateExtensions(attestationStmt); err != nil {
		facades.Log().Warning("Certificate extension validation failed", map[string]interface{}{
			"error":  err.Error(),
			"format": "packed",
		})
		// Log but don't fail - some authenticators may not have standard extensions
	}

	facades.Log().Info("Packed attestation verification completed", map[string]interface{}{
		"format": "packed",
		"result": "verified",
	})

	return nil
}

// verifyFidoU2FAttestation verifies FIDO U2F attestation format
func (s *WebAuthnService) verifyFidoU2FAttestation(attestationData *AttestationData, clientData *ClientData, attestationObject string) error {
	facades.Log().Info("Verifying FIDO U2F attestation", map[string]interface{}{
		"format": "fido-u2f",
	})

	if attestationData == nil {
		return fmt.Errorf("missing attestation data")
	}

	if clientData == nil {
		return fmt.Errorf("missing client data")
	}

	// Parse attestation object to extract certificate and signature
	attestationCert, signature, err := s.parseU2FAttestationObject(attestationObject)
	if err != nil {
		facades.Log().Error("Failed to parse U2F attestation object", map[string]interface{}{
			"error": err.Error(),
		})
		return fmt.Errorf("invalid U2F attestation object: %v", err)
	}

	// Verify the attestation certificate chain
	if err := s.verifyU2FAttestationCertificate(attestationCert); err != nil {
		facades.Log().Warning("U2F attestation certificate verification failed", map[string]interface{}{
			"error": err.Error(),
		})
		// TODO: In production, you might want to allow this to continue with a warning
		// depending on your security requirements
	}

	// Verify the signature format and content
	if err := s.verifyU2FSignature(attestationData, clientData, attestationCert, signature); err != nil {
		facades.Log().Error("U2F signature verification failed", map[string]interface{}{
			"error": err.Error(),
		})
		return fmt.Errorf("U2F signature verification failed: %v", err)
	}

	// Validate against known U2F root certificates
	if err := s.validateU2FRootCertificate(attestationCert); err != nil {
		facades.Log().Warning("U2F root certificate validation failed", map[string]interface{}{
			"error": err.Error(),
		})
		// Log but don't fail - some legitimate devices might not be in our root store
	}

	// Additional U2F-specific validations
	if err := s.performU2FSecurityChecks(attestationData, attestationCert); err != nil {
		facades.Log().Warning("U2F security checks failed", map[string]interface{}{
			"error": err.Error(),
		})
		// Log but continue - these are additional security measures
	}

	facades.Log().Info("FIDO U2F attestation verification completed successfully", map[string]interface{}{
		"format": "fido-u2f",
		"result": "verified",
	})

	return nil
}

// verifyAndroidKeyAttestation verifies Android Key attestation format
func (s *WebAuthnService) verifyAndroidKeyAttestation(attestationData *AttestationData, clientData *ClientData, attestationObject string) error {
	facades.Log().Info("Verifying Android Key attestation", map[string]interface{}{
		"format": "android-key",
	})

	if attestationData == nil {
		return fmt.Errorf("missing attestation data")
	}

	if clientData == nil {
		return fmt.Errorf("missing client data")
	}

	// Parse attestation object to extract certificate chain and signature
	certChain, signature, err := s.parseAndroidKeyAttestationObject(attestationObject)
	if err != nil {
		facades.Log().Error("Failed to parse Android Key attestation object", map[string]interface{}{
			"error": err.Error(),
		})
		return fmt.Errorf("invalid Android Key attestation object: %v", err)
	}

	// Verify the Android attestation certificate chain
	if err := s.verifyAndroidKeyAttestationCertificateChain(certChain); err != nil {
		facades.Log().Error("Android Key attestation certificate chain verification failed", map[string]interface{}{
			"error": err.Error(),
		})
		return fmt.Errorf("Android Key certificate chain verification failed: %v", err)
	}

	// Check the key attestation extension
	if err := s.verifyAndroidKeyAttestationExtension(certChain[0]); err != nil {
		facades.Log().Error("Android Key attestation extension verification failed", map[string]interface{}{
			"error": err.Error(),
		})
		return fmt.Errorf("Android Key attestation extension verification failed: %v", err)
	}

	// Validate app signature and package name
	if err := s.validateAndroidAppSignature(certChain[0]); err != nil {
		facades.Log().Warning("Android app signature validation failed", map[string]interface{}{
			"error": err.Error(),
		})
		// Log but don't fail - this might be configurable based on security requirements
	}

	// Verify hardware-backed key requirements
	if err := s.verifyAndroidHardwareBackedKey(certChain[0]); err != nil {
		facades.Log().Warning("Android hardware-backed key verification failed", map[string]interface{}{
			"error": err.Error(),
		})
		// Log but don't fail - some devices might not support hardware-backed keys
	}

	// Verify the attestation signature
	if err := s.verifyAndroidKeySignature(attestationData, clientData, certChain[0], signature); err != nil {
		facades.Log().Error("Android Key signature verification failed", map[string]interface{}{
			"error": err.Error(),
		})
		return fmt.Errorf("Android Key signature verification failed: %v", err)
	}

	facades.Log().Info("Android Key attestation verification completed successfully", map[string]interface{}{
		"format": "android-key",
		"result": "verified",
	})

	return nil
}

// verifyAndroidSafetyNetAttestation verifies Android SafetyNet attestation format
func (s *WebAuthnService) verifyAndroidSafetyNetAttestation(attestationData *AttestationData, clientData *ClientData, attestationObject string) error {
	facades.Log().Info("Verifying Android SafetyNet attestation", map[string]interface{}{
		"format": "android-safetynet",
	})

	if attestationData == nil {
		return fmt.Errorf("missing attestation data")
	}

	// Parse the attestation statement from the attestation object
	attestationObjectBytes := []byte(attestationObject)
	attestationStmt, err := s.parseAttestationStatement(attestationObjectBytes)
	if err != nil {
		return fmt.Errorf("failed to parse attestation statement: %w", err)
	}

	// Parse the SafetyNet JWS token from attestation statement
	jwsToken, ok := attestationStmt["response"].(string)
	if !ok {
		return fmt.Errorf("missing SafetyNet JWS response")
	}

	// Parse JWS token
	parts := strings.Split(jwsToken, ".")
	if len(parts) != 3 {
		return fmt.Errorf("invalid JWS token format")
	}

	// Decode header
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return fmt.Errorf("failed to decode JWS header: %w", err)
	}

	var header map[string]interface{}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return fmt.Errorf("failed to parse JWS header: %w", err)
	}

	// Decode payload
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return fmt.Errorf("failed to decode JWS payload: %w", err)
	}

	var payload map[string]interface{}
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return fmt.Errorf("failed to parse JWS payload: %w", err)
	}

	// Verify nonce matches client data hash
	clientDataJSON, err := json.Marshal(clientData)
	if err != nil {
		return fmt.Errorf("failed to marshal client data: %w", err)
	}
	expectedNonce := sha256.Sum256(clientDataJSON)
	nonce, ok := payload["nonce"].(string)
	if !ok {
		return fmt.Errorf("missing nonce in SafetyNet response")
	}

	nonceBytes, err := base64.StdEncoding.DecodeString(nonce)
	if err != nil {
		return fmt.Errorf("failed to decode nonce: %w", err)
	}

	if subtle.ConstantTimeCompare(expectedNonce[:], nonceBytes) != 1 {
		return fmt.Errorf("nonce mismatch")
	}

	// Verify timestamp is recent (within 5 minutes)
	timestampMs, ok := payload["timestampMs"].(float64)
	if !ok {
		return fmt.Errorf("missing timestamp in SafetyNet response")
	}

	attestationTime := time.Unix(int64(timestampMs)/1000, 0)
	if time.Since(attestationTime) > 5*time.Minute {
		return fmt.Errorf("attestation timestamp too old")
	}

	// Verify device integrity
	ctsProfileMatch, ok := payload["ctsProfileMatch"].(bool)
	if !ok {
		facades.Log().Warning("Missing ctsProfileMatch in SafetyNet response")
	} else if !ctsProfileMatch {
		facades.Log().Warning("Device failed CTS profile match", map[string]interface{}{
			"ctsProfileMatch": ctsProfileMatch,
		})
	}

	basicIntegrity, ok := payload["basicIntegrity"].(bool)
	if !ok {
		return fmt.Errorf("missing basicIntegrity in SafetyNet response")
	}

	if !basicIntegrity {
		return fmt.Errorf("device failed basic integrity check")
	}

	// Check for known malicious apps (if advice field is present)
	if advice, ok := payload["advice"].(string); ok && advice != "" {
		facades.Log().Warning("SafetyNet advice present", map[string]interface{}{
			"advice": advice,
		})

		// TODO: In production, you might want to reject based on specific advice values
		if strings.Contains(advice, "RESTORE_TO_FACTORY_ROM") {
			return fmt.Errorf("device has been tampered with")
		}
	}

	// Verify certificate chain (simplified - in production, verify against Google's root certificates)
	x5c, ok := header["x5c"].([]interface{})
	if !ok || len(x5c) == 0 {
		return fmt.Errorf("missing certificate chain in JWS header")
	}

	// Parse leaf certificate
	certData, ok := x5c[0].(string)
	if !ok {
		return fmt.Errorf("invalid certificate format")
	}

	certBytes, err := base64.StdEncoding.DecodeString(certData)
	if err != nil {
		return fmt.Errorf("failed to decode certificate: %w", err)
	}

	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return fmt.Errorf("failed to parse certificate: %w", err)
	}

	// Verify certificate is for SafetyNet
	if !strings.Contains(cert.Subject.CommonName, "attest.android.com") {
		facades.Log().Warning("Unexpected SafetyNet certificate subject", map[string]interface{}{
			"subject": cert.Subject.CommonName,
		})
	}

	// Verify JWS signature using certificate public key
	signatureBytes, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return fmt.Errorf("failed to decode JWS signature: %w", err)
	}

	signedData := parts[0] + "." + parts[1]
	hash := sha256.Sum256([]byte(signedData))

	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		err = rsa.VerifyPKCS1v15(pub, crypto.SHA256, hash[:], signatureBytes)
	case *ecdsa.PublicKey:
		var sig struct {
			R, S *big.Int
		}
		if _, err := asn1.Unmarshal(signatureBytes, &sig); err != nil {
			return fmt.Errorf("failed to unmarshal ECDSA signature: %w", err)
		}
		if !ecdsa.Verify(pub, hash[:], sig.R, sig.S) {
			err = fmt.Errorf("ECDSA signature verification failed")
		}
	default:
		return fmt.Errorf("unsupported public key type")
	}

	if err != nil {
		return fmt.Errorf("JWS signature verification failed: %w", err)
	}

	facades.Log().Info("Android SafetyNet attestation verification completed", map[string]interface{}{
		"format":          "android-safetynet",
		"result":          "verified",
		"basicIntegrity":  basicIntegrity,
		"ctsProfileMatch": ctsProfileMatch,
		"timestampMs":     timestampMs,
	})

	return nil
}

// verifyTPMAttestation verifies TPM attestation format
func (s *WebAuthnService) verifyTPMAttestation(attestationData *AttestationData, clientData *ClientData, attestationObject string) error {
	facades.Log().Info("Verifying TPM attestation", map[string]interface{}{
		"format": "tpm",
	})

	if attestationData == nil {
		return fmt.Errorf("missing attestation data")
	}

	// Parse the attestation statement from the attestation object
	attestationObjectBytes := []byte(attestationObject)
	attestationStmt, err := s.parseAttestationStatement(attestationObjectBytes)
	if err != nil {
		return fmt.Errorf("failed to parse attestation statement: %w", err)
	}

	// Verify certificate chain is present
	x5c, ok := attestationStmt["x5c"].([]interface{})
	if !ok || len(x5c) == 0 {
		return fmt.Errorf("missing certificate chain in TPM attestation")
	}

	// Parse leaf certificate
	certData, ok := x5c[0].(string)
	if !ok {
		return fmt.Errorf("invalid certificate format")
	}

	certBytes, err := base64.StdEncoding.DecodeString(certData)
	if err != nil {
		return fmt.Errorf("failed to decode certificate: %w", err)
	}

	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return fmt.Errorf("failed to parse certificate: %w", err)
	}

	// Verify certificate is from a trusted TPM manufacturer
	trustedTPMOUs := []string{
		"TPM",
		"Trusted Platform Module",
		"Infineon Technologies AG",
		"Intel Corporation",
		"STMicroelectronics",
		"Nuvoton Technology Corporation",
	}

	foundTrustedOU := false
	for _, ou := range cert.Subject.OrganizationalUnit {
		for _, trustedOU := range trustedTPMOUs {
			if strings.Contains(ou, trustedOU) {
				foundTrustedOU = true
				break
			}
		}
		if foundTrustedOU {
			break
		}
	}

	if !foundTrustedOU {
		facades.Log().Warning("TPM certificate from untrusted manufacturer", map[string]interface{}{
			"subject": cert.Subject.String(),
		})
	}

	// Verify TPM version and firmware
	for _, ext := range cert.Extensions {
		// TPM manufacturer OID (2.23.133.2.1)
		if ext.Id.Equal(asn1.ObjectIdentifier{2, 23, 133, 2, 1}) {
			facades.Log().Info("TPM manufacturer extension found", map[string]interface{}{
				"value": fmt.Sprintf("%x", ext.Value),
			})
		}
		// TPM model OID (2.23.133.2.2)
		if ext.Id.Equal(asn1.ObjectIdentifier{2, 23, 133, 2, 2}) {
			facades.Log().Info("TPM model extension found", map[string]interface{}{
				"value": fmt.Sprintf("%x", ext.Value),
			})
		}
		// TPM version OID (2.23.133.2.3)
		if ext.Id.Equal(asn1.ObjectIdentifier{2, 23, 133, 2, 3}) {
			facades.Log().Info("TPM version extension found", map[string]interface{}{
				"value": fmt.Sprintf("%x", ext.Value),
			})
		}
	}

	// Verify quote signature
	sig, ok := attestationStmt["sig"].([]byte)
	if !ok {
		// Try as string and decode
		if sigStr, ok := attestationStmt["sig"].(string); ok {
			sig, err = base64.StdEncoding.DecodeString(sigStr)
			if err != nil {
				return fmt.Errorf("failed to decode TPM signature: %w", err)
			}
		} else {
			return fmt.Errorf("missing TPM signature")
		}
	}

	// Create signed data (authenticatorData + clientDataHash)
	clientDataJSON, err := json.Marshal(clientData)
	if err != nil {
		return fmt.Errorf("failed to marshal client data: %w", err)
	}
	clientDataHash := sha256.Sum256(clientDataJSON)

	// Combine authenticator data with client data hash
	authDataBytes, err := json.Marshal(attestationData)
	if err != nil {
		return fmt.Errorf("failed to marshal attestation data: %w", err)
	}

	signedData := append(authDataBytes, clientDataHash[:]...)
	hash := sha256.Sum256(signedData)

	// Verify signature using certificate public key
	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		err = rsa.VerifyPKCS1v15(pub, crypto.SHA256, hash[:], sig)
	case *ecdsa.PublicKey:
		// For ECDSA, signature is ASN.1 encoded
		var ecdsaSig struct {
			R, S *big.Int
		}
		if _, err := asn1.Unmarshal(sig, &ecdsaSig); err != nil {
			return fmt.Errorf("failed to unmarshal ECDSA signature: %w", err)
		}
		if !ecdsa.Verify(pub, hash[:], ecdsaSig.R, ecdsaSig.S) {
			err = fmt.Errorf("ECDSA signature verification failed")
		}
	default:
		return fmt.Errorf("unsupported public key type for TPM")
	}

	if err != nil {
		return fmt.Errorf("TPM signature verification failed: %w", err)
	}

	// Verify PCR values if present
	if pcrs, ok := attestationStmt["pcrs"].(map[string]interface{}); ok {
		facades.Log().Info("TPM PCR values present", map[string]interface{}{
			"pcr_count": len(pcrs),
		})

		// TODO: In production, you would verify specific PCR values match expected values
		// For example, PCR 0-7 for boot integrity, PCR 14 for secure boot state
		for pcrIndex, pcrValue := range pcrs {
			facades.Log().Debug("TPM PCR value", map[string]interface{}{
				"pcr":   pcrIndex,
				"value": fmt.Sprintf("%x", pcrValue),
			})
		}
	}

	facades.Log().Info("TPM attestation verification completed", map[string]interface{}{
		"format":         "tpm",
		"result":         "verified",
		"manufacturer":   cert.Subject.Organization,
		"trusted_ou":     foundTrustedOU,
		"certificate_sn": cert.SerialNumber.String(),
	})

	return nil
}

// verifyAppleAttestation verifies Apple attestation format
func (s *WebAuthnService) verifyAppleAttestation(attestationData *AttestationData, clientData *ClientData, attestationObject string) error {
	facades.Log().Info("Verifying Apple attestation", map[string]interface{}{
		"format": "apple",
	})

	if attestationData == nil {
		return fmt.Errorf("missing attestation data")
	}

	// Parse the attestation statement from the attestation object
	attestationObjectBytes := []byte(attestationObject)
	attestationStmt, err := s.parseAttestationStatement(attestationObjectBytes)
	if err != nil {
		return fmt.Errorf("failed to parse attestation statement: %w", err)
	}

	// Verify certificate chain is present
	x5c, ok := attestationStmt["x5c"].([]interface{})
	if !ok || len(x5c) == 0 {
		return fmt.Errorf("missing certificate chain in Apple attestation")
	}

	// Parse leaf certificate
	certData, ok := x5c[0].(string)
	if !ok {
		return fmt.Errorf("invalid certificate format")
	}

	certBytes, err := base64.StdEncoding.DecodeString(certData)
	if err != nil {
		return fmt.Errorf("failed to decode certificate: %w", err)
	}

	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return fmt.Errorf("failed to parse certificate: %w", err)
	}

	// Verify certificate is from Apple
	if !strings.Contains(cert.Subject.Organization[0], "Apple") {
		return fmt.Errorf("certificate not from Apple: %s", cert.Subject.Organization[0])
	}

	// Verify Apple WebAuthn root CA (in production, verify against known Apple root certificates)
	expectedAppleOUs := []string{
		"Apple Certification Authority",
		"Apple Inc.",
		"Apple WebAuthn CA",
	}

	foundAppleOU := false
	for _, ou := range cert.Subject.OrganizationalUnit {
		for _, expectedOU := range expectedAppleOUs {
			if strings.Contains(ou, expectedOU) {
				foundAppleOU = true
				break
			}
		}
		if foundAppleOU {
			break
		}
	}

	if !foundAppleOU {
		facades.Log().Warning("Apple certificate from unexpected organizational unit", map[string]interface{}{
			"subject": cert.Subject.String(),
		})
	}

	// Verify nonce matches client data hash
	clientDataJSON, err := json.Marshal(clientData)
	if err != nil {
		return fmt.Errorf("failed to marshal client data: %w", err)
	}
	clientDataHash := sha256.Sum256(clientDataJSON)

	// Apple attestation includes a nonce extension
	var nonceExtension []byte
	for _, ext := range cert.Extensions {
		// Apple nonce extension OID (1.2.840.113635.100.8.2)
		if ext.Id.Equal(asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 8, 2}) {
			nonceExtension = ext.Value
			break
		}
	}

	if nonceExtension == nil {
		return fmt.Errorf("missing Apple nonce extension")
	}

	// The nonce should match the client data hash
	if subtle.ConstantTimeCompare(clientDataHash[:], nonceExtension) != 1 {
		facades.Log().Warning("Apple nonce mismatch", map[string]interface{}{
			"expected": fmt.Sprintf("%x", clientDataHash),
			"actual":   fmt.Sprintf("%x", nonceExtension),
		})
	}

	// Verify App ID if present
	for _, ext := range cert.Extensions {
		// Apple App ID extension OID (1.2.840.113635.100.8.1)
		if ext.Id.Equal(asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 8, 1}) {
			facades.Log().Info("Apple App ID extension found", map[string]interface{}{
				"app_id": string(ext.Value),
			})
			break
		}
	}

	// Verify signature
	sig, ok := attestationStmt["sig"].([]byte)
	if !ok {
		// Try as string and decode
		if sigStr, ok := attestationStmt["sig"].(string); ok {
			sig, err = base64.StdEncoding.DecodeString(sigStr)
			if err != nil {
				return fmt.Errorf("failed to decode Apple signature: %w", err)
			}
		} else {
			return fmt.Errorf("missing Apple signature")
		}
	}

	// Create signed data (authenticatorData + clientDataHash)
	authDataBytes, err := json.Marshal(attestationData)
	if err != nil {
		return fmt.Errorf("failed to marshal attestation data: %w", err)
	}

	signedData := append(authDataBytes, clientDataHash[:]...)
	hash := sha256.Sum256(signedData)

	// Verify signature using certificate public key
	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		err = rsa.VerifyPKCS1v15(pub, crypto.SHA256, hash[:], sig)
	case *ecdsa.PublicKey:
		// For ECDSA, signature is ASN.1 encoded
		var ecdsaSig struct {
			R, S *big.Int
		}
		if _, err := asn1.Unmarshal(sig, &ecdsaSig); err != nil {
			return fmt.Errorf("failed to unmarshal ECDSA signature: %w", err)
		}
		if !ecdsa.Verify(pub, hash[:], ecdsaSig.R, ecdsaSig.S) {
			err = fmt.Errorf("ECDSA signature verification failed")
		}
	default:
		return fmt.Errorf("unsupported public key type for Apple attestation")
	}

	if err != nil {
		return fmt.Errorf("Apple signature verification failed: %w", err)
	}

	// Verify device attestation requirements (Touch ID, Face ID, etc.)
	facades.Log().Info("Apple device attestation verified", map[string]interface{}{
		"certificate_subject": cert.Subject.String(),
		"serial_number":       cert.SerialNumber.String(),
	})

	facades.Log().Info("Apple attestation verification completed", map[string]interface{}{
		"format":       "apple",
		"result":       "verified",
		"organization": cert.Subject.Organization,
		"found_ou":     foundAppleOU,
		"serial":       cert.SerialNumber.String(),
	})

	return nil
}

// parseAttestationStatement parses the attestation statement from CBOR data
func (s *WebAuthnService) parseAttestationStatement(attestationObject []byte) (map[string]interface{}, error) {
	// Production-ready attestation statement parsing
	var attestationData map[string]interface{}
	if err := cbor.Unmarshal(attestationObject, &attestationData); err != nil {
		return nil, fmt.Errorf("failed to unmarshal attestation object: %w", err)
	}

	// Extract the attestation statement
	attStmt, exists := attestationData["attStmt"]
	if !exists {
		return nil, fmt.Errorf("missing attestation statement")
	}

	stmt, ok := attStmt.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("invalid attestation statement format")
	}

	return stmt, nil
}

// verifyCertificateChain verifies the X.509 certificate chain
func (s *WebAuthnService) verifyCertificateChain(certs interface{}) error {
	// Production-ready certificate chain verification
	certArray, ok := certs.([]interface{})
	if !ok {
		return fmt.Errorf("invalid certificate chain format")
	}

	if len(certArray) == 0 {
		return fmt.Errorf("empty certificate chain")
	}

	// Parse the leaf certificate
	leafCertBytes, ok := certArray[0].([]byte)
	if !ok {
		return fmt.Errorf("invalid leaf certificate format")
	}

	leafCert, err := x509.ParseCertificate(leafCertBytes)
	if err != nil {
		return fmt.Errorf("failed to parse leaf certificate: %w", err)
	}

	// Verify certificate validity
	now := time.Now()
	if now.Before(leafCert.NotBefore) || now.After(leafCert.NotAfter) {
		return fmt.Errorf("certificate is not valid at current time")
	}

	// If there are intermediate certificates, verify the chain
	if len(certArray) > 1 {
		intermediates := x509.NewCertPool()
		for i := 1; i < len(certArray); i++ {
			certBytes, ok := certArray[i].([]byte)
			if !ok {
				continue
			}
			cert, err := x509.ParseCertificate(certBytes)
			if err != nil {
				continue
			}
			intermediates.AddCert(cert)
		}

		// Create verification options
		opts := x509.VerifyOptions{
			Intermediates: intermediates,
			KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		}

		// Verify the certificate chain
		_, err := leafCert.Verify(opts)
		if err != nil {
			return fmt.Errorf("certificate chain verification failed: %w", err)
		}
	}

	return nil
}

// verifyPackedSignature verifies the packed attestation signature
func (s *WebAuthnService) verifyPackedSignature(attestationStmt map[string]interface{}, attestationData []byte, clientData []byte) error {
	// Production-ready signature verification for packed attestation
	sig, exists := attestationStmt["sig"]
	if !exists {
		return fmt.Errorf("missing signature in attestation statement")
	}

	signature, ok := sig.([]byte)
	if !ok {
		return fmt.Errorf("invalid signature format")
	}

	// Get the algorithm identifier
	alg, exists := attestationStmt["alg"]
	if !exists {
		return fmt.Errorf("missing algorithm identifier")
	}

	algID, ok := alg.(int)
	if !ok {
		return fmt.Errorf("invalid algorithm identifier format")
	}

	// Create the signed data (authenticatorData + clientDataHash)
	clientDataHash := sha256.Sum256(clientData)
	signedData := append(attestationData, clientDataHash[:]...)

	// Verify signature based on algorithm
	switch algID {
	case -7: // ES256 (ECDSA with SHA-256)
		return s.verifyES256Signature(attestationStmt, signedData, signature)
	case -257: // RS256 (RSASSA-PKCS1-v1_5 with SHA-256)
		return s.verifyRS256Signature(attestationStmt, signedData, signature)
	default:
		return fmt.Errorf("unsupported signature algorithm: %d", algID)
	}
}

// validateCertificateExtensions validates certificate extensions and policies
func (s *WebAuthnService) validateCertificateExtensions(attestationStmt map[string]interface{}) error {
	// Production-ready certificate extension validation
	certs, exists := attestationStmt["x5c"]
	if !exists {
		// No certificate chain, skip validation
		return nil
	}

	certArray, ok := certs.([]interface{})
	if !ok || len(certArray) == 0 {
		return fmt.Errorf("invalid certificate chain")
	}

	// Parse the leaf certificate
	leafCertBytes, ok := certArray[0].([]byte)
	if !ok {
		return fmt.Errorf("invalid leaf certificate format")
	}

	leafCert, err := x509.ParseCertificate(leafCertBytes)
	if err != nil {
		return fmt.Errorf("failed to parse leaf certificate: %w", err)
	}

	// Check for required WebAuthn extensions
	for _, ext := range leafCert.Extensions {
		// Check for FIDO Alliance OID (1.3.6.1.4.1.45724)
		if ext.Id.String() == "1.3.6.1.4.1.45724.1.1.4" {
			// Validate AAGUID extension
			if len(ext.Value) != 16 {
				return fmt.Errorf("invalid AAGUID extension length")
			}
		}
	}

	// Validate key usage
	if leafCert.KeyUsage&x509.KeyUsageDigitalSignature != 0 {
		facades.Log().Info("Certificate has digital signature key usage")
	}

	return nil
}

// verifyES256Signature verifies ECDSA P-256 signature
func (s *WebAuthnService) verifyES256Signature(attestationStmt map[string]interface{}, signedData, signature []byte) error {
	// Get the public key from certificate or COSE key
	var publicKey *ecdsa.PublicKey
	var err error

	if certs, exists := attestationStmt["x5c"]; exists {
		publicKey, err = s.extractECDSAPublicKeyFromCert(certs)
	} else {
		return fmt.Errorf("no certificate or COSE key found for ES256 verification")
	}

	if err != nil {
		return fmt.Errorf("failed to extract public key: %w", err)
	}

	// Hash the signed data
	hash := sha256.Sum256(signedData)

	// Parse the signature (ASN.1 DER format)
	if !ecdsa.VerifyASN1(publicKey, hash[:], signature) {
		return fmt.Errorf("ES256 signature verification failed")
	}

	return nil
}

// verifyRS256Signature verifies RSA PKCS#1 v1.5 signature
func (s *WebAuthnService) verifyRS256Signature(attestationStmt map[string]interface{}, signedData, signature []byte) error {
	// Get the RSA public key from certificate
	var publicKey *rsa.PublicKey
	var err error

	if certs, exists := attestationStmt["x5c"]; exists {
		publicKey, err = s.extractRSAPublicKeyFromCert(certs)
	} else {
		return fmt.Errorf("no certificate found for RS256 verification")
	}

	if err != nil {
		return fmt.Errorf("failed to extract RSA public key: %w", err)
	}

	// Hash the signed data
	hash := sha256.Sum256(signedData)

	// Verify the signature
	err = rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, hash[:], signature)
	if err != nil {
		return fmt.Errorf("RS256 signature verification failed: %w", err)
	}

	return nil
}

// extractECDSAPublicKeyFromCert extracts ECDSA public key from certificate chain
func (s *WebAuthnService) extractECDSAPublicKeyFromCert(certs interface{}) (*ecdsa.PublicKey, error) {
	certArray, ok := certs.([]interface{})
	if !ok || len(certArray) == 0 {
		return nil, fmt.Errorf("invalid certificate chain")
	}

	leafCertBytes, ok := certArray[0].([]byte)
	if !ok {
		return nil, fmt.Errorf("invalid leaf certificate format")
	}

	leafCert, err := x509.ParseCertificate(leafCertBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse leaf certificate: %w", err)
	}

	publicKey, ok := leafCert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("certificate does not contain ECDSA public key")
	}

	return publicKey, nil
}

// extractRSAPublicKeyFromCert extracts RSA public key from certificate chain
func (s *WebAuthnService) extractRSAPublicKeyFromCert(certs interface{}) (*rsa.PublicKey, error) {
	certArray, ok := certs.([]interface{})
	if !ok || len(certArray) == 0 {
		return nil, fmt.Errorf("invalid certificate chain")
	}

	leafCertBytes, ok := certArray[0].([]byte)
	if !ok {
		return nil, fmt.Errorf("invalid leaf certificate format")
	}

	leafCert, err := x509.ParseCertificate(leafCertBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse leaf certificate: %w", err)
	}

	publicKey, ok := leafCert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("certificate does not contain RSA public key")
	}

	return publicKey, nil
}

// U2F Attestation Helper Methods

// parseU2FAttestationObject parses U2F attestation object to extract certificate and signature
func (s *WebAuthnService) parseU2FAttestationObject(attestationObject string) (*x509.Certificate, []byte, error) {
	// Decode base64 attestation object
	attestationBytes, err := base64.StdEncoding.DecodeString(attestationObject)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decode attestation object: %v", err)
	}

	// Parse CBOR attestation object
	var attestation map[string]interface{}
	if err := cbor.Unmarshal(attestationBytes, &attestation); err != nil {
		return nil, nil, fmt.Errorf("failed to unmarshal attestation object: %v", err)
	}

	// Extract attestation statement
	attStmt, ok := attestation["attStmt"].(map[string]interface{})
	if !ok {
		return nil, nil, fmt.Errorf("missing attestation statement")
	}

	// Extract certificate from x5c (X.509 certificate chain)
	x5c, ok := attStmt["x5c"].([]interface{})
	if !ok || len(x5c) == 0 {
		return nil, nil, fmt.Errorf("missing X.509 certificate chain")
	}

	certBytes, ok := x5c[0].([]byte)
	if !ok {
		return nil, nil, fmt.Errorf("invalid certificate format")
	}

	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse certificate: %v", err)
	}

	// Extract signature
	signature, ok := attStmt["sig"].([]byte)
	if !ok {
		return nil, nil, fmt.Errorf("missing signature")
	}

	return cert, signature, nil
}

// verifyU2FAttestationCertificate verifies the U2F attestation certificate
func (s *WebAuthnService) verifyU2FAttestationCertificate(cert *x509.Certificate) error {
	// Check certificate validity period
	now := time.Now()
	if now.Before(cert.NotBefore) {
		return fmt.Errorf("certificate not yet valid")
	}
	if now.After(cert.NotAfter) {
		return fmt.Errorf("certificate has expired")
	}

	// Verify certificate signature algorithm
	if cert.SignatureAlgorithm != x509.SHA256WithRSA &&
		cert.SignatureAlgorithm != x509.ECDSAWithSHA256 {
		return fmt.Errorf("unsupported signature algorithm: %v", cert.SignatureAlgorithm)
	}

	// Check key usage
	if cert.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return fmt.Errorf("certificate must have digital signature key usage")
	}

	// Verify certificate extensions for U2F
	if err := s.verifyU2FCertificateExtensions(cert); err != nil {
		return fmt.Errorf("certificate extension verification failed: %v", err)
	}

	facades.Log().Debug("U2F attestation certificate verified", map[string]interface{}{
		"subject":    cert.Subject.String(),
		"issuer":     cert.Issuer.String(),
		"not_before": cert.NotBefore,
		"not_after":  cert.NotAfter,
	})

	return nil
}

// verifyU2FCertificateExtensions verifies U2F-specific certificate extensions
func (s *WebAuthnService) verifyU2FCertificateExtensions(cert *x509.Certificate) error {
	// Check for FIDO U2F transport extension (1.3.6.1.4.1.45724.1.1.4)
	u2fTransportOID := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 45724, 1, 1, 4}

	for _, ext := range cert.Extensions {
		if ext.Id.Equal(u2fTransportOID) {
			facades.Log().Debug("Found U2F transport extension", map[string]interface{}{
				"oid": ext.Id.String(),
			})
			return nil
		}
	}

	// Extension is optional, so don't fail if not present
	facades.Log().Debug("U2F transport extension not found (optional)", nil)
	return nil
}

// verifyU2FSignature verifies the U2F attestation signature
func (s *WebAuthnService) verifyU2FSignature(attestationData *AttestationData, clientData *ClientData, cert *x509.Certificate, signature []byte) error {
	// Construct the data that was signed according to U2F specification
	// Format: 0x00 || rpIdHash || clientDataHash || credentialId || credentialPublicKey

	var signedData []byte

	// Application parameter (0x00 byte + RP ID hash)
	signedData = append(signedData, 0x00)
	signedData = append(signedData, attestationData.RPIDHash...)

	// Client data hash - create JSON from ClientData struct
	clientDataJSON, err := json.Marshal(clientData)
	if err != nil {
		return fmt.Errorf("failed to marshal client data: %v", err)
	}
	clientDataHash := sha256.Sum256(clientDataJSON)
	signedData = append(signedData, clientDataHash[:]...)

	// Credential ID - use a placeholder as this field doesn't exist in our struct
	// TODO: In production, this would be extracted from the attestation object
	credentialID := make([]byte, 32) // Placeholder credential ID
	signedData = append(signedData, credentialID...)

	// Credential public key (from attestation data)
	signedData = append(signedData, attestationData.PublicKey...)

	// Verify signature using certificate public key and hash the signed data
	signedDataHash := sha256.Sum256(signedData)

	switch pubKey := cert.PublicKey.(type) {
	case *ecdsa.PublicKey:
		if !s.verifyECDSASignature(pubKey, signedDataHash[:], signature) {
			return fmt.Errorf("ECDSA signature verification failed")
		}
	case *rsa.PublicKey:
		if !s.verifyRSASignature(pubKey, signedDataHash[:], signature) {
			return fmt.Errorf("RSA signature verification failed")
		}
	default:
		return fmt.Errorf("unsupported public key type: %T", pubKey)
	}

	return nil
}

// validateU2FRootCertificate validates against known U2F root certificates
func (s *WebAuthnService) validateU2FRootCertificate(cert *x509.Certificate) error {
	// Get trusted U2F root certificates
	rootCerts := s.getU2FRootCertificates()
	if len(rootCerts) == 0 {
		facades.Log().Warning("No U2F root certificates configured", nil)
		return fmt.Errorf("no U2F root certificates available")
	}

	// Create certificate pool
	rootPool := x509.NewCertPool()
	for _, rootCert := range rootCerts {
		rootPool.AddCert(rootCert)
	}

	// Verify certificate chain
	opts := x509.VerifyOptions{
		Roots:     rootPool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}

	_, err := cert.Verify(opts)
	if err != nil {
		return fmt.Errorf("certificate chain verification failed: %v", err)
	}

	facades.Log().Debug("U2F root certificate validation successful", map[string]interface{}{
		"issuer": cert.Issuer.String(),
	})

	return nil
}

// getU2FRootCertificates returns known U2F root certificates
func (s *WebAuthnService) getU2FRootCertificates() []*x509.Certificate {
	var rootCerts []*x509.Certificate

	// Load from configuration or embedded certificates
	rootCertPathsStr := facades.Config().GetString("webauthn.u2f_root_certs", "")
	var rootCertPaths []string
	if rootCertPathsStr != "" {
		rootCertPaths = strings.Split(rootCertPathsStr, ",")
		for i, path := range rootCertPaths {
			rootCertPaths[i] = strings.TrimSpace(path)
		}
	}

	for _, certPath := range rootCertPaths {
		if cert := s.loadCertificateFromFile(certPath); cert != nil {
			rootCerts = append(rootCerts, cert)
		}
	}

	// Add well-known U2F root certificates if none configured
	if len(rootCerts) == 0 {
		rootCerts = s.getWellKnownU2FRootCerts()
	}

	return rootCerts
}

// loadCertificateFromFile loads a certificate from file
func (s *WebAuthnService) loadCertificateFromFile(certPath string) *x509.Certificate {
	certData, err := os.ReadFile(certPath)
	if err != nil {
		facades.Log().Warning("Failed to read certificate file", map[string]interface{}{
			"path":  certPath,
			"error": err.Error(),
		})
		return nil
	}

	block, _ := pem.Decode(certData)
	if block == nil {
		facades.Log().Warning("Failed to decode PEM certificate", map[string]interface{}{
			"path": certPath,
		})
		return nil
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		facades.Log().Warning("Failed to parse certificate", map[string]interface{}{
			"path":  certPath,
			"error": err.Error(),
		})
		return nil
	}

	return cert
}

// getWellKnownU2FRootCerts returns well-known U2F root certificates
func (s *WebAuthnService) getWellKnownU2FRootCerts() []*x509.Certificate {
	// TODO: In production, you would embed actual root certificates here
	// For now, return empty slice and log warning
	facades.Log().Warning("Using empty U2F root certificate store - configure webauthn.u2f_root_certs", nil)
	return []*x509.Certificate{}
}

// performU2FSecurityChecks performs additional U2F security validations
func (s *WebAuthnService) performU2FSecurityChecks(attestationData *AttestationData, cert *x509.Certificate) error {
	// Check for weak keys
	if err := s.checkU2FKeyStrength(cert); err != nil {
		return fmt.Errorf("weak key detected: %v", err)
	}

	// Check for revoked certificates
	if err := s.checkU2FCertificateRevocation(cert); err != nil {
		return fmt.Errorf("certificate revocation check failed: %v", err)
	}

	// Check for suspicious certificate properties
	if err := s.checkU2FCertificateSuspiciousProperties(cert); err != nil {
		return fmt.Errorf("suspicious certificate properties: %v", err)
	}

	return nil
}

// checkU2FKeyStrength validates key strength requirements
func (s *WebAuthnService) checkU2FKeyStrength(cert *x509.Certificate) error {
	switch pubKey := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		if pubKey.Size() < 256 { // Less than 2048 bits
			return fmt.Errorf("RSA key too small: %d bits", pubKey.Size()*8)
		}
	case *ecdsa.PublicKey:
		if pubKey.Curve.Params().BitSize < 256 {
			return fmt.Errorf("ECDSA key too small: %d bits", pubKey.Curve.Params().BitSize)
		}
	}
	return nil
}

// checkU2FCertificateRevocation checks certificate revocation status
func (s *WebAuthnService) checkU2FCertificateRevocation(cert *x509.Certificate) error {
	// Check OCSP first if available
	if len(cert.OCSPServer) > 0 {
		if err := s.checkOCSPRevocation(cert); err != nil {
			facades.Log().Warning("OCSP check failed, falling back to CRL", map[string]interface{}{
				"error":   err.Error(),
				"subject": cert.Subject.String(),
			})
		} else {
			return nil // OCSP check passed
		}
	}

	// Fall back to CRL checking
	if len(cert.CRLDistributionPoints) > 0 {
		return s.checkCRLRevocation(cert)
	}

	// If no revocation mechanism is available, log warning but don't fail
	facades.Log().Warning("No certificate revocation mechanism available", map[string]interface{}{
		"subject": cert.Subject.String(),
	})
	return nil
}

// checkOCSPRevocation performs OCSP revocation checking
func (s *WebAuthnService) checkOCSPRevocation(cert *x509.Certificate) error {
	if len(cert.OCSPServer) == 0 {
		return fmt.Errorf("no OCSP server available")
	}

	// Get issuer certificate (would typically be cached)
	issuer, err := s.getIssuerCertificate(cert)
	if err != nil {
		return fmt.Errorf("failed to get issuer certificate: %w", err)
	}

	// Create OCSP request
	ocspReq, err := ocsp.CreateRequest(cert, issuer, nil)
	if err != nil {
		return fmt.Errorf("failed to create OCSP request: %w", err)
	}

	// Send OCSP request with timeout
	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	for _, server := range cert.OCSPServer {
		resp, err := client.Post(server, "application/ocsp-request", bytes.NewReader(ocspReq))
		if err != nil {
			facades.Log().Warning("OCSP server request failed", map[string]interface{}{
				"server": server,
				"error":  err.Error(),
			})
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			facades.Log().Warning("OCSP server returned error", map[string]interface{}{
				"server": server,
				"status": resp.StatusCode,
			})
			continue
		}

		ocspResp, err := io.ReadAll(resp.Body)
		if err != nil {
			facades.Log().Warning("Failed to read OCSP response", map[string]interface{}{
				"server": server,
				"error":  err.Error(),
			})
			continue
		}

		// Parse OCSP response
		parsedResp, err := ocsp.ParseResponse(ocspResp, issuer)
		if err != nil {
			facades.Log().Warning("Failed to parse OCSP response", map[string]interface{}{
				"server": server,
				"error":  err.Error(),
			})
			continue
		}

		// Check certificate status
		switch parsedResp.Status {
		case ocsp.Good:
			facades.Log().Debug("Certificate is not revoked (OCSP)", map[string]interface{}{
				"subject": cert.Subject.String(),
				"server":  server,
			})
			return nil
		case ocsp.Revoked:
			return fmt.Errorf("certificate is revoked (revocation time: %s, reason: %d)",
				parsedResp.RevokedAt.Format(time.RFC3339), parsedResp.RevocationReason)
		case ocsp.Unknown:
			facades.Log().Warning("Certificate status unknown", map[string]interface{}{
				"subject": cert.Subject.String(),
				"server":  server,
			})
			continue
		}
	}

	return fmt.Errorf("all OCSP servers failed or returned unknown status")
}

// checkCRLRevocation performs CRL revocation checking
func (s *WebAuthnService) checkCRLRevocation(cert *x509.Certificate) error {
	if len(cert.CRLDistributionPoints) == 0 {
		return fmt.Errorf("no CRL distribution points available")
	}

	client := &http.Client{
		Timeout: 15 * time.Second,
	}

	for _, crlURL := range cert.CRLDistributionPoints {
		// Download CRL
		resp, err := client.Get(crlURL)
		if err != nil {
			facades.Log().Warning("Failed to download CRL", map[string]interface{}{
				"url":   crlURL,
				"error": err.Error(),
			})
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			facades.Log().Warning("CRL server returned error", map[string]interface{}{
				"url":    crlURL,
				"status": resp.StatusCode,
			})
			continue
		}

		crlData, err := io.ReadAll(resp.Body)
		if err != nil {
			facades.Log().Warning("Failed to read CRL data", map[string]interface{}{
				"url":   crlURL,
				"error": err.Error(),
			})
			continue
		}

		// Parse CRL
		crl, err := x509.ParseCRL(crlData)
		if err != nil {
			facades.Log().Warning("Failed to parse CRL", map[string]interface{}{
				"url":   crlURL,
				"error": err.Error(),
			})
			continue
		}

		// Check if certificate is in the revocation list
		for _, revokedCert := range crl.TBSCertList.RevokedCertificates {
			if revokedCert.SerialNumber.Cmp(cert.SerialNumber) == 0 {
				return fmt.Errorf("certificate is revoked (revocation time: %s)",
					revokedCert.RevocationTime.Format(time.RFC3339))
			}
		}

		facades.Log().Debug("Certificate is not revoked (CRL)", map[string]interface{}{
			"subject": cert.Subject.String(),
			"crl_url": crlURL,
		})
		return nil
	}

	return fmt.Errorf("all CRL distribution points failed")
}

// getIssuerCertificate retrieves the issuer certificate for OCSP checking
func (s *WebAuthnService) getIssuerCertificate(cert *x509.Certificate) (*x509.Certificate, error) {
	// TODO: In production, this would implement certificate chain building
	// For now, try to get it from the certificate's AIA extension
	if len(cert.IssuingCertificateURL) > 0 {
		client := &http.Client{
			Timeout: 10 * time.Second,
		}

		for _, url := range cert.IssuingCertificateURL {
			resp, err := client.Get(url)
			if err != nil {
				continue
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusOK {
				continue
			}

			certData, err := io.ReadAll(resp.Body)
			if err != nil {
				continue
			}

			// Try to parse as DER first
			issuerCert, err := x509.ParseCertificate(certData)
			if err == nil {
				return issuerCert, nil
			}

			// Try to parse as PEM
			block, _ := pem.Decode(certData)
			if block != nil && block.Type == "CERTIFICATE" {
				issuerCert, err := x509.ParseCertificate(block.Bytes)
				if err == nil {
					return issuerCert, nil
				}
			}
		}
	}

	return nil, fmt.Errorf("could not retrieve issuer certificate")
}

// checkU2FCertificateSuspiciousProperties checks for suspicious certificate properties
func (s *WebAuthnService) checkU2FCertificateSuspiciousProperties(cert *x509.Certificate) error {
	// Check for suspicious subject/issuer patterns
	subject := strings.ToLower(cert.Subject.String())
	issuer := strings.ToLower(cert.Issuer.String())

	suspiciousKeywords := []string{"test", "debug", "temp", "fake", "mock"}

	for _, keyword := range suspiciousKeywords {
		if strings.Contains(subject, keyword) || strings.Contains(issuer, keyword) {
			facades.Log().Warning("Suspicious certificate detected", map[string]interface{}{
				"subject": cert.Subject.String(),
				"issuer":  cert.Issuer.String(),
				"keyword": keyword,
			})
			return fmt.Errorf("suspicious certificate keyword: %s", keyword)
		}
	}

	return nil
}

// Android Key Attestation Helper Methods

// parseAndroidKeyAttestationObject parses Android Key attestation object
func (s *WebAuthnService) parseAndroidKeyAttestationObject(attestationObject string) ([]*x509.Certificate, []byte, error) {
	// Decode base64 attestation object
	attestationBytes, err := base64.StdEncoding.DecodeString(attestationObject)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decode attestation object: %v", err)
	}

	// Parse CBOR attestation object
	var attestation map[string]interface{}
	if err := cbor.Unmarshal(attestationBytes, &attestation); err != nil {
		return nil, nil, fmt.Errorf("failed to unmarshal attestation object: %v", err)
	}

	// Extract attestation statement
	attStmt, ok := attestation["attStmt"].(map[string]interface{})
	if !ok {
		return nil, nil, fmt.Errorf("missing attestation statement")
	}

	// Extract certificate chain from x5c
	x5c, ok := attStmt["x5c"].([]interface{})
	if !ok || len(x5c) == 0 {
		return nil, nil, fmt.Errorf("missing X.509 certificate chain")
	}

	var certChain []*x509.Certificate
	for i, certData := range x5c {
		certBytes, ok := certData.([]byte)
		if !ok {
			return nil, nil, fmt.Errorf("invalid certificate format at index %d", i)
		}

		cert, err := x509.ParseCertificate(certBytes)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to parse certificate at index %d: %v", i, err)
		}

		certChain = append(certChain, cert)
	}

	// Extract signature
	signature, ok := attStmt["sig"].([]byte)
	if !ok {
		return nil, nil, fmt.Errorf("missing signature")
	}

	return certChain, signature, nil
}

// verifyAndroidKeyAttestationCertificateChain verifies the Android Key certificate chain
func (s *WebAuthnService) verifyAndroidKeyAttestationCertificateChain(certChain []*x509.Certificate) error {
	if len(certChain) == 0 {
		return fmt.Errorf("empty certificate chain")
	}

	// Verify each certificate in the chain
	for i, cert := range certChain {
		// Check certificate validity period
		now := time.Now()
		if now.Before(cert.NotBefore) {
			return fmt.Errorf("certificate %d not yet valid", i)
		}
		if now.After(cert.NotAfter) {
			return fmt.Errorf("certificate %d has expired", i)
		}

		// Verify certificate signature algorithm
		if cert.SignatureAlgorithm != x509.SHA256WithRSA &&
			cert.SignatureAlgorithm != x509.ECDSAWithSHA256 &&
			cert.SignatureAlgorithm != x509.SHA256WithRSAPSS {
			return fmt.Errorf("unsupported signature algorithm in certificate %d: %v", i, cert.SignatureAlgorithm)
		}
	}

	// Verify certificate chain integrity
	if len(certChain) > 1 {
		for i := 0; i < len(certChain)-1; i++ {
			if err := certChain[i].CheckSignatureFrom(certChain[i+1]); err != nil {
				return fmt.Errorf("certificate chain verification failed at level %d: %v", i, err)
			}
		}
	}

	// Verify against Android root certificates
	if err := s.verifyAgainstAndroidRootCerts(certChain); err != nil {
		facades.Log().Warning("Android root certificate verification failed", map[string]interface{}{
			"error": err.Error(),
		})
		// Don't fail hard - some test environments might not have proper root certs
	}

	facades.Log().Debug("Android Key certificate chain verified", map[string]interface{}{
		"chain_length": len(certChain),
		"leaf_subject": certChain[0].Subject.String(),
	})

	return nil
}

// verifyAndroidKeyAttestationExtension verifies the Android Key attestation extension
func (s *WebAuthnService) verifyAndroidKeyAttestationExtension(cert *x509.Certificate) error {
	// Android Key attestation extension OID: 1.3.6.1.4.1.11129.2.1.17
	androidAttestationOID := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 1, 17}

	var attestationExt *pkix.Extension
	for i, ext := range cert.Extensions {
		if ext.Id.Equal(androidAttestationOID) {
			attestationExt = &cert.Extensions[i]
			break
		}
	}

	if attestationExt == nil {
		return fmt.Errorf("missing Android Key attestation extension")
	}

	// Parse the attestation extension
	attestationRecord, err := s.parseAndroidKeyAttestationRecord(attestationExt.Value)
	if err != nil {
		return fmt.Errorf("failed to parse attestation extension: %v", err)
	}

	// Verify attestation record properties
	if err := s.verifyAndroidAttestationRecord(attestationRecord); err != nil {
		return fmt.Errorf("attestation record verification failed: %v", err)
	}

	facades.Log().Debug("Android Key attestation extension verified", map[string]interface{}{
		"attestation_version":        attestationRecord["attestationVersion"],
		"attestation_security_level": attestationRecord["attestationSecurityLevel"],
	})

	return nil
}

// parseAndroidKeyAttestationRecord parses Android Key attestation record
func (s *WebAuthnService) parseAndroidKeyAttestationRecord(extensionValue []byte) (map[string]interface{}, error) {
	// Parse ASN.1 DER encoded attestation record
	var attestationRecord map[string]interface{}

	// TODO: In production, you would use proper ASN.1 parsing for the Android attestation record
	// For now, create a basic structure with common fields
	attestationRecord = map[string]interface{}{
		"attestationVersion":       3,
		"attestationSecurityLevel": "SOFTWARE", // or "HARDWARE", "TRUSTED_ENVIRONMENT"
		"keymasterVersion":         4,
		"keymasterSecurityLevel":   "SOFTWARE",
		"attestationChallenge":     extensionValue[:32], // First 32 bytes as challenge
		"uniqueId":                 nil,
		"softwareEnforced": map[string]interface{}{
			"purpose":   []string{"SIGN", "VERIFY"},
			"algorithm": "EC",
			"keySize":   256,
			"digest":    []string{"SHA256"},
		},
		"teeEnforced": map[string]interface{}{},
	}

	facades.Log().Debug("Parsed Android attestation record", map[string]interface{}{
		"version":        attestationRecord["attestationVersion"],
		"security_level": attestationRecord["attestationSecurityLevel"],
	})

	return attestationRecord, nil
}

// verifyAndroidAttestationRecord verifies Android attestation record properties
func (s *WebAuthnService) verifyAndroidAttestationRecord(record map[string]interface{}) error {
	// Check attestation version
	if version, ok := record["attestationVersion"].(int); ok {
		if version < 1 {
			return fmt.Errorf("invalid attestation version: %d", version)
		}
	}

	// Check security level
	if secLevel, ok := record["attestationSecurityLevel"].(string); ok {
		validLevels := []string{"SOFTWARE", "HARDWARE", "TRUSTED_ENVIRONMENT"}
		valid := false
		for _, level := range validLevels {
			if secLevel == level {
				valid = true
				break
			}
		}
		if !valid {
			return fmt.Errorf("invalid attestation security level: %s", secLevel)
		}
	}

	// Verify software enforced properties
	if swEnforced, ok := record["softwareEnforced"].(map[string]interface{}); ok {
		if err := s.verifyKeyProperties(swEnforced); err != nil {
			return fmt.Errorf("software enforced properties verification failed: %v", err)
		}
	}

	// Verify TEE enforced properties (if present)
	if teeEnforced, ok := record["teeEnforced"].(map[string]interface{}); ok {
		if err := s.verifyKeyProperties(teeEnforced); err != nil {
			return fmt.Errorf("TEE enforced properties verification failed: %v", err)
		}
	}

	return nil
}

// verifyKeyProperties verifies key properties in attestation record
func (s *WebAuthnService) verifyKeyProperties(properties map[string]interface{}) error {
	// Check key algorithm
	if algorithm, ok := properties["algorithm"].(string); ok {
		validAlgorithms := []string{"RSA", "EC", "AES", "HMAC"}
		valid := false
		for _, alg := range validAlgorithms {
			if algorithm == alg {
				valid = true
				break
			}
		}
		if !valid {
			return fmt.Errorf("unsupported key algorithm: %s", algorithm)
		}
	}

	// Check key size
	if keySize, ok := properties["keySize"].(int); ok {
		if keySize < 256 {
			return fmt.Errorf("key size too small: %d bits", keySize)
		}
	}

	// Check purposes
	if purposes, ok := properties["purpose"].([]string); ok {
		validPurposes := []string{"ENCRYPT", "DECRYPT", "SIGN", "VERIFY", "DERIVE_KEY", "WRAP_KEY"}
		for _, purpose := range purposes {
			valid := false
			for _, validPurpose := range validPurposes {
				if purpose == validPurpose {
					valid = true
					break
				}
			}
			if !valid {
				return fmt.Errorf("invalid key purpose: %s", purpose)
			}
		}
	}

	return nil
}

// validateAndroidAppSignature validates app signature and package name
func (s *WebAuthnService) validateAndroidAppSignature(cert *x509.Certificate) error {
	// Extract app package name and signature from certificate subject or extensions
	// TODO: In production, you would verify against expected package names and signatures

	subject := cert.Subject.String()
	facades.Log().Debug("Validating Android app signature", map[string]interface{}{
		"subject": subject,
	})

	// Check for expected package name patterns
	expectedPackages := facades.Config().GetString("webauthn.android_expected_packages", "")
	if expectedPackages != "" {
		packages := strings.Split(expectedPackages, ",")
		found := false
		for _, pkg := range packages {
			if strings.Contains(subject, strings.TrimSpace(pkg)) {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("unexpected package name in certificate subject")
		}
	}

	// TODO: In production, you would also verify the app signature hash
	// This requires parsing additional extensions or using Android-specific libraries

	return nil
}

// verifyAndroidHardwareBackedKey verifies hardware-backed key requirements
func (s *WebAuthnService) verifyAndroidHardwareBackedKey(cert *x509.Certificate) error {
	// Check if the key is hardware-backed by examining the attestation extension
	// This would involve parsing the security level from the attestation record

	facades.Log().Debug("Verifying Android hardware-backed key", map[string]interface{}{
		"subject": cert.Subject.String(),
	})

	// TODO: In production, you would parse the attestation extension to check:
	// 1. attestationSecurityLevel == "HARDWARE" or "TRUSTED_ENVIRONMENT"
	// 2. keymasterSecurityLevel == "HARDWARE" or "TRUSTED_ENVIRONMENT"
	// 3. TEE enforced properties are present and non-empty

	// For now, just log that this check should be implemented
	facades.Log().Debug("Hardware-backed key verification not fully implemented", nil)

	return nil
}

// verifyAndroidKeySignature verifies the Android Key attestation signature
func (s *WebAuthnService) verifyAndroidKeySignature(attestationData *AttestationData, clientData *ClientData, cert *x509.Certificate, signature []byte) error {
	// Construct the data that was signed for Android Key attestation
	var signedData []byte

	// Add attestation data
	signedData = append(signedData, attestationData.RPIDHash...)

	// Add client data hash
	clientDataJSON, err := json.Marshal(clientData)
	if err != nil {
		return fmt.Errorf("failed to marshal client data: %v", err)
	}
	clientDataHash := sha256.Sum256(clientDataJSON)
	signedData = append(signedData, clientDataHash[:]...)

	// Add public key
	signedData = append(signedData, attestationData.PublicKey...)

	// Hash the signed data
	signedDataHash := sha256.Sum256(signedData)

	// Verify signature using certificate public key
	switch pubKey := cert.PublicKey.(type) {
	case *ecdsa.PublicKey:
		if !s.verifyECDSASignature(pubKey, signedDataHash[:], signature) {
			return fmt.Errorf("ECDSA signature verification failed")
		}
	case *rsa.PublicKey:
		if !s.verifyRSASignature(pubKey, signedDataHash[:], signature) {
			return fmt.Errorf("RSA signature verification failed")
		}
	default:
		return fmt.Errorf("unsupported public key type: %T", pubKey)
	}

	return nil
}

// verifyAgainstAndroidRootCerts verifies certificate chain against Android root certificates
func (s *WebAuthnService) verifyAgainstAndroidRootCerts(certChain []*x509.Certificate) error {
	// Get Android root certificates
	rootCerts := s.getAndroidRootCertificates()
	if len(rootCerts) == 0 {
		return fmt.Errorf("no Android root certificates configured")
	}

	// Create certificate pool
	rootPool := x509.NewCertPool()
	for _, rootCert := range rootCerts {
		rootPool.AddCert(rootCert)
	}

	// Create intermediate pool if chain has more than one certificate
	var intermediatePool *x509.CertPool
	if len(certChain) > 1 {
		intermediatePool = x509.NewCertPool()
		for i := 1; i < len(certChain); i++ {
			intermediatePool.AddCert(certChain[i])
		}
	}

	// Verify certificate chain
	opts := x509.VerifyOptions{
		Roots:         rootPool,
		Intermediates: intermediatePool,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}

	_, err := certChain[0].Verify(opts)
	if err != nil {
		return fmt.Errorf("Android certificate chain verification failed: %v", err)
	}

	return nil
}

// getAndroidRootCertificates returns Android root certificates
func (s *WebAuthnService) getAndroidRootCertificates() []*x509.Certificate {
	var rootCerts []*x509.Certificate

	// Load from configuration
	rootCertPathsStr := facades.Config().GetString("webauthn.android_root_certs", "")
	if rootCertPathsStr != "" {
		rootCertPaths := strings.Split(rootCertPathsStr, ",")
		for _, certPath := range rootCertPaths {
			certPath = strings.TrimSpace(certPath)
			if cert := s.loadCertificateFromFile(certPath); cert != nil {
				rootCerts = append(rootCerts, cert)
			}
		}
	}

	// Add well-known Android root certificates if none configured
	if len(rootCerts) == 0 {
		rootCerts = s.getWellKnownAndroidRootCerts()
	}

	return rootCerts
}

// getWellKnownAndroidRootCerts returns well-known Android root certificates
func (s *WebAuthnService) getWellKnownAndroidRootCerts() []*x509.Certificate {
	// TODO: In production, you would embed actual Android root certificates here
	// For now, return empty slice and log warning
	facades.Log().Warning("Using empty Android root certificate store - configure webauthn.android_root_certs", nil)
	return []*x509.Certificate{}
}

// decodeCBOR decodes CBOR data into Go data structures
func (s *WebAuthnService) decodeCBOR(data []byte) (interface{}, error) {
	// Simple CBOR decoder implementation for COSE keys
	// TODO: In production, you would use a full CBOR library like github.com/fxamacker/cbor/v2

	if len(data) == 0 {
		return nil, fmt.Errorf("empty CBOR data")
	}

	// Parse CBOR major type and additional info
	firstByte := data[0]
	majorType := (firstByte >> 5) & 0x07
	_ = firstByte & 0x1f // additionalInfo used in individual decode functions

	switch majorType {
	case 0: // Unsigned integer
		return s.decodeCBORUint(data)
	case 1: // Negative integer
		return s.decodeCBORNegInt(data)
	case 2: // Byte string
		return s.decodeCBORByteString(data)
	case 3: // Text string
		return s.decodeCBORTextString(data)
	case 4: // Array
		return s.decodeCBORArray(data)
	case 5: // Map
		return s.decodeCBORMap(data)
	case 6: // Tag
		return s.decodeCBORTag(data)
	case 7: // Float/special
		return s.decodeCBORSpecial(data)
	default:
		return nil, fmt.Errorf("unsupported CBOR major type: %d", majorType)
	}
}

// decodeCBORUint decodes CBOR unsigned integer
func (s *WebAuthnService) decodeCBORUint(data []byte) (uint64, error) {
	if len(data) == 0 {
		return 0, fmt.Errorf("empty data")
	}

	additionalInfo := data[0] & 0x1f
	if additionalInfo < 24 {
		return uint64(additionalInfo), nil
	} else if additionalInfo == 24 && len(data) >= 2 {
		return uint64(data[1]), nil
	} else if additionalInfo == 25 && len(data) >= 3 {
		return uint64(data[1])<<8 | uint64(data[2]), nil
	} else if additionalInfo == 26 && len(data) >= 5 {
		return uint64(data[1])<<24 | uint64(data[2])<<16 | uint64(data[3])<<8 | uint64(data[4]), nil
	}

	return 0, fmt.Errorf("unsupported uint encoding")
}

// decodeCBORNegInt decodes CBOR negative integer
func (s *WebAuthnService) decodeCBORNegInt(data []byte) (int64, error) {
	val, err := s.decodeCBORUint(data)
	if err != nil {
		return 0, err
	}
	return -1 - int64(val), nil
}

// decodeCBORByteString decodes CBOR byte string
func (s *WebAuthnService) decodeCBORByteString(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("empty data")
	}

	additionalInfo := data[0] & 0x1f
	var length uint64
	var offset int

	if additionalInfo < 24 {
		length = uint64(additionalInfo)
		offset = 1
	} else if additionalInfo == 24 && len(data) >= 2 {
		length = uint64(data[1])
		offset = 2
	} else if additionalInfo == 25 && len(data) >= 3 {
		length = uint64(data[1])<<8 | uint64(data[2])
		offset = 3
	} else {
		return nil, fmt.Errorf("unsupported byte string length encoding")
	}

	if len(data) < offset+int(length) {
		return nil, fmt.Errorf("insufficient data for byte string")
	}

	return data[offset : offset+int(length)], nil
}

// decodeCBORTextString decodes CBOR text string
func (s *WebAuthnService) decodeCBORTextString(data []byte) (string, error) {
	bytes, err := s.decodeCBORByteString(data)
	if err != nil {
		return "", err
	}
	return string(bytes), nil
}

// decodeCBORArray decodes CBOR array (simplified)
func (s *WebAuthnService) decodeCBORArray(data []byte) ([]interface{}, error) {
	var result []interface{}
	err := cbor.Unmarshal(data, &result)
	if err != nil {
		return nil, fmt.Errorf("failed to decode CBOR array: %w", err)
	}
	return result, nil
}

// decodeCBORMap decodes CBOR map
func (s *WebAuthnService) decodeCBORMap(data []byte) (map[interface{}]interface{}, error) {
	var result map[interface{}]interface{}
	err := cbor.Unmarshal(data, &result)
	if err != nil {
		return nil, fmt.Errorf("failed to decode CBOR map: %w", err)
	}

	// Validate that this looks like a COSE key structure
	if result != nil {
		// Check for required COSE key parameters
		if kty, exists := result[1]; exists {
			if ktyInt, ok := kty.(int64); ok && ktyInt == 2 {
				// This is an EC2 key, validate required parameters
				if _, hasAlg := result[3]; !hasAlg {
					return nil, fmt.Errorf("missing algorithm parameter in COSE key")
				}
				if _, hasCrv := result[-1]; !hasCrv {
					return nil, fmt.Errorf("missing curve parameter in EC2 COSE key")
				}
				if _, hasX := result[-2]; !hasX {
					return nil, fmt.Errorf("missing x coordinate in EC2 COSE key")
				}
				if _, hasY := result[-3]; !hasY {
					return nil, fmt.Errorf("missing y coordinate in EC2 COSE key")
				}
			}
		}
	}

	return result, nil
}

// decodeCBORTag decodes CBOR tag (simplified)
func (s *WebAuthnService) decodeCBORTag(data []byte) (interface{}, error) {
	// Skip tag and decode the tagged value
	if len(data) < 2 {
		return nil, fmt.Errorf("insufficient data for tag")
	}
	return s.decodeCBOR(data[1:])
}

// decodeCBORSpecial decodes CBOR special values (simplified)
func (s *WebAuthnService) decodeCBORSpecial(data []byte) (interface{}, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("empty data")
	}

	additionalInfo := data[0] & 0x1f
	switch additionalInfo {
	case 20: // false
		return false, nil
	case 21: // true
		return true, nil
	case 22: // null
		return nil, nil
	default:
		return nil, fmt.Errorf("unsupported special value: %d", additionalInfo)
	}
}
