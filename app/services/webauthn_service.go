package services

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"goravel/app/helpers"
	"goravel/app/models"

	"github.com/goravel/framework/facades"
)

type WebAuthnService struct {
	// In a real implementation, you would use a WebAuthn library
	// For now, we'll implement a more robust simplified version
}

func NewWebAuthnService() *WebAuthnService {
	return &WebAuthnService{}
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
	// Generate a random challenge
	challenge := s.generateChallenge()

	// Get existing credentials to exclude
	existingCredentials, err := s.GetUserCredentials(user)
	if err != nil {
		return nil, err
	}

	excludeCredentials := make([]map[string]interface{}, 0)
	for _, cred := range existingCredentials {
		excludeCredentials = append(excludeCredentials, map[string]interface{}{
			"id":   cred.CredentialID,
			"type": "public-key",
		})
	}

	// Create registration data
	registrationData := &WebAuthnRegistrationData{
		Challenge:          challenge,
		RPName:             facades.Config().GetString("app.name", "Goravel"),
		RPID:               s.getRPID(),
		UserID:             user.ID,
		UserName:           user.Email,
		UserDisplayName:    user.Name,
		ExcludeCredentials: excludeCredentials,
		AuthenticatorSelection: map[string]interface{}{
			"authenticator_attachment": "platform",
			"user_verification":        "preferred",
			"require_resident_key":     false,
		},
		Attestation: "direct",
		Extensions: map[string]interface{}{
			"appid": s.getRPID(),
		},
	}

	// Store challenge in session
	sessionID := s.generateSessionID()
	s.storeSession(sessionID, map[string]interface{}{
		"challenge":  challenge,
		"user_id":    user.ID,
		"created_at": time.Now(),
		"expires_at": time.Now().Add(5 * time.Minute),
	})

	return registrationData, nil
}

// FinishRegistration completes the WebAuthn registration process
func (s *WebAuthnService) FinishRegistration(user *models.User, response map[string]interface{}) (*models.WebauthnCredential, error) {
	// Get session data
	sessionID := response["session_id"].(string)
	sessionData := s.getSession(sessionID)
	if sessionData == nil {
		return nil, fmt.Errorf("invalid session")
	}

	// Validate challenge
	expectedChallenge := sessionData["challenge"].(string)
	receivedChallenge := response["challenge"].(string)
	if expectedChallenge != receivedChallenge {
		return nil, fmt.Errorf("challenge mismatch")
	}

	// In a real implementation, you would verify the attestation
	// For now, we'll create a credential record
	credential := &models.WebauthnCredential{
		UserID:          user.ID,
		Name:            "Security Key",
		CredentialID:    s.generateCredentialID(),
		PublicKey:       s.extractPublicKey(response),
		AttestationType: "direct",
		Transports:      s.extractTransports(response),
		Flags:           "user_present,user_verified",
		BackupEligible:  true,
		BackedUp:        false,
		SignCount:       0,
	}

	credential.ID = s.generateULID()

	err := facades.Orm().Query().Create(credential)
	if err != nil {
		return nil, err
	}

	// Enable WebAuthn for user if not already enabled
	if !user.WebauthnEnabled {
		now := time.Now()
		user.WebauthnEnabled = true
		user.WebauthnEnabledAt = &now
		facades.Orm().Query().Save(user)
	}

	// Clean up session
	s.cleanupSession(sessionID)

	return credential, nil
}

// BeginLogin starts the WebAuthn authentication process
func (s *WebAuthnService) BeginLogin(user *models.User) (*WebAuthnAuthenticationData, error) {
	// Get user credentials
	credentials, err := s.GetUserCredentials(user)
	if err != nil {
		return nil, err
	}

	if len(credentials) == 0 {
		return nil, fmt.Errorf("no WebAuthn credentials found")
	}

	// Generate challenge
	challenge := s.generateChallenge()

	// Create allow credentials list
	allowCredentials := make([]map[string]interface{}, 0)
	for _, cred := range credentials {
		allowCredentials = append(allowCredentials, map[string]interface{}{
			"id":   cred.CredentialID,
			"type": "public-key",
		})
	}

	// Create authentication data
	authData := &WebAuthnAuthenticationData{
		Challenge:        challenge,
		RPID:             s.getRPID(),
		AllowCredentials: allowCredentials,
		UserVerification: "preferred",
		Extensions: map[string]interface{}{
			"appid": s.getRPID(),
		},
	}

	// Store session
	sessionID := s.generateSessionID()
	s.storeSession(sessionID, map[string]interface{}{
		"challenge":  challenge,
		"user_id":    user.ID,
		"created_at": time.Now(),
		"expires_at": time.Now().Add(5 * time.Minute),
	})

	return authData, nil
}

// FinishLogin completes the WebAuthn authentication process
func (s *WebAuthnService) FinishLogin(user *models.User, response map[string]interface{}) error {
	// Get session data
	sessionID := response["session_id"].(string)
	sessionData := s.getSession(sessionID)
	if sessionData == nil {
		return fmt.Errorf("invalid session")
	}

	// Validate challenge
	expectedChallenge := sessionData["challenge"].(string)
	receivedChallenge := response["challenge"].(string)
	if expectedChallenge != receivedChallenge {
		return fmt.Errorf("challenge mismatch")
	}

	// In a real implementation, you would verify the assertion
	// For now, we'll just update the credential's last used time
	credentialID := response["credential_id"].(string)

	var credential models.WebauthnCredential
	err := facades.Orm().Query().Where("user_id", user.ID).Where("credential_id", credentialID).First(&credential)
	if err != nil {
		return fmt.Errorf("credential not found")
	}

	// Update last used timestamp
	now := time.Now()
	credential.LastUsedAt = &now
	credential.SignCount++
	facades.Orm().Query().Save(&credential)

	// Clean up session
	s.cleanupSession(sessionID)

	return nil
}

// GetUserCredentials retrieves WebAuthn credentials for a user
func (s *WebAuthnService) GetUserCredentials(user *models.User) ([]models.WebauthnCredential, error) {
	var credentials []models.WebauthnCredential
	err := facades.Orm().Query().Where("user_id", user.ID).Find(&credentials)
	return credentials, err
}

// DeleteCredential deletes a WebAuthn credential
func (s *WebAuthnService) DeleteCredential(user *models.User, credentialID string) error {
	var credential models.WebauthnCredential
	err := facades.Orm().Query().Where("user_id", user.ID).Where("credential_id", credentialID).First(&credential)
	if err != nil {
		return fmt.Errorf("credential not found")
	}

	_, err = facades.Orm().Query().Delete(&credential)
	return err
}

// Helper methods

func (s *WebAuthnService) generateChallenge() string {
	bytes := make([]byte, 32)
	rand.Read(bytes)
	return base64.StdEncoding.EncodeToString(bytes)
}

func (s *WebAuthnService) generateCredentialID() string {
	bytes := make([]byte, 16)
	rand.Read(bytes)
	return base64.StdEncoding.EncodeToString(bytes)
}

func (s *WebAuthnService) generateULID() string {
	// Use the helper function from the project
	return helpers.GenerateULID()
}

func (s *WebAuthnService) generateSessionID() string {
	return fmt.Sprintf("webauthn_session_%d", time.Now().UnixNano())
}

func (s *WebAuthnService) getRPID() string {
	// In production, this should be your domain
	return facades.Config().GetString("app.url", "localhost")
}

func (s *WebAuthnService) extractPublicKey(response map[string]interface{}) string {
	// In a real implementation, you would extract the actual public key
	// For now, we'll return a placeholder
	return "simulated_public_key_data"
}

func (s *WebAuthnService) extractTransports(response map[string]interface{}) string {
	// In a real implementation, you would extract the actual transports
	// For now, we'll return a default list
	transports := []string{"usb", "nfc", "ble"}
	transportsJSON, _ := json.Marshal(transports)
	return string(transportsJSON)
}

func (s *WebAuthnService) storeSession(sessionID string, data map[string]interface{}) error {
	sessionKey := "webauthn_session_" + sessionID
	return facades.Cache().Put(sessionKey, data, 5*time.Minute)
}

func (s *WebAuthnService) getSession(sessionID string) map[string]interface{} {
	sessionKey := "webauthn_session_" + sessionID
	var data map[string]interface{}
	err := facades.Cache().Get(sessionKey, &data)
	if err != nil {
		return nil
	}
	return data
}

func (s *WebAuthnService) cleanupSession(sessionID string) {
	sessionKey := "webauthn_session_" + sessionID
	facades.Cache().Forget(sessionKey)
}
