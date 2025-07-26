package services

import (
	"fmt"
	"strings"
	"time"

	"goravel/app/models"

	"github.com/goravel/framework/facades"
)

type OAuthConsentService struct{}

type ConsentRequest struct {
	UserID      string   `json:"user_id"`
	ClientID    string   `json:"client_id"`
	Scopes      []string `json:"scopes"`
	RedirectURI string   `json:"redirect_uri"`
	State       string   `json:"state"`
	Nonce       string   `json:"nonce,omitempty"`
}

type ConsentResponse struct {
	Granted       bool     `json:"granted"`
	GrantedScopes []string `json:"granted_scopes"`
	ConsentID     string   `json:"consent_id"`
}

type ScopeInfo struct {
	Scope       string `json:"scope"`
	Title       string `json:"title"`
	Description string `json:"description"`
	Sensitive   bool   `json:"sensitive"`
	Category    string `json:"category"`
	Icon        string `json:"icon,omitempty"`
}

type ConsentScreen struct {
	Client        *models.OAuthClient `json:"client"`
	User          *models.User        `json:"user"`
	Scopes        []ScopeInfo         `json:"scopes"`
	RedirectURI   string              `json:"redirect_uri"`
	State         string              `json:"state"`
	Nonce         string              `json:"nonce,omitempty"`
	ConsentID     string              `json:"consent_id"`
	PreviousGrant bool                `json:"previous_grant"`
}

type UserConsent struct {
	ID          string    `json:"id"`
	UserID      string    `json:"user_id"`
	ClientID    string    `json:"client_id"`
	Scopes      []string  `json:"scopes"`
	GrantedAt   time.Time `json:"granted_at"`
	LastUsedAt  time.Time `json:"last_used_at"`
	ExpiresAt   time.Time `json:"expires_at"`
	Revoked     bool      `json:"revoked"`
	IPAddress   string    `json:"ip_address"`
	UserAgent   string    `json:"user_agent"`
	ConsentType string    `json:"consent_type"` // "explicit", "implicit", "remembered"
}

func NewOAuthConsentService() *OAuthConsentService {
	return &OAuthConsentService{}
}

// PrepareConsentScreen prepares the consent screen data for display
func (s *OAuthConsentService) PrepareConsentScreen(userID, clientID string, scopes []string, redirectURI, state, nonce string) (*ConsentScreen, error) {
	// Get client information
	var client models.OAuthClient
	if err := facades.Orm().Query().Where("id", clientID).First(&client); err != nil {
		return nil, fmt.Errorf("client not found")
	}

	// Get user information
	var user models.User
	if err := facades.Orm().Query().Where("id", userID).First(&user); err != nil {
		return nil, fmt.Errorf("user not found")
	}

	// Check for existing consent
	existingConsent := s.GetUserConsent(userID, clientID)
	previousGrant := existingConsent != nil && !existingConsent.Revoked

	// Prepare scope information with Google-like descriptions
	scopeInfos := s.GetScopeInfos(scopes)

	// Generate consent ID for tracking
	consentID := s.generateConsentID()

	// Store consent request temporarily
	s.storeConsentRequest(consentID, &ConsentRequest{
		UserID:      userID,
		ClientID:    clientID,
		Scopes:      scopes,
		RedirectURI: redirectURI,
		State:       state,
		Nonce:       nonce,
	})

	return &ConsentScreen{
		Client:        &client,
		User:          &user,
		Scopes:        scopeInfos,
		RedirectURI:   redirectURI,
		State:         state,
		Nonce:         nonce,
		ConsentID:     consentID,
		PreviousGrant: previousGrant,
	}, nil
}

// GetScopeInfos returns detailed information about requested scopes
func (s *OAuthConsentService) GetScopeInfos(scopes []string) []ScopeInfo {
	var scopeInfos []ScopeInfo

	// Get scope descriptions from config
	descriptions := facades.Config().Get("oauth.scope_descriptions").(map[string]map[string]string)

	for _, scope := range scopes {
		info := ScopeInfo{
			Scope:    scope,
			Category: s.getScopeCategory(scope),
		}

		// Get description from config or use default
		if desc, exists := descriptions[scope]; exists {
			info.Title = desc["title"]
			info.Description = desc["description"]
			info.Sensitive = desc["sensitive"] == "true"
		} else {
			info.Title = s.getDefaultScopeTitle(scope)
			info.Description = s.getDefaultScopeDescription(scope)
			info.Sensitive = s.isScopeSensitive(scope)
		}

		info.Icon = s.getScopeIcon(scope)
		scopeInfos = append(scopeInfos, info)
	}

	return scopeInfos
}

// ProcessConsentResponse processes the user's consent response
func (s *OAuthConsentService) ProcessConsentResponse(consentID string, granted bool, grantedScopes []string, ipAddress, userAgent string) (*ConsentResponse, error) {
	// Retrieve the consent request
	consentRequest, err := s.getConsentRequest(consentID)
	if err != nil {
		return nil, fmt.Errorf("invalid consent ID")
	}

	if !granted {
		// User denied consent
		s.logConsentEvent(consentRequest.UserID, consentRequest.ClientID, "denied", grantedScopes, ipAddress, userAgent)
		return &ConsentResponse{
			Granted:   false,
			ConsentID: consentID,
		}, nil
	}

	// Validate granted scopes are subset of requested scopes
	if !s.areValidScopes(grantedScopes, consentRequest.Scopes) {
		return nil, fmt.Errorf("granted scopes exceed requested scopes")
	}

	// Store or update user consent
	consent := &UserConsent{
		ID:          s.generateConsentID(),
		UserID:      consentRequest.UserID,
		ClientID:    consentRequest.ClientID,
		Scopes:      grantedScopes,
		GrantedAt:   time.Now(),
		LastUsedAt:  time.Now(),
		ExpiresAt:   time.Now().Add(365 * 24 * time.Hour), // 1 year
		Revoked:     false,
		IPAddress:   ipAddress,
		UserAgent:   userAgent,
		ConsentType: "explicit",
	}

	if err := s.storeUserConsent(consent); err != nil {
		return nil, fmt.Errorf("failed to store consent: %w", err)
	}

	// Log consent event
	s.logConsentEvent(consentRequest.UserID, consentRequest.ClientID, "granted", grantedScopes, ipAddress, userAgent)

	// Clean up temporary consent request
	s.cleanupConsentRequest(consentID)

	return &ConsentResponse{
		Granted:       true,
		GrantedScopes: grantedScopes,
		ConsentID:     consentID,
	}, nil
}

// GetUserConsent retrieves existing user consent for a client
func (s *OAuthConsentService) GetUserConsent(userID, clientID string) *UserConsent {
	key := fmt.Sprintf("user_consent_%s_%s", userID, clientID)

	var consent UserConsent
	if err := facades.Cache().Get(key, &consent); err == nil && !consent.Revoked && consent.ExpiresAt.After(time.Now()) {
		return &consent
	}

	return nil
}

// RevokeUserConsent revokes a user's consent for a specific client
func (s *OAuthConsentService) RevokeUserConsent(userID, clientID string) error {
	consent := s.GetUserConsent(userID, clientID)
	if consent == nil {
		return fmt.Errorf("consent not found")
	}

	consent.Revoked = true

	if err := s.storeUserConsent(consent); err != nil {
		return fmt.Errorf("failed to revoke consent: %w", err)
	}

	// Log revocation event
	s.logConsentEvent(userID, clientID, "revoked", consent.Scopes, "", "")

	return nil
}

// GetUserConsents retrieves all consents for a user
func (s *OAuthConsentService) GetUserConsents(userID string) ([]*UserConsent, error) {
	// This would typically query a database
	// For now, we'll return from cache/storage
	var consents []*UserConsent

	// In a real implementation, you'd query the database for all user consents
	// For demonstration, we'll return an empty slice
	return consents, nil
}

// Helper methods

func (s *OAuthConsentService) getScopeCategory(scope string) string {
	if strings.HasPrefix(scope, "user") {
		return "profile"
	} else if strings.HasPrefix(scope, "calendar") {
		return "calendar"
	} else if strings.HasPrefix(scope, "chat") {
		return "messaging"
	} else if strings.HasPrefix(scope, "org") {
		return "organization"
	} else if strings.HasPrefix(scope, "files") {
		return "storage"
	} else if scope == "openid" || scope == "profile" || scope == "email" {
		return "identity"
	}
	return "general"
}

func (s *OAuthConsentService) getDefaultScopeTitle(scope string) string {
	switch scope {
	case "openid":
		return "Sign you in"
	case "profile":
		return "View your profile"
	case "email":
		return "View your email address"
	default:
		return fmt.Sprintf("Access %s", scope)
	}
}

func (s *OAuthConsentService) getDefaultScopeDescription(scope string) string {
	switch scope {
	case "openid":
		return "Allow this app to sign you in and access your basic profile information"
	case "profile":
		return "View your name, profile picture, and other basic profile information"
	case "email":
		return "View your email address"
	default:
		return fmt.Sprintf("Access your %s data", scope)
	}
}

func (s *OAuthConsentService) isScopeSensitive(scope string) bool {
	sensitiveScopes := []string{
		"user:write", "user:delete", "calendar:write", "chat:write",
		"org:admin", "admin", "files:write", "files:delete",
	}

	for _, sensitive := range sensitiveScopes {
		if scope == sensitive || strings.HasPrefix(scope, sensitive) {
			return true
		}
	}
	return false
}

func (s *OAuthConsentService) getScopeIcon(scope string) string {
	icons := map[string]string{
		"openid":   "🔐",
		"profile":  "👤",
		"email":    "📧",
		"calendar": "📅",
		"chat":     "💬",
		"files":    "📁",
		"org":      "🏢",
	}

	for prefix, icon := range icons {
		if scope == prefix || strings.HasPrefix(scope, prefix) {
			return icon
		}
	}
	return "🔧"
}

func (s *OAuthConsentService) generateConsentID() string {
	return fmt.Sprintf("consent_%d_%s", time.Now().UnixNano(), s.generateRandomString(8))
}

func (s *OAuthConsentService) generateRandomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[time.Now().UnixNano()%int64(len(charset))]
	}
	return string(b)
}

func (s *OAuthConsentService) storeConsentRequest(consentID string, request *ConsentRequest) {
	key := fmt.Sprintf("consent_request_%s", consentID)
	facades.Cache().Put(key, request, 30*time.Minute) // 30 minutes expiry
}

func (s *OAuthConsentService) getConsentRequest(consentID string) (*ConsentRequest, error) {
	key := fmt.Sprintf("consent_request_%s", consentID)

	var request ConsentRequest
	if err := facades.Cache().Get(key, &request); err != nil {
		return nil, fmt.Errorf("consent request not found or expired")
	}

	return &request, nil
}

func (s *OAuthConsentService) cleanupConsentRequest(consentID string) {
	key := fmt.Sprintf("consent_request_%s", consentID)
	facades.Cache().Forget(key)
}

func (s *OAuthConsentService) storeUserConsent(consent *UserConsent) error {
	key := fmt.Sprintf("user_consent_%s_%s", consent.UserID, consent.ClientID)
	return facades.Cache().Put(key, consent, time.Until(consent.ExpiresAt))
}

func (s *OAuthConsentService) areValidScopes(grantedScopes, requestedScopes []string) bool {
	for _, granted := range grantedScopes {
		found := false
		for _, requested := range requestedScopes {
			if granted == requested {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func (s *OAuthConsentService) logConsentEvent(userID, clientID, action string, scopes []string, ipAddress, userAgent string) {
	facades.Log().Info("OAuth consent event", map[string]interface{}{
		"user_id":    userID,
		"client_id":  clientID,
		"action":     action,
		"scopes":     scopes,
		"ip_address": ipAddress,
		"user_agent": userAgent,
		"timestamp":  time.Now(),
	})
}
