package services

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"goravel/app/models"

	"github.com/goravel/framework/facades"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

type GoogleOAuthService struct {
	config      *oauth2.Config
	authService *AuthService
}

type GoogleUserInfo struct {
	ID            string `json:"id"`
	Email         string `json:"email"`
	VerifiedEmail bool   `json:"verified_email"`
	Name          string `json:"name"`
	GivenName     string `json:"given_name"`
	FamilyName    string `json:"family_name"`
	Picture       string `json:"picture"`
	Locale        string `json:"locale"`
	HD            string `json:"hd,omitempty"` // Hosted domain for G Suite accounts
}

func NewGoogleOAuthService() *GoogleOAuthService {
	// Get Google OAuth configuration
	clientID := facades.Config().GetString("auth.google_oauth.client_id")
	clientSecret := facades.Config().GetString("auth.google_oauth.client_secret")
	redirectURL := facades.Config().GetString("auth.google_oauth.redirect_url")
	scopes := facades.Config().Get("auth.google_oauth.scopes").([]string)

	config := &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		Scopes:       scopes,
		Endpoint:     google.Endpoint,
	}

	authService, err := NewAuthService()
	if err != nil {
		facades.Log().Error("Failed to create auth service for Google OAuth", map[string]interface{}{
			"error": err.Error(),
		})
		return nil
	}

	return &GoogleOAuthService{
		config:      config,
		authService: authService,
	}
}

// IsEnabled checks if Google OAuth is enabled
func (s *GoogleOAuthService) IsEnabled() bool {
	return facades.Config().GetBool("auth.google_oauth.enabled", false)
}

// GetAuthURL generates the Google OAuth authorization URL
func (s *GoogleOAuthService) GetAuthURL(state string) string {
	if state == "" {
		state = s.GenerateState()
	}

	// Add additional security parameters
	return s.config.AuthCodeURL(state,
		oauth2.AccessTypeOffline,
		oauth2.SetAuthURLParam("prompt", "consent"), // Force consent screen
		oauth2.SetAuthURLParam("include_granted_scopes", "true"),
	)
}

// HandleCallback processes the OAuth callback and returns user information
func (s *GoogleOAuthService) HandleCallback(ctx context.Context, code string) (*models.User, error) {
	// Exchange authorization code for token
	token, err := s.config.Exchange(ctx, code)
	if err != nil {
		facades.Log().Error("Google OAuth token exchange failed", map[string]interface{}{
			"error": err.Error(),
		})
		return nil, fmt.Errorf("failed to exchange code for token: %w", err)
	}

	// Get user info from Google
	userInfo, err := s.getUserInfo(ctx, token)
	if err != nil {
		facades.Log().Error("Google OAuth user info retrieval failed", map[string]interface{}{
			"error": err.Error(),
		})
		return nil, fmt.Errorf("failed to get user info: %w", err)
	}

	// Find or create user
	user, err := s.findOrCreateUser(userInfo)
	if err != nil {
		return nil, fmt.Errorf("failed to find or create user: %w", err)
	}

	facades.Log().Info("Google OAuth authentication successful", map[string]interface{}{
		"user_id": user.ID,
		"email":   user.Email,
	})

	return user, nil
}

// getUserInfo fetches user information from Google API
func (s *GoogleOAuthService) getUserInfo(ctx context.Context, token *oauth2.Token) (*GoogleUserInfo, error) {
	client := s.config.Client(ctx, token)

	resp, err := client.Get("https://www.googleapis.com/oauth2/v2/userinfo")
	if err != nil {
		return nil, fmt.Errorf("failed to get user info: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to get user info, status: %d, body: %s", resp.StatusCode, string(body))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	var userInfo GoogleUserInfo
	if err := json.Unmarshal(body, &userInfo); err != nil {
		return nil, fmt.Errorf("failed to unmarshal user info: %w", err)
	}

	return &userInfo, nil
}

// findOrCreateUser finds an existing user or creates a new one
func (s *GoogleOAuthService) findOrCreateUser(userInfo *GoogleUserInfo) (*models.User, error) {
	// First, try to find user by Google ID
	var user models.User
	err := facades.Orm().Query().Where("google_id", userInfo.ID).First(&user)
	if err == nil {
		// User found, update their information
		user.Name = userInfo.Name
		user.Email = userInfo.Email
		user.Avatar = userInfo.Picture
		user.GoogleID = &userInfo.ID
		user.IsActive = true
		now := time.Now()
		user.EmailVerifiedAt = &now

		if err := facades.Orm().Query().Save(&user); err != nil {
			return nil, fmt.Errorf("failed to update user: %w", err)
		}
		return &user, nil
	}

	// Try to find user by email
	err = facades.Orm().Query().Where("email", userInfo.Email).First(&user)
	if err == nil {
		// User exists with this email, link Google account
		user.GoogleID = &userInfo.ID
		user.Avatar = userInfo.Picture
		user.IsActive = true
		if user.EmailVerifiedAt == nil {
			now := time.Now()
			user.EmailVerifiedAt = &now
		}

		if err := facades.Orm().Query().Save(&user); err != nil {
			return nil, fmt.Errorf("failed to link Google account: %w", err)
		}
		return &user, nil
	}

	// Create new user
	now := time.Now()
	newUser := models.User{
		Name:            userInfo.Name,
		Email:           userInfo.Email,
		Avatar:          userInfo.Picture,
		GoogleID:        &userInfo.ID,
		IsActive:        true,
		EmailVerifiedAt: &now,
		Password:        "", // No password for OAuth users
	}

	if err := facades.Orm().Query().Create(&newUser); err != nil {
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	return &newUser, nil
}

// GenerateState generates a cryptographically secure random state parameter
func (s *GoogleOAuthService) GenerateState() string {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		// Fallback to time-based state if crypto/rand fails
		hash := sha256.Sum256([]byte(fmt.Sprintf("%d_%d", time.Now().UnixNano(), time.Now().Unix())))
		return fmt.Sprintf("%x", hash[:16])
	}
	return fmt.Sprintf("%x", bytes)
}

// ValidateState validates the OAuth state parameter with timing attack protection
func (s *GoogleOAuthService) ValidateState(expected, actual string) bool {
	if expected == "" || actual == "" {
		return false
	}

	// Use constant-time comparison to prevent timing attacks
	expectedBytes := []byte(expected)
	actualBytes := []byte(actual)

	if len(expectedBytes) != len(actualBytes) {
		return false
	}

	result := byte(0)
	for i := 0; i < len(expectedBytes); i++ {
		result |= expectedBytes[i] ^ actualBytes[i]
	}

	return result == 0
}

// GetUserByGoogleID finds a user by their Google ID
func (s *GoogleOAuthService) GetUserByGoogleID(googleID string) (*models.User, error) {
	var user models.User
	err := facades.Orm().Query().Where("google_id", googleID).First(&user)
	if err != nil {
		return nil, fmt.Errorf("user not found: %w", err)
	}
	return &user, nil
}

// UnlinkGoogleAccount removes the Google ID from a user account
func (s *GoogleOAuthService) UnlinkGoogleAccount(userID string) error {
	var user models.User
	err := facades.Orm().Query().Where("id", userID).First(&user)
	if err != nil {
		return fmt.Errorf("user not found: %w", err)
	}

	user.GoogleID = nil
	if err := facades.Orm().Query().Save(&user); err != nil {
		return fmt.Errorf("failed to unlink Google account: %w", err)
	}

	facades.Log().Info("Google account unlinked", map[string]interface{}{
		"user_id": userID,
		"email":   user.Email,
	})

	return nil
}

// RefreshUserInfo refreshes user information from Google
func (s *GoogleOAuthService) RefreshUserInfo(ctx context.Context, user *models.User, token *oauth2.Token) error {
	if user.GoogleID == nil {
		return fmt.Errorf("user is not linked to Google account")
	}

	userInfo, err := s.getUserInfo(ctx, token)
	if err != nil {
		return fmt.Errorf("failed to get updated user info: %w", err)
	}

	// Verify that the Google ID matches
	if userInfo.ID != *user.GoogleID {
		facades.Log().Warning("Google ID mismatch detected", map[string]interface{}{
			"user_id":            user.ID,
			"expected_google_id": *user.GoogleID,
			"actual_google_id":   userInfo.ID,
		})
		return fmt.Errorf("Google ID mismatch: security violation detected")
	}

	// Update user information
	user.Name = userInfo.Name
	user.Email = userInfo.Email
	user.Avatar = userInfo.Picture

	if err := facades.Orm().Query().Save(user); err != nil {
		return fmt.Errorf("failed to update user info: %w", err)
	}

	facades.Log().Info("Google user info refreshed", map[string]interface{}{
		"user_id": user.ID,
		"email":   user.Email,
	})

	return nil
}

// ValidateTokenWithGoogle validates a token directly with Google's tokeninfo endpoint
func (s *GoogleOAuthService) ValidateTokenWithGoogle(ctx context.Context, accessToken string) (*GoogleTokenInfo, error) {
	client := &http.Client{Timeout: 10 * time.Second}

	resp, err := client.Get(fmt.Sprintf("https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s", accessToken))
	if err != nil {
		return nil, fmt.Errorf("failed to validate token: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("token validation failed with status: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read validation response: %w", err)
	}

	var tokenInfo GoogleTokenInfo
	if err := json.Unmarshal(body, &tokenInfo); err != nil {
		return nil, fmt.Errorf("failed to unmarshal token info: %w", err)
	}

	// Validate that the token is for our application
	if tokenInfo.Audience != s.config.ClientID {
		return nil, fmt.Errorf("token audience mismatch")
	}

	return &tokenInfo, nil
}

// GoogleTokenInfo represents Google's token validation response
type GoogleTokenInfo struct {
	Audience      string `json:"aud"`
	UserID        string `json:"user_id"`
	Scope         string `json:"scope"`
	ExpiresIn     int    `json:"expires_in"`
	Email         string `json:"email,omitempty"`
	VerifiedEmail bool   `json:"verified_email,omitempty"`
}

// RevokeToken revokes a Google OAuth token
func (s *GoogleOAuthService) RevokeToken(ctx context.Context, token string, userID string) error {
	client := &http.Client{Timeout: 10 * time.Second}

	resp, err := client.Post(
		fmt.Sprintf("https://oauth2.googleapis.com/revoke?token=%s", token),
		"application/x-www-form-urlencoded",
		nil,
	)
	if err != nil {
		return fmt.Errorf("failed to revoke token: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("token revocation failed with status: %d", resp.StatusCode)
	}

	facades.Log().Info("Google OAuth token revoked", map[string]interface{}{
		"user_id": userID,
	})

	return nil
}

// IsGSuiteAccount checks if the user is from a G Suite domain
func (s *GoogleOAuthService) IsGSuiteAccount(userInfo *GoogleUserInfo) bool {
	return userInfo.HD != ""
}

// GetGSuiteDomain returns the G Suite domain if applicable
func (s *GoogleOAuthService) GetGSuiteDomain(userInfo *GoogleUserInfo) string {
	return userInfo.HD
}

// GenerateDeviceFingerprint generates a device fingerprint from request information
func (s *GoogleOAuthService) GenerateDeviceFingerprint(userAgent, acceptLanguage, acceptEncoding string, screenResolution string) string {
	data := fmt.Sprintf("%s|%s|%s|%s", userAgent, acceptLanguage, acceptEncoding, screenResolution)
	hash := sha256.Sum256([]byte(data))
	return fmt.Sprintf("%x", hash)
}
