package services

import (
	"context"
	"crypto/rand"
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
	userService *UserService
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

	return &GoogleOAuthService{
		config:      config,
		authService: NewAuthService(),
		userService: NewUserService(),
	}
}

func NewUserService() *UserService {
	return &UserService{}
}

type UserService struct{}

// IsEnabled checks if Google OAuth is enabled
func (s *GoogleOAuthService) IsEnabled() bool {
	return facades.Config().GetBool("auth.google_oauth.enabled", false)
}

// GetAuthURL generates the Google OAuth authorization URL
func (s *GoogleOAuthService) GetAuthURL(state string) string {
	if state == "" {
		state = s.GenerateState()
	}
	return s.config.AuthCodeURL(state, oauth2.AccessTypeOffline)
}

// HandleCallback processes the OAuth callback and returns user information
func (s *GoogleOAuthService) HandleCallback(ctx context.Context, code string) (*models.User, error) {
	// Exchange authorization code for token
	token, err := s.config.Exchange(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("failed to exchange code for token: %w", err)
	}

	// Get user info from Google
	userInfo, err := s.getUserInfo(ctx, token)
	if err != nil {
		return nil, fmt.Errorf("failed to get user info: %w", err)
	}

	// Find or create user
	user, err := s.findOrCreateUser(userInfo)
	if err != nil {
		return nil, fmt.Errorf("failed to find or create user: %w", err)
	}

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
		return nil, fmt.Errorf("failed to get user info, status: %d", resp.StatusCode)
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

// GenerateState generates a random state parameter for OAuth
func (s *GoogleOAuthService) GenerateState() string {
	bytes := make([]byte, 32)
	rand.Read(bytes)
	return fmt.Sprintf("%x", bytes)
}

// ValidateState validates the OAuth state parameter
func (s *GoogleOAuthService) ValidateState(expected, actual string) bool {
	return expected == actual && expected != ""
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

	// Update user information
	user.Name = userInfo.Name
	user.Email = userInfo.Email
	user.Avatar = userInfo.Picture

	if err := facades.Orm().Query().Save(user); err != nil {
		return fmt.Errorf("failed to update user info: %w", err)
	}

	return nil
}
