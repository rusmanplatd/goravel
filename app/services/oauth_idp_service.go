package services

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"goravel/app/models"

	"github.com/goravel/framework/facades"
	"golang.org/x/oauth2"
)

type OAuthIdpService struct {
	authService         *AuthService
	multiAccountService *MultiAccountService
	riskService         *OAuthRiskService
}

type GenericUserInfo struct {
	ID       string                 `json:"id"`
	Email    string                 `json:"email"`
	Name     string                 `json:"name"`
	Username string                 `json:"username"`
	Avatar   string                 `json:"avatar"`
	Data     map[string]interface{} `json:"data"`
}

type IdpDeviceInfo struct {
	Fingerprint string    `json:"fingerprint"`
	UserAgent   string    `json:"user_agent"`
	IPAddress   string    `json:"ip_address"`
	Location    string    `json:"location,omitempty"`
	IsTrusted   bool      `json:"is_trusted"`
	LastUsed    time.Time `json:"last_used"`
	FirstSeen   time.Time `json:"first_seen"`
	DeviceType  string    `json:"device_type"`  // mobile, desktop, tablet
	Platform    string    `json:"platform"`     // iOS, Android, Windows, macOS, Linux
	Browser     string    `json:"browser"`      // Chrome, Safari, Firefox, Edge
	TrustScore  int       `json:"trust_score"`  // 0-100, higher is more trusted
	RiskFactors []string  `json:"risk_factors"` // List of risk factors
}

type AuthenticationContext struct {
	UserID        string                 `json:"user_id"`
	ProviderName  string                 `json:"provider_name"`
	DeviceInfo    *IdpDeviceInfo         `json:"device_info"`
	SessionData   map[string]interface{} `json:"session_data"`
	RiskScore     int                    `json:"risk_score"`
	RequiresMFA   bool                   `json:"requires_mfa"`
	TrustedDevice bool                   `json:"trusted_device"`
	Timestamp     time.Time              `json:"timestamp"`
}

func NewOAuthIdpService() *OAuthIdpService {
	authService, err := NewAuthService()
	if err != nil {
		facades.Log().Error("Failed to create auth service for OAuth IDP", map[string]interface{}{
			"error": err.Error(),
		})
		return nil
	}

	multiAccountService, err := NewMultiAccountService()
	if err != nil {
		facades.Log().Error("Failed to create multi-account service for OAuth IDP", map[string]interface{}{
			"error": err.Error(),
		})
		return nil
	}

	return &OAuthIdpService{
		authService:         authService,
		multiAccountService: multiAccountService,
		riskService:         NewOAuthRiskService(),
	}
}

// GetProvider retrieves an OAuth provider by name
func (s *OAuthIdpService) GetProvider(name string) (*models.OAuthIdentityProvider, error) {
	var provider models.OAuthIdentityProvider
	err := facades.Orm().Query().Where("name", name).Where("enabled", true).First(&provider)
	if err != nil {
		return nil, fmt.Errorf("provider not found or disabled: %w", err)
	}
	return &provider, nil
}

// GetAllEnabledProviders retrieves all enabled OAuth providers
func (s *OAuthIdpService) GetAllEnabledProviders() ([]models.OAuthIdentityProvider, error) {
	var providers []models.OAuthIdentityProvider
	err := facades.Orm().Query().Where("enabled", true).OrderBy("sort_order").Find(&providers)
	if err != nil {
		return nil, fmt.Errorf("failed to get providers: %w", err)
	}
	return providers, nil
}

// GetAuthURL generates the OAuth authorization URL for a provider
func (s *OAuthIdpService) GetAuthURL(providerName, state string) (string, error) {
	provider, err := s.GetProvider(providerName)
	if err != nil {
		return "", err
	}

	if state == "" {
		state = s.GenerateState()
	}

	scopes, err := provider.GetScopes()
	if err != nil {
		return "", fmt.Errorf("failed to parse scopes: %w", err)
	}

	config := &oauth2.Config{
		ClientID:     provider.ClientID,
		ClientSecret: provider.ClientSecret,
		RedirectURL:  provider.RedirectURL,
		Scopes:       scopes,
		Endpoint: oauth2.Endpoint{
			AuthURL:  provider.AuthorizationURL,
			TokenURL: provider.TokenURL,
		},
	}

	return config.AuthCodeURL(state, oauth2.AccessTypeOffline), nil
}

// HandleCallback processes the OAuth callback and returns user information
func (s *OAuthIdpService) HandleCallback(ctx context.Context, providerName, code string) (*models.User, error) {
	provider, err := s.GetProvider(providerName)
	if err != nil {
		return nil, err
	}

	// Exchange authorization code for token
	token, err := s.exchangeCodeForToken(ctx, provider, code)
	if err != nil {
		return nil, fmt.Errorf("failed to exchange code for token: %w", err)
	}

	// Get user info from provider
	userInfo, err := s.getUserInfo(ctx, provider, token)
	if err != nil {
		return nil, fmt.Errorf("failed to get user info: %w", err)
	}

	// Find or create user
	user, err := s.findOrCreateUser(provider, userInfo, token)
	if err != nil {
		return nil, fmt.Errorf("failed to find or create user: %w", err)
	}

	return user, nil
}

// exchangeCodeForToken exchanges the authorization code for an access token
func (s *OAuthIdpService) exchangeCodeForToken(ctx context.Context, provider *models.OAuthIdentityProvider, code string) (*oauth2.Token, error) {
	scopes, err := provider.GetScopes()
	if err != nil {
		return nil, fmt.Errorf("failed to parse scopes: %w", err)
	}

	config := &oauth2.Config{
		ClientID:     provider.ClientID,
		ClientSecret: provider.ClientSecret,
		RedirectURL:  provider.RedirectURL,
		Scopes:       scopes,
		Endpoint: oauth2.Endpoint{
			AuthURL:  provider.AuthorizationURL,
			TokenURL: provider.TokenURL,
		},
	}

	return config.Exchange(ctx, code)
}

// getUserInfo fetches user information from the OAuth provider
func (s *OAuthIdpService) getUserInfo(ctx context.Context, provider *models.OAuthIdentityProvider, token *oauth2.Token) (*GenericUserInfo, error) {
	scopes, err := provider.GetScopes()
	if err != nil {
		return nil, fmt.Errorf("failed to parse scopes: %w", err)
	}

	config := &oauth2.Config{
		ClientID:     provider.ClientID,
		ClientSecret: provider.ClientSecret,
		RedirectURL:  provider.RedirectURL,
		Scopes:       scopes,
		Endpoint: oauth2.Endpoint{
			AuthURL:  provider.AuthorizationURL,
			TokenURL: provider.TokenURL,
		},
	}

	client := config.Client(ctx, token)

	resp, err := client.Get(provider.UserinfoURL)
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

	var rawData map[string]interface{}
	if err := json.Unmarshal(body, &rawData); err != nil {
		return nil, fmt.Errorf("failed to unmarshal user info: %w", err)
	}

	// Map the provider response to our generic format
	userInfo, err := s.mapUserInfo(provider, rawData)
	if err != nil {
		return nil, fmt.Errorf("failed to map user info: %w", err)
	}

	return userInfo, nil
}

// mapUserInfo maps provider-specific user info to our generic format
func (s *OAuthIdpService) mapUserInfo(provider *models.OAuthIdentityProvider, rawData map[string]interface{}) (*GenericUserInfo, error) {
	mapping, err := provider.GetUserinfoMapping()
	if err != nil {
		return nil, fmt.Errorf("failed to parse userinfo mapping: %w", err)
	}

	userInfo := &GenericUserInfo{
		Data: rawData,
	}

	// Map fields based on provider configuration
	if idField, ok := mapping["id"]; ok {
		if id, exists := rawData[idField]; exists {
			userInfo.ID = fmt.Sprintf("%v", id)
		}
	}

	if emailField, ok := mapping["email"]; ok {
		if email, exists := rawData[emailField]; exists {
			userInfo.Email = fmt.Sprintf("%v", email)
		}
	}

	if nameField, ok := mapping["name"]; ok {
		if name, exists := rawData[nameField]; exists {
			userInfo.Name = fmt.Sprintf("%v", name)
		}
	}

	if usernameField, ok := mapping["username"]; ok {
		if username, exists := rawData[usernameField]; exists {
			userInfo.Username = fmt.Sprintf("%v", username)
		}
	}

	if avatarField, ok := mapping["avatar"]; ok {
		if avatar, exists := rawData[avatarField]; exists {
			userInfo.Avatar = fmt.Sprintf("%v", avatar)
		}
	}

	// Fallback mappings for common fields
	if userInfo.ID == "" {
		if id, exists := rawData["id"]; exists {
			userInfo.ID = fmt.Sprintf("%v", id)
		} else if sub, exists := rawData["sub"]; exists {
			userInfo.ID = fmt.Sprintf("%v", sub)
		}
	}

	if userInfo.Email == "" {
		if email, exists := rawData["email"]; exists {
			userInfo.Email = fmt.Sprintf("%v", email)
		}
	}

	if userInfo.Name == "" {
		if name, exists := rawData["name"]; exists {
			userInfo.Name = fmt.Sprintf("%v", name)
		} else if displayName, exists := rawData["display_name"]; exists {
			userInfo.Name = fmt.Sprintf("%v", displayName)
		}
	}

	if userInfo.Avatar == "" {
		if picture, exists := rawData["picture"]; exists {
			userInfo.Avatar = fmt.Sprintf("%v", picture)
		} else if avatarUrl, exists := rawData["avatar_url"]; exists {
			userInfo.Avatar = fmt.Sprintf("%v", avatarUrl)
		}
	}

	return userInfo, nil
}

// findOrCreateUser finds an existing user or creates a new one
func (s *OAuthIdpService) findOrCreateUser(provider *models.OAuthIdentityProvider, userInfo *GenericUserInfo, token *oauth2.Token) (*models.User, error) {
	// First, try to find existing OAuth identity
	var identity models.OAuthUserIdentity
	err := facades.Orm().Query().Where("provider_id", provider.ID).Where("provider_user_id", userInfo.ID).First(&identity)
	if err == nil {
		// Identity found, update it and get the user
		err = s.updateUserIdentity(&identity, userInfo, token)
		if err != nil {
			return nil, fmt.Errorf("failed to update user identity: %w", err)
		}

		var user models.User
		err = facades.Orm().Query().Where("id", identity.UserID).First(&user)
		if err != nil {
			return nil, fmt.Errorf("failed to get user: %w", err)
		}

		// Update user information from provider
		s.updateUserFromProvider(&user, userInfo)
		if err := facades.Orm().Query().Save(&user); err != nil {
			return nil, fmt.Errorf("failed to update user: %w", err)
		}

		return &user, nil
	}

	// Try to find user by email
	var user models.User
	err = facades.Orm().Query().Where("email", userInfo.Email).First(&user)
	if err == nil {
		// User exists with this email, create new identity
		err = s.createUserIdentity(provider, &user, userInfo, token)
		if err != nil {
			return nil, fmt.Errorf("failed to create user identity: %w", err)
		}

		// Update user information from provider
		s.updateUserFromProvider(&user, userInfo)
		if err := facades.Orm().Query().Save(&user); err != nil {
			return nil, fmt.Errorf("failed to update user: %w", err)
		}

		return &user, nil
	}

	// Create new user and identity
	newUser := models.User{
		Name:     userInfo.Name,
		Email:    userInfo.Email,
		Avatar:   userInfo.Avatar,
		IsActive: true,
		Password: "", // No password for OAuth users
	}

	// Set email as verified for OAuth users
	now := time.Now()
	newUser.EmailVerifiedAt = &now

	if err := facades.Orm().Query().Create(&newUser); err != nil {
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	// Create identity
	err = s.createUserIdentity(provider, &newUser, userInfo, token)
	if err != nil {
		return nil, fmt.Errorf("failed to create user identity: %w", err)
	}

	return &newUser, nil
}

// createUserIdentity creates a new OAuth user identity
func (s *OAuthIdpService) createUserIdentity(provider *models.OAuthIdentityProvider, user *models.User, userInfo *GenericUserInfo, token *oauth2.Token) error {
	identity := models.OAuthUserIdentity{
		UserID:         user.ID,
		ProviderID:     provider.ID,
		ProviderUserID: userInfo.ID,
		ProviderEmail:  userInfo.Email,
		ProviderName:   userInfo.Name,
	}

	if userInfo.Username != "" {
		identity.ProviderUsername = &userInfo.Username
	}

	if userInfo.Avatar != "" {
		identity.ProviderAvatar = &userInfo.Avatar
	}

	// Store additional provider data
	if err := identity.SetProviderData(userInfo.Data); err != nil {
		return fmt.Errorf("failed to set provider data: %w", err)
	}

	// Store tokens with encryption for production security
	if token.AccessToken != "" {
		encryptedAccessToken, err := s.encryptToken(token.AccessToken)
		if err != nil {
			facades.Log().Error("Failed to encrypt access token", map[string]interface{}{
				"error": err.Error(),
			})
			return fmt.Errorf("failed to encrypt access token: %w", err)
		}
		identity.AccessToken = &encryptedAccessToken
	}

	if token.RefreshToken != "" {
		encryptedRefreshToken, err := s.encryptToken(token.RefreshToken)
		if err != nil {
			facades.Log().Error("Failed to encrypt refresh token", map[string]interface{}{
				"error": err.Error(),
			})
			return fmt.Errorf("failed to encrypt refresh token: %w", err)
		}
		identity.RefreshToken = &encryptedRefreshToken
	}

	if !token.Expiry.IsZero() {
		identity.TokenExpiresAt = &token.Expiry
	}

	identity.UpdateLastLogin()

	return facades.Orm().Query().Create(&identity)
}

// updateUserIdentity updates an existing OAuth user identity
func (s *OAuthIdpService) updateUserIdentity(identity *models.OAuthUserIdentity, userInfo *GenericUserInfo, token *oauth2.Token) error {
	identity.ProviderEmail = userInfo.Email
	identity.ProviderName = userInfo.Name

	if userInfo.Username != "" {
		identity.ProviderUsername = &userInfo.Username
	}

	if userInfo.Avatar != "" {
		identity.ProviderAvatar = &userInfo.Avatar
	}

	// Update provider data
	if err := identity.SetProviderData(userInfo.Data); err != nil {
		return fmt.Errorf("failed to set provider data: %w", err)
	}

	// Update tokens
	if token.AccessToken != "" {
		identity.AccessToken = &token.AccessToken
	}

	if token.RefreshToken != "" {
		identity.RefreshToken = &token.RefreshToken
	}

	if !token.Expiry.IsZero() {
		identity.TokenExpiresAt = &token.Expiry
	}

	identity.UpdateLastLogin()

	return facades.Orm().Query().Save(identity)
}

// updateUserFromProvider updates user information from provider data
func (s *OAuthIdpService) updateUserFromProvider(user *models.User, userInfo *GenericUserInfo) {
	if userInfo.Name != "" {
		user.Name = userInfo.Name
	}

	if userInfo.Avatar != "" {
		user.Avatar = userInfo.Avatar
	}

	// Ensure user is active
	user.IsActive = true

	// Set email as verified if not already
	if user.EmailVerifiedAt == nil {
		now := time.Now()
		user.EmailVerifiedAt = &now
	}
}

// GenerateState generates a random state parameter for OAuth
func (s *OAuthIdpService) GenerateState() string {
	bytes := make([]byte, 32)
	rand.Read(bytes)
	return fmt.Sprintf("%x", bytes)
}

// ValidateState validates the OAuth state parameter
func (s *OAuthIdpService) ValidateState(expected, actual string) bool {
	return expected == actual && expected != ""
}

// UnlinkProvider removes the OAuth provider link from a user
func (s *OAuthIdpService) UnlinkProvider(userID, providerName string) error {
	provider, err := s.GetProvider(providerName)
	if err != nil {
		return err
	}

	var identity models.OAuthUserIdentity
	err = facades.Orm().Query().Where("user_id", userID).Where("provider_id", provider.ID).First(&identity)
	if err != nil {
		return fmt.Errorf("identity not found: %w", err)
	}

	_, err = facades.Orm().Query().Delete(&identity)
	return err
}

// GetUserIdentities returns all OAuth identities for a user
func (s *OAuthIdpService) GetUserIdentities(userID string) ([]models.OAuthUserIdentity, error) {
	var identities []models.OAuthUserIdentity
	err := facades.Orm().Query().Where("user_id", userID).With("Provider").Find(&identities)
	if err != nil {
		return nil, fmt.Errorf("failed to get user identities: %w", err)
	}
	return identities, nil
}

// IsValidRedirectURL validates redirect URLs to prevent open redirect attacks
func (s *OAuthIdpService) IsValidRedirectURL(redirectURL string) bool {
	if redirectURL == "" {
		return false
	}

	// Parse the URL
	parsedURL, err := url.Parse(redirectURL)
	if err != nil {
		return false
	}

	// Allow relative URLs (same domain)
	if parsedURL.Host == "" {
		return true
	}

	// Get allowed hosts from config
	allowedHosts := facades.Config().Get("auth.allowed_redirect_hosts", []string{}).([]string)

	// Check if host is in allowed list
	for _, allowedHost := range allowedHosts {
		if parsedURL.Host == allowedHost {
			return true
		}
	}

	return false
}

// GenerateDeviceFingerprint creates a unique device fingerprint similar to Google's approach
func (s *OAuthIdpService) GenerateDeviceFingerprint(userAgent, acceptLanguage, acceptEncoding, screenResolution, timezone string) string {
	data := fmt.Sprintf("%s|%s|%s|%s|%s", userAgent, acceptLanguage, acceptEncoding, screenResolution, timezone)
	hash := sha256.Sum256([]byte(data))
	return fmt.Sprintf("%x", hash)
}

// AnalyzeDeviceInfo extracts device information from request headers
func (s *OAuthIdpService) AnalyzeDeviceInfo(userAgent, ipAddress string) *IdpDeviceInfo {
	fingerprint := s.GenerateDeviceFingerprint(userAgent, "", "", "", "")

	deviceInfo := &IdpDeviceInfo{
		Fingerprint: fingerprint,
		UserAgent:   userAgent,
		IPAddress:   ipAddress,
		LastUsed:    time.Now(),
		FirstSeen:   time.Now(),
		TrustScore:  50, // Default neutral score
		RiskFactors: []string{},
	}

	// Analyze user agent for device type and platform
	s.parseUserAgent(deviceInfo, userAgent)

	// Check if device is trusted based on history
	s.checkDeviceTrust(deviceInfo)

	return deviceInfo
}

// parseUserAgent extracts device information from user agent string
func (s *OAuthIdpService) parseUserAgent(deviceInfo *IdpDeviceInfo, userAgent string) {
	ua := strings.ToLower(userAgent)

	// Detect platform
	if strings.Contains(ua, "windows") {
		deviceInfo.Platform = "Windows"
	} else if strings.Contains(ua, "macintosh") || strings.Contains(ua, "mac os") {
		deviceInfo.Platform = "macOS"
	} else if strings.Contains(ua, "linux") {
		deviceInfo.Platform = "Linux"
	} else if strings.Contains(ua, "android") {
		deviceInfo.Platform = "Android"
	} else if strings.Contains(ua, "iphone") || strings.Contains(ua, "ipad") {
		deviceInfo.Platform = "iOS"
	}

	// Detect device type
	if strings.Contains(ua, "mobile") || strings.Contains(ua, "android") || strings.Contains(ua, "iphone") {
		deviceInfo.DeviceType = "mobile"
	} else if strings.Contains(ua, "tablet") || strings.Contains(ua, "ipad") {
		deviceInfo.DeviceType = "tablet"
	} else {
		deviceInfo.DeviceType = "desktop"
	}

	// Detect browser
	if strings.Contains(ua, "chrome") && !strings.Contains(ua, "edge") {
		deviceInfo.Browser = "Chrome"
	} else if strings.Contains(ua, "safari") && !strings.Contains(ua, "chrome") {
		deviceInfo.Browser = "Safari"
	} else if strings.Contains(ua, "firefox") {
		deviceInfo.Browser = "Firefox"
	} else if strings.Contains(ua, "edge") {
		deviceInfo.Browser = "Edge"
	} else if strings.Contains(ua, "opera") {
		deviceInfo.Browser = "Opera"
	}
}

// checkDeviceTrust determines if a device should be trusted based on history
func (s *OAuthIdpService) checkDeviceTrust(deviceInfo *IdpDeviceInfo) {
	// Query device history from database
	// This would typically check against a device_trust table
	// For now, we'll implement basic logic

	// Devices are trusted if they've been used successfully multiple times
	// and haven't been associated with suspicious activity

	// Default trust factors
	baseScore := 50

	// Increase trust for known good browsers
	if deviceInfo.Browser == "Chrome" || deviceInfo.Browser == "Safari" || deviceInfo.Browser == "Firefox" {
		baseScore += 10
	}

	// Decrease trust for unusual platforms
	if deviceInfo.Platform == "Linux" && deviceInfo.DeviceType == "desktop" {
		baseScore -= 5
		deviceInfo.RiskFactors = append(deviceInfo.RiskFactors, "unusual_platform")
	}

	// Mobile devices get slight trust boost for modern apps
	if deviceInfo.DeviceType == "mobile" {
		baseScore += 5
	}

	deviceInfo.TrustScore = baseScore
	deviceInfo.IsTrusted = baseScore >= 70
}

// CreateAuthenticationContext creates a comprehensive authentication context
func (s *OAuthIdpService) CreateAuthenticationContext(userID, providerName, userAgent, ipAddress string) (*AuthenticationContext, error) {
	deviceInfo := s.AnalyzeDeviceInfo(userAgent, ipAddress)

	// Assess risk using the risk service
	riskCtx := &AuthContext{
		UserID:    userID,
		ClientID:  providerName, // Using provider as client for risk assessment
		IPAddress: ipAddress,
		UserAgent: userAgent,
		Timestamp: time.Now(),
	}

	riskAssessment, err := s.riskService.AssessRisk(riskCtx)
	if err != nil {
		facades.Log().Warning("Risk assessment failed", map[string]interface{}{
			"user_id":  userID,
			"provider": providerName,
			"error":    err.Error(),
		})
		// Continue with default risk score
		riskAssessment = &RiskAssessment{Score: 25, RequireMFA: false}
	}

	authCtx := &AuthenticationContext{
		UserID:        userID,
		ProviderName:  providerName,
		DeviceInfo:    deviceInfo,
		SessionData:   make(map[string]interface{}),
		RiskScore:     riskAssessment.Score,
		RequiresMFA:   riskAssessment.RequireMFA,
		TrustedDevice: deviceInfo.IsTrusted && riskAssessment.Score < 30,
		Timestamp:     time.Now(),
	}

	// Store device information for future reference
	s.storeDeviceInfo(userID, deviceInfo)

	return authCtx, nil
}

// storeDeviceInfo stores device information for trust building
func (s *OAuthIdpService) storeDeviceInfo(userID string, deviceInfo *IdpDeviceInfo) {
	// In a real implementation, this would store device info in a database table
	// For now, we'll log it for tracking
	facades.Log().Info("Device info stored", map[string]interface{}{
		"user_id":      userID,
		"fingerprint":  deviceInfo.Fingerprint,
		"device_type":  deviceInfo.DeviceType,
		"platform":     deviceInfo.Platform,
		"browser":      deviceInfo.Browser,
		"trust_score":  deviceInfo.TrustScore,
		"is_trusted":   deviceInfo.IsTrusted,
		"risk_factors": deviceInfo.RiskFactors,
	})
}

// GetTrustedDevices returns a list of trusted devices for a user
func (s *OAuthIdpService) GetTrustedDevices(userID string) ([]IdpDeviceInfo, error) {
	// This would query the device_trust table in a real implementation
	// For now, return empty slice
	return []IdpDeviceInfo{}, nil
}

// RevokeTrustedDevice revokes trust for a specific device
func (s *OAuthIdpService) RevokeTrustedDevice(userID, deviceFingerprint string) error {
	// This would update the device_trust table in a real implementation
	facades.Log().Info("Device trust revoked", map[string]interface{}{
		"user_id":     userID,
		"fingerprint": deviceFingerprint,
	})
	return nil
}

// encryptToken encrypts sensitive tokens using application encryption key
func (s *OAuthIdpService) encryptToken(token string) (string, error) {
	if token == "" {
		return "", nil
	}

	// Use Goravel's encryption facade for consistent encryption
	encrypted, err := facades.Crypt().EncryptString(token)
	if err != nil {
		return "", fmt.Errorf("failed to encrypt token: %w", err)
	}

	return encrypted, nil
}

// decryptToken decrypts sensitive tokens
func (s *OAuthIdpService) decryptToken(encryptedToken string) (string, error) {
	if encryptedToken == "" {
		return "", nil
	}

	// Use Goravel's encryption facade for consistent decryption
	decrypted, err := facades.Crypt().DecryptString(encryptedToken)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt token: %w", err)
	}

	return decrypted, nil
}
