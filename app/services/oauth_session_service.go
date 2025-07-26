package services

import (
	"fmt"
	"strings"
	"time"

	"github.com/goravel/framework/facades"
)

type OAuthSessionService struct{}

type SessionInfo struct {
	ID          string                 `json:"id"`
	UserID      string                 `json:"user_id"`
	ClientID    string                 `json:"client_id"`
	Scopes      []string               `json:"scopes"`
	CreatedAt   time.Time              `json:"created_at"`
	LastUsedAt  time.Time              `json:"last_used_at"`
	ExpiresAt   time.Time              `json:"expires_at"`
	IPAddress   string                 `json:"ip_address"`
	UserAgent   string                 `json:"user_agent"`
	DeviceInfo  map[string]interface{} `json:"device_info"`
	Status      string                 `json:"status"` // "active", "expired", "revoked"
	TokenHashes []string               `json:"token_hashes"`
}

type SessionSummary struct {
	TotalSessions   int            `json:"total_sessions"`
	ActiveSessions  int            `json:"active_sessions"`
	ExpiredSessions int            `json:"expired_sessions"`
	RevokedSessions int            `json:"revoked_sessions"`
	Sessions        []SessionInfo  `json:"sessions"`
	DeviceSummary   map[string]int `json:"device_summary"`
	LocationSummary map[string]int `json:"location_summary"`
}

type LogoutRequest struct {
	SessionID   string `json:"session_id,omitempty"`
	AllSessions bool   `json:"all_sessions"`
	ClientID    string `json:"client_id,omitempty"`
	TokenHint   string `json:"token_hint,omitempty"`
}

func NewOAuthSessionService() *OAuthSessionService {
	return &OAuthSessionService{}
}

// CreateSession creates a new OAuth session
func (s *OAuthSessionService) CreateSession(userID, clientID string, scopes []string, ipAddress, userAgent string) (*SessionInfo, error) {
	sessionID := s.generateSessionID()

	session := &SessionInfo{
		ID:          sessionID,
		UserID:      userID,
		ClientID:    clientID,
		Scopes:      scopes,
		CreatedAt:   time.Now(),
		LastUsedAt:  time.Now(),
		ExpiresAt:   time.Now().Add(time.Duration(facades.Config().GetInt("oauth.session_ttl_hours", 24)) * time.Hour),
		IPAddress:   ipAddress,
		UserAgent:   userAgent,
		DeviceInfo:  s.parseDeviceInfo(userAgent),
		Status:      "active",
		TokenHashes: []string{},
	}

	if err := s.storeSession(session); err != nil {
		return nil, fmt.Errorf("failed to store session: %w", err)
	}

	// Add to user's active sessions list
	s.addToUserSessions(userID, sessionID)

	facades.Log().Info("OAuth session created", map[string]interface{}{
		"session_id": sessionID,
		"user_id":    userID,
		"client_id":  clientID,
		"ip_address": ipAddress,
	})

	return session, nil
}

// GetSession retrieves a session by ID
func (s *OAuthSessionService) GetSession(sessionID string) (*SessionInfo, error) {
	key := fmt.Sprintf("oauth_session_%s", sessionID)

	var session SessionInfo
	if err := facades.Cache().Get(key, &session); err != nil {
		return nil, fmt.Errorf("session not found")
	}

	// Check if session is expired
	if session.ExpiresAt.Before(time.Now()) && session.Status == "active" {
		session.Status = "expired"
		s.storeSession(&session)
	}

	return &session, nil
}

// UpdateSessionActivity updates the last used time for a session
func (s *OAuthSessionService) UpdateSessionActivity(sessionID string) error {
	session, err := s.GetSession(sessionID)
	if err != nil {
		return err
	}

	if session.Status != "active" {
		return fmt.Errorf("session is not active")
	}

	session.LastUsedAt = time.Now()
	return s.storeSession(session)
}

// AddTokenToSession associates a token with a session
func (s *OAuthSessionService) AddTokenToSession(sessionID, tokenHash string) error {
	session, err := s.GetSession(sessionID)
	if err != nil {
		return err
	}

	// Add token hash to session
	session.TokenHashes = append(session.TokenHashes, tokenHash)

	return s.storeSession(session)
}

// GetUserSessions retrieves all sessions for a user
func (s *OAuthSessionService) GetUserSessions(userID string) (*SessionSummary, error) {
	sessionIDs, err := s.getUserSessionIDs(userID)
	if err != nil {
		return nil, err
	}

	summary := &SessionSummary{
		Sessions:        []SessionInfo{},
		DeviceSummary:   make(map[string]int),
		LocationSummary: make(map[string]int),
	}

	for _, sessionID := range sessionIDs {
		session, err := s.GetSession(sessionID)
		if err != nil {
			continue // Skip invalid sessions
		}

		summary.Sessions = append(summary.Sessions, *session)
		summary.TotalSessions++

		switch session.Status {
		case "active":
			summary.ActiveSessions++
		case "expired":
			summary.ExpiredSessions++
		case "revoked":
			summary.RevokedSessions++
		}

		// Device summary
		if deviceType, ok := session.DeviceInfo["type"].(string); ok {
			summary.DeviceSummary[deviceType]++
		}

		// Location summary (simplified)
		location := s.getLocationFromIP(session.IPAddress)
		summary.LocationSummary[location]++
	}

	return summary, nil
}

// RevokeSession revokes a specific session
func (s *OAuthSessionService) RevokeSession(sessionID string, reason string) error {
	session, err := s.GetSession(sessionID)
	if err != nil {
		return err
	}

	session.Status = "revoked"

	if err := s.storeSession(session); err != nil {
		return err
	}

	// Revoke all associated tokens
	for _, tokenHash := range session.TokenHashes {
		s.revokeTokenByHash(tokenHash)
	}

	facades.Log().Info("OAuth session revoked", map[string]interface{}{
		"session_id": sessionID,
		"user_id":    session.UserID,
		"reason":     reason,
	})

	return nil
}

// RevokeAllUserSessions revokes all sessions for a user (global logout)
func (s *OAuthSessionService) RevokeAllUserSessions(userID string, reason string) error {
	sessionIDs, err := s.getUserSessionIDs(userID)
	if err != nil {
		return err
	}

	revokedCount := 0
	for _, sessionID := range sessionIDs {
		if err := s.RevokeSession(sessionID, reason); err != nil {
			facades.Log().Warning("Failed to revoke session", map[string]interface{}{
				"session_id": sessionID,
				"user_id":    userID,
				"error":      err.Error(),
			})
		} else {
			revokedCount++
		}
	}

	facades.Log().Info("Global logout completed", map[string]interface{}{
		"user_id":       userID,
		"revoked_count": revokedCount,
		"reason":        reason,
	})

	return nil
}

// RevokeClientSessions revokes all sessions for a specific client
func (s *OAuthSessionService) RevokeClientSessions(userID, clientID string, reason string) error {
	sessionIDs, err := s.getUserSessionIDs(userID)
	if err != nil {
		return err
	}

	revokedCount := 0
	for _, sessionID := range sessionIDs {
		session, err := s.GetSession(sessionID)
		if err != nil {
			continue
		}

		if session.ClientID == clientID {
			if err := s.RevokeSession(sessionID, reason); err != nil {
				facades.Log().Warning("Failed to revoke client session", map[string]interface{}{
					"session_id": sessionID,
					"client_id":  clientID,
					"error":      err.Error(),
				})
			} else {
				revokedCount++
			}
		}
	}

	facades.Log().Info("Client sessions revoked", map[string]interface{}{
		"user_id":       userID,
		"client_id":     clientID,
		"revoked_count": revokedCount,
		"reason":        reason,
	})

	return nil
}

// ProcessLogout handles logout requests with Google-like functionality
func (s *OAuthSessionService) ProcessLogout(userID string, request *LogoutRequest) error {
	if request.AllSessions {
		// Global logout - revoke all sessions
		return s.RevokeAllUserSessions(userID, "user_logout")
	}

	if request.SessionID != "" {
		// Single session logout
		return s.RevokeSession(request.SessionID, "user_logout")
	}

	if request.ClientID != "" {
		// Client-specific logout
		return s.RevokeClientSessions(userID, request.ClientID, "client_logout")
	}

	if request.TokenHint != "" {
		// Token-based logout
		return s.revokeSessionByToken(request.TokenHint, "token_logout")
	}

	return fmt.Errorf("invalid logout request")
}

// CleanupExpiredSessions removes expired sessions
func (s *OAuthSessionService) CleanupExpiredSessions() error {
	// Get all user IDs (this would typically be from a database query)
	userIDs := s.getAllUserIDs()

	cleanedCount := 0
	for _, userID := range userIDs {
		sessionIDs, err := s.getUserSessionIDs(userID)
		if err != nil {
			continue
		}

		var validSessionIDs []string
		for _, sessionID := range sessionIDs {
			session, err := s.GetSession(sessionID)
			if err != nil {
				continue
			}

			if session.ExpiresAt.Before(time.Now()) {
				// Remove expired session
				s.removeSession(sessionID)
				cleanedCount++
			} else {
				validSessionIDs = append(validSessionIDs, sessionID)
			}
		}

		// Update user's session list
		s.setUserSessionIDs(userID, validSessionIDs)
	}

	facades.Log().Info("Session cleanup completed", map[string]interface{}{
		"cleaned_count": cleanedCount,
	})

	return nil
}

// GetSessionMetrics returns session analytics
func (s *OAuthSessionService) GetSessionMetrics() (map[string]interface{}, error) {
	userIDs := s.getAllUserIDs()

	metrics := map[string]interface{}{
		"total_users":      len(userIDs),
		"active_sessions":  0,
		"expired_sessions": 0,
		"revoked_sessions": 0,
		"device_breakdown": make(map[string]int),
		"client_breakdown": make(map[string]int),
	}

	for _, userID := range userIDs {
		sessionIDs, err := s.getUserSessionIDs(userID)
		if err != nil {
			continue
		}

		for _, sessionID := range sessionIDs {
			session, err := s.GetSession(sessionID)
			if err != nil {
				continue
			}

			switch session.Status {
			case "active":
				metrics["active_sessions"] = metrics["active_sessions"].(int) + 1
			case "expired":
				metrics["expired_sessions"] = metrics["expired_sessions"].(int) + 1
			case "revoked":
				metrics["revoked_sessions"] = metrics["revoked_sessions"].(int) + 1
			}

			// Device breakdown
			if deviceType, ok := session.DeviceInfo["type"].(string); ok {
				deviceBreakdown := metrics["device_breakdown"].(map[string]int)
				deviceBreakdown[deviceType]++
			}

			// Client breakdown
			clientBreakdown := metrics["client_breakdown"].(map[string]int)
			clientBreakdown[session.ClientID]++
		}
	}

	return metrics, nil
}

// Helper methods

func (s *OAuthSessionService) generateSessionID() string {
	return fmt.Sprintf("sess_%d_%s", time.Now().UnixNano(), s.generateRandomString(16))
}

func (s *OAuthSessionService) generateRandomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[time.Now().UnixNano()%int64(len(charset))]
	}
	return string(b)
}

func (s *OAuthSessionService) storeSession(session *SessionInfo) error {
	key := fmt.Sprintf("oauth_session_%s", session.ID)
	return facades.Cache().Put(key, session, time.Until(session.ExpiresAt))
}

func (s *OAuthSessionService) removeSession(sessionID string) {
	key := fmt.Sprintf("oauth_session_%s", sessionID)
	facades.Cache().Forget(key)
}

func (s *OAuthSessionService) addToUserSessions(userID, sessionID string) {
	sessionIDs, _ := s.getUserSessionIDs(userID)
	sessionIDs = append(sessionIDs, sessionID)
	s.setUserSessionIDs(userID, sessionIDs)
}

func (s *OAuthSessionService) getUserSessionIDs(userID string) ([]string, error) {
	key := fmt.Sprintf("user_sessions_%s", userID)

	var sessionIDs []string
	if err := facades.Cache().Get(key, &sessionIDs); err != nil {
		return []string{}, nil // Return empty slice if not found
	}

	return sessionIDs, nil
}

func (s *OAuthSessionService) setUserSessionIDs(userID string, sessionIDs []string) {
	key := fmt.Sprintf("user_sessions_%s", userID)
	facades.Cache().Put(key, sessionIDs, 30*24*time.Hour) // 30 days
}

func (s *OAuthSessionService) parseDeviceInfo(userAgent string) map[string]interface{} {
	deviceInfo := map[string]interface{}{
		"user_agent": userAgent,
		"type":       "unknown",
		"browser":    "unknown",
		"os":         "unknown",
	}

	// Simple user agent parsing (in production, use a proper library)
	userAgentLower := strings.ToLower(userAgent)

	// Device type detection
	if strings.Contains(userAgentLower, "mobile") || strings.Contains(userAgentLower, "android") || strings.Contains(userAgentLower, "iphone") {
		deviceInfo["type"] = "mobile"
	} else if strings.Contains(userAgentLower, "tablet") || strings.Contains(userAgentLower, "ipad") {
		deviceInfo["type"] = "tablet"
	} else {
		deviceInfo["type"] = "desktop"
	}

	// Browser detection
	if strings.Contains(userAgentLower, "chrome") {
		deviceInfo["browser"] = "chrome"
	} else if strings.Contains(userAgentLower, "firefox") {
		deviceInfo["browser"] = "firefox"
	} else if strings.Contains(userAgentLower, "safari") {
		deviceInfo["browser"] = "safari"
	} else if strings.Contains(userAgentLower, "edge") {
		deviceInfo["browser"] = "edge"
	}

	// OS detection
	if strings.Contains(userAgentLower, "windows") {
		deviceInfo["os"] = "windows"
	} else if strings.Contains(userAgentLower, "mac") {
		deviceInfo["os"] = "macos"
	} else if strings.Contains(userAgentLower, "linux") {
		deviceInfo["os"] = "linux"
	} else if strings.Contains(userAgentLower, "android") {
		deviceInfo["os"] = "android"
	} else if strings.Contains(userAgentLower, "ios") {
		deviceInfo["os"] = "ios"
	}

	return deviceInfo
}

func (s *OAuthSessionService) getLocationFromIP(ipAddress string) string {
	// Placeholder for GeoIP lookup
	// In production, integrate with a GeoIP service
	if ipAddress == "127.0.0.1" || ipAddress == "::1" {
		return "localhost"
	}
	return "unknown"
}

func (s *OAuthSessionService) revokeTokenByHash(tokenHash string) {
	// Implementation would revoke the token by its hash
	// This would typically involve blacklisting the token
	facades.Log().Info("Token revoked by hash", map[string]interface{}{
		"token_hash": tokenHash,
	})
}

func (s *OAuthSessionService) revokeSessionByToken(tokenHint string, reason string) error {
	// Implementation would find the session by token and revoke it
	// This is a simplified placeholder
	facades.Log().Info("Session revoked by token hint", map[string]interface{}{
		"token_hint": tokenHint,
		"reason":     reason,
	})
	return nil
}

func (s *OAuthSessionService) getAllUserIDs() []string {
	// Placeholder - in production, this would query the database
	// for all users with active sessions
	return []string{}
}
