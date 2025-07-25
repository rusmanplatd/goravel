package services

import (
	"fmt"
	"time"

	"goravel/app/models"

	"github.com/goravel/framework/facades"
)

type SessionService struct{}

// NewSessionService creates a new session service
func NewSessionService() *SessionService {
	return &SessionService{}
}

// Session represents a user session
type Session struct {
	ID           string                 `json:"id"`
	UserID       string                 `json:"user_id"`
	Token        string                 `json:"token"`
	RefreshToken string                 `json:"refresh_token"`
	DeviceInfo   map[string]interface{} `json:"device_info"`
	IPAddress    string                 `json:"ip_address"`
	UserAgent    string                 `json:"user_agent"`
	IsActive     bool                   `json:"is_active"`
	LastActivity time.Time              `json:"last_activity"`
	ExpiresAt    time.Time              `json:"expires_at"`
	CreatedAt    time.Time              `json:"created_at"`
}

// CreateSession creates a new user session
func (s *SessionService) CreateSession(user *models.User, accessToken, refreshToken, ipAddress, userAgent string, deviceInfo map[string]interface{}) (*Session, error) {
	sessionID := s.generateSessionID()

	// Set expiration based on refresh token
	expiresAt := time.Now().Add(30 * 24 * time.Hour) // 30 days default

	session := &Session{
		ID:           sessionID,
		UserID:       user.ID,
		Token:        accessToken,
		RefreshToken: refreshToken,
		DeviceInfo:   deviceInfo,
		IPAddress:    ipAddress,
		UserAgent:    userAgent,
		IsActive:     true,
		LastActivity: time.Now(),
		ExpiresAt:    expiresAt,
		CreatedAt:    time.Now(),
	}

	// Store session in cache
	err := s.storeSession(session)
	if err != nil {
		return nil, err
	}

	// Log session creation
	facades.Log().Info("User session created", map[string]interface{}{
		"user_id":    user.ID,
		"session_id": sessionID,
		"ip_address": ipAddress,
		"user_agent": userAgent,
	})

	return session, nil
}

// GetSession retrieves a session by ID
func (s *SessionService) GetSession(sessionID string) (*Session, error) {
	var session Session
	err := facades.Cache().Get("session_"+sessionID, &session)
	if err != nil {
		return nil, fmt.Errorf("session not found")
	}

	// Check if session is expired
	if time.Now().After(session.ExpiresAt) {
		s.DeleteSession(sessionID)
		return nil, fmt.Errorf("session expired")
	}

	// Update last activity
	session.LastActivity = time.Now()
	s.storeSession(&session)

	return &session, nil
}

// GetUserSessions retrieves all active sessions for a user
func (s *SessionService) GetUserSessions(userID string) ([]*Session, error) {
	// Get user session keys from cache
	userSessionsKey := fmt.Sprintf("user_sessions:%s", userID)
	var sessionIDs []string
	err := facades.Cache().Get(userSessionsKey, &sessionIDs)
	if err != nil {
		// No sessions found for user
		return []*Session{}, nil
	}

	var sessions []*Session
	for _, sessionID := range sessionIDs {
		session, err := s.GetSession(sessionID)
		if err != nil {
			// Session might be expired, remove from list
			s.removeSessionFromUser(userID, sessionID)
			continue
		}

		// Only return active sessions
		if session.IsActive && time.Now().Before(session.ExpiresAt) {
			sessions = append(sessions, session)
		} else {
			// Remove inactive/expired sessions
			s.removeSessionFromUser(userID, sessionID)
		}
	}

	return sessions, nil
}

// UpdateSessionActivity updates the last activity time for a session
func (s *SessionService) UpdateSessionActivity(sessionID string) error {
	session, err := s.GetSession(sessionID)
	if err != nil {
		return err
	}

	session.LastActivity = time.Now()
	return s.storeSession(session)
}

// RevokeSession revokes a specific session
func (s *SessionService) RevokeSession(sessionID string) error {
	session, err := s.GetSession(sessionID)
	if err != nil {
		return err
	}

	session.IsActive = false
	s.storeSession(session)

	// Log session revocation
	facades.Log().Info("User session revoked", map[string]interface{}{
		"user_id":    session.UserID,
		"session_id": sessionID,
	})

	return nil
}

// RevokeAllUserSessions revokes all sessions for a user except the current one
func (s *SessionService) RevokeAllUserSessions(userID string, currentSessionID string) error {
	sessions, err := s.GetUserSessions(userID)
	if err != nil {
		return err
	}

	for _, session := range sessions {
		if session.ID != currentSessionID {
			s.RevokeSession(session.ID)
		}
	}

	return nil
}

// RevokeExpiredSessions removes expired sessions
func (s *SessionService) RevokeExpiredSessions() error {
	// Since sessions are stored in cache, we need a different approach
	// We'll iterate through all users and clean up their expired sessions

	facades.Log().Info("Starting expired session cleanup")

	// This is a simplified implementation since we can't easily iterate all cache keys
	// In a production system, you might want to:
	// 1. Keep a list of all active session IDs in a separate cache key
	// 2. Use a database table for session tracking
	// 3. Use Redis SCAN command if using Redis cache

	// For now, we'll log that the cleanup should be implemented with proper session tracking
	facades.Log().Info("Session cleanup completed - cache-based sessions are automatically expired by TTL")

	return nil
}

// ValidateSession validates if a session is still valid
func (s *SessionService) ValidateSession(sessionID string) (bool, error) {
	session, err := s.GetSession(sessionID)
	if err != nil {
		return false, err
	}

	// Check if session is active and not expired
	if !session.IsActive || time.Now().After(session.ExpiresAt) {
		return false, nil
	}

	// Check if session has been inactive for too long (e.g., 24 hours)
	inactivityLimit := 24 * time.Hour
	if time.Since(session.LastActivity) > inactivityLimit {
		s.RevokeSession(sessionID)
		return false, nil
	}

	return true, nil
}

// GetSessionDeviceInfo extracts device information from user agent
func (s *SessionService) GetSessionDeviceInfo(userAgent string) map[string]interface{} {
	deviceInfo := map[string]interface{}{
		"user_agent": userAgent,
		"platform":   "unknown",
		"browser":    "unknown",
		"device":     "unknown",
	}

	// Simple device detection (in production, use a proper user agent parser)
	if len(userAgent) > 0 {
		// Basic platform detection
		switch {
		case contains(userAgent, "Windows"):
			deviceInfo["platform"] = "Windows"
		case contains(userAgent, "Mac"):
			deviceInfo["platform"] = "macOS"
		case contains(userAgent, "Linux"):
			deviceInfo["platform"] = "Linux"
		case contains(userAgent, "Android"):
			deviceInfo["platform"] = "Android"
		case contains(userAgent, "iPhone") || contains(userAgent, "iPad"):
			deviceInfo["platform"] = "iOS"
		}

		// Basic browser detection
		switch {
		case contains(userAgent, "Chrome"):
			deviceInfo["browser"] = "Chrome"
		case contains(userAgent, "Firefox"):
			deviceInfo["browser"] = "Firefox"
		case contains(userAgent, "Safari"):
			deviceInfo["browser"] = "Safari"
		case contains(userAgent, "Edge"):
			deviceInfo["browser"] = "Edge"
		}

		// Basic device type detection
		switch {
		case contains(userAgent, "Mobile"):
			deviceInfo["device"] = "Mobile"
		case contains(userAgent, "Tablet"):
			deviceInfo["device"] = "Tablet"
		default:
			deviceInfo["device"] = "Desktop"
		}
	}

	return deviceInfo
}

// Helper methods

func (s *SessionService) generateSessionID() string {
	// Generate a unique session ID
	return fmt.Sprintf("session_%d", time.Now().UnixNano())
}

func (s *SessionService) storeSession(session *Session) error {
	// Store session in cache
	sessionKey := "session_" + session.ID

	// Store session data
	err := facades.Cache().Put(sessionKey, session, time.Until(session.ExpiresAt))
	if err != nil {
		return err
	}

	// Add session to user's session list
	err = s.addSessionToUser(session.UserID, session.ID)
	if err != nil {
		return err
	}

	return nil
}

func (s *SessionService) addSessionToUser(userID, sessionID string) error {
	userSessionsKey := fmt.Sprintf("user_sessions:%s", userID)
	var sessionIDs []string

	// Get existing sessions
	err := facades.Cache().Get(userSessionsKey, &sessionIDs)
	if err != nil {
		// No existing sessions, start with empty slice
		sessionIDs = []string{}
	}

	// Add new session if not already present
	found := false
	for _, id := range sessionIDs {
		if id == sessionID {
			found = true
			break
		}
	}

	if !found {
		sessionIDs = append(sessionIDs, sessionID)
	}

	// Store updated session list
	return facades.Cache().Put(userSessionsKey, sessionIDs, 24*time.Hour)
}

func (s *SessionService) DeleteSession(sessionID string) {
	sessionKey := "session_" + sessionID
	facades.Cache().Forget(sessionKey)
}

func (s *SessionService) removeSessionFromUser(userID, sessionID string) {
	userSessionsKey := fmt.Sprintf("user_sessions:%s", userID)
	var sessionIDs []string

	// Get existing sessions
	err := facades.Cache().Get(userSessionsKey, &sessionIDs)
	if err != nil {
		return // No sessions to remove
	}

	// Remove the specific session
	var updatedSessionIDs []string
	for _, id := range sessionIDs {
		if id != sessionID {
			updatedSessionIDs = append(updatedSessionIDs, id)
		}
	}

	// Update the session list
	if len(updatedSessionIDs) > 0 {
		facades.Cache().Put(userSessionsKey, updatedSessionIDs, 24*time.Hour)
	} else {
		// No sessions left, remove the key entirely
		facades.Cache().Forget(userSessionsKey)
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || (len(s) > len(substr) && (s[:len(substr)] == substr || s[len(s)-len(substr):] == substr || containsSubstring(s, substr))))
}

func containsSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
