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

// CleanupExpiredSessions removes expired sessions from the cache
func (s *SessionService) CleanupExpiredSessions() error {
	startTime := time.Now()

	facades.Log().Info("Starting expired session cleanup")

	// Get all active session IDs from the tracking set
	activeSessionIDs, err := s.getActiveSessionIDs()
	if err != nil {
		facades.Log().Error("Failed to get active session IDs", map[string]interface{}{
			"error": err.Error(),
		})
		return err
	}

	cleanedCount := 0
	errorCount := 0
	validCount := 0

	for _, sessionID := range activeSessionIDs {
		// Check if session is expired
		isValid, err := s.ValidateSession(sessionID)
		if err != nil {
			facades.Log().Warning("Error validating session during cleanup", map[string]interface{}{
				"session_id": sessionID,
				"error":      err.Error(),
			})
			errorCount++
			continue
		}

		if !isValid {
			// Remove expired session
			if err := s.removeExpiredSession(sessionID); err != nil {
				facades.Log().Error("Failed to remove expired session", map[string]interface{}{
					"session_id": sessionID,
					"error":      err.Error(),
				})
				errorCount++
			} else {
				cleanedCount++
			}
		} else {
			validCount++
		}
	}

	duration := time.Since(startTime)

	// Record metrics
	s.recordCleanupMetrics(len(activeSessionIDs), cleanedCount, validCount, errorCount, duration)

	facades.Log().Info("Session cleanup completed", map[string]interface{}{
		"total_sessions":   len(activeSessionIDs),
		"cleaned_sessions": cleanedCount,
		"valid_sessions":   validCount,
		"errors":           errorCount,
		"duration_ms":      duration.Milliseconds(),
	})

	return nil
}

// recordCleanupMetrics records session cleanup metrics
func (s *SessionService) recordCleanupMetrics(total, cleaned, valid, errors int, duration time.Duration) {
	// Store metrics in cache for monitoring dashboard
	metrics := map[string]interface{}{
		"timestamp":        time.Now().Unix(),
		"total_sessions":   total,
		"cleaned_sessions": cleaned,
		"valid_sessions":   valid,
		"error_count":      errors,
		"duration_ms":      duration.Milliseconds(),
		"cleanup_rate":     float64(cleaned) / float64(total) * 100,
	}

	// Store latest metrics
	facades.Cache().Put("session_cleanup_metrics:latest", metrics, 24*time.Hour)

	// Store historical metrics (keep last 24 hours)
	historicalKey := fmt.Sprintf("session_cleanup_metrics:%d", time.Now().Unix())
	facades.Cache().Put(historicalKey, metrics, 24*time.Hour)

	// Update running statistics
	s.updateSessionStatistics(total, cleaned, valid, errors)
}

// updateSessionStatistics updates running session statistics
func (s *SessionService) updateSessionStatistics(total, cleaned, valid, errors int) {
	statsKey := "session_statistics"

	var stats map[string]interface{}
	if err := facades.Cache().Get(statsKey, &stats); err != nil {
		stats = map[string]interface{}{
			"total_cleanups":   0,
			"total_cleaned":    0,
			"total_errors":     0,
			"average_duration": 0.0,
			"last_cleanup":     time.Now().Unix(),
		}
	}

	// Update counters
	stats["total_cleanups"] = stats["total_cleanups"].(int) + 1
	stats["total_cleaned"] = stats["total_cleaned"].(int) + cleaned
	stats["total_errors"] = stats["total_errors"].(int) + errors
	stats["last_cleanup"] = time.Now().Unix()

	// Store updated statistics
	facades.Cache().Put(statsKey, stats, 7*24*time.Hour) // Keep for 7 days
}

// GetSessionMetrics returns current session metrics
func (s *SessionService) GetSessionMetrics() (map[string]interface{}, error) {
	// Get active session count
	activeSessionIDs, err := s.getActiveSessionIDs()
	if err != nil {
		return nil, fmt.Errorf("failed to get active sessions: %w", err)
	}

	// Get cleanup statistics
	var cleanupStats map[string]interface{}
	if err := facades.Cache().Get("session_statistics", &cleanupStats); err != nil {
		cleanupStats = map[string]interface{}{
			"total_cleanups": 0,
			"total_cleaned":  0,
			"total_errors":   0,
			"last_cleanup":   0,
		}
	}

	// Get latest cleanup metrics
	var latestCleanup map[string]interface{}
	facades.Cache().Get("session_cleanup_metrics:latest", &latestCleanup)

	metrics := map[string]interface{}{
		"active_sessions": len(activeSessionIDs),
		"cleanup_stats":   cleanupStats,
		"latest_cleanup":  latestCleanup,
		"timestamp":       time.Now().Unix(),
		"service_status":  "healthy",
	}

	return metrics, nil
}

// HealthCheck performs a health check on the session service
func (s *SessionService) HealthCheck() map[string]interface{} {
	health := map[string]interface{}{
		"service":   "session_service",
		"status":    "healthy",
		"timestamp": time.Now().Unix(),
		"checks":    map[string]interface{}{},
	}

	checks := health["checks"].(map[string]interface{})

	// Check cache connectivity
	testKey := "health_check_test"
	testValue := time.Now().Unix()
	if err := facades.Cache().Put(testKey, testValue, time.Minute); err != nil {
		checks["cache_write"] = map[string]interface{}{
			"status": "failed",
			"error":  err.Error(),
		}
		health["status"] = "unhealthy"
	} else {
		var retrievedValue int64
		if err := facades.Cache().Get(testKey, &retrievedValue); err != nil || retrievedValue != testValue {
			checks["cache_read"] = map[string]interface{}{
				"status": "failed",
				"error":  "cache read verification failed",
			}
			health["status"] = "unhealthy"
		} else {
			checks["cache"] = map[string]interface{}{
				"status": "healthy",
			}
			facades.Cache().Forget(testKey)
		}
	}

	// Check active sessions tracking
	activeSessionIDs, err := s.getActiveSessionIDs()
	if err != nil {
		checks["session_tracking"] = map[string]interface{}{
			"status": "failed",
			"error":  err.Error(),
		}
		health["status"] = "unhealthy"
	} else {
		checks["session_tracking"] = map[string]interface{}{
			"status":          "healthy",
			"active_sessions": len(activeSessionIDs),
		}
	}

	// Check cleanup performance
	var cleanupStats map[string]interface{}
	if err := facades.Cache().Get("session_statistics", &cleanupStats); err == nil {
		if lastCleanup, ok := cleanupStats["last_cleanup"].(int64); ok {
			timeSinceCleanup := time.Now().Unix() - lastCleanup
			if timeSinceCleanup > 3600 { // More than 1 hour
				checks["cleanup_schedule"] = map[string]interface{}{
					"status":             "warning",
					"last_cleanup_hours": timeSinceCleanup / 3600,
					"message":            "cleanup may be overdue",
				}
			} else {
				checks["cleanup_schedule"] = map[string]interface{}{
					"status":             "healthy",
					"last_cleanup_hours": timeSinceCleanup / 3600,
				}
			}
		}
	}

	return health
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

	// Production device detection using user agent parsing
	// Enhanced user agent parsing for better device detection
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

	// Add to active sessions set
	if err := s.addToActiveSessionsSet(session.ID); err != nil {
		facades.Log().Warning("Failed to add session to active set", map[string]interface{}{
			"session_id": session.ID,
			"error":      err.Error(),
		})
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

	// Remove from active sessions set
	if err := s.removeFromActiveSessionsSet(sessionID); err != nil {
		facades.Log().Warning("Failed to remove session from active set during deletion", map[string]interface{}{
			"session_id": sessionID,
			"error":      err.Error(),
		})
	}
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

// Session tracking helper methods

const ACTIVE_SESSIONS_KEY = "active_sessions_set"

func (s *SessionService) getActiveSessionIDs() ([]string, error) {
	// Get the set of active session IDs from cache
	var sessionIDs []string
	err := facades.Cache().Get(ACTIVE_SESSIONS_KEY, &sessionIDs)
	if err != nil {
		// If no active sessions exist, return empty slice
		return []string{}, nil
	}
	return sessionIDs, nil
}

func (s *SessionService) addToActiveSessionsSet(sessionID string) error {
	// Add session ID to the active sessions tracking set
	activeSessionIDs, err := s.getActiveSessionIDs()
	if err != nil {
		return err
	}

	// Check if session already exists in the set
	for _, id := range activeSessionIDs {
		if id == sessionID {
			return nil // Already exists
		}
	}

	// Add new session ID
	activeSessionIDs = append(activeSessionIDs, sessionID)

	// Store back to cache with longer TTL than individual sessions
	return facades.Cache().Put(ACTIVE_SESSIONS_KEY, activeSessionIDs, 48*time.Hour)
}

func (s *SessionService) removeFromActiveSessionsSet(sessionID string) error {
	// Remove session ID from the active sessions tracking set
	activeSessionIDs, err := s.getActiveSessionIDs()
	if err != nil {
		return err
	}

	// Filter out the session ID
	var filteredSessionIDs []string
	for _, id := range activeSessionIDs {
		if id != sessionID {
			filteredSessionIDs = append(filteredSessionIDs, id)
		}
	}

	// Store back to cache
	return facades.Cache().Put(ACTIVE_SESSIONS_KEY, filteredSessionIDs, 48*time.Hour)
}

func (s *SessionService) removeExpiredSession(sessionID string) error {
	// Remove session from cache
	sessionKey := "session_" + sessionID
	facades.Cache().Forget(sessionKey)

	// Remove from active sessions set
	if err := s.removeFromActiveSessionsSet(sessionID); err != nil {
		facades.Log().Warning("Failed to remove session from active set", map[string]interface{}{
			"session_id": sessionID,
			"error":      err.Error(),
		})
	}

	// Get session to find user ID for cleanup
	session, err := s.GetSession(sessionID)
	if err == nil {
		// Remove from user's session list
		s.removeSessionFromUser(session.UserID, sessionID)
	}

	facades.Log().Debug("Expired session removed", map[string]interface{}{
		"session_id": sessionID,
	})

	return nil
}
