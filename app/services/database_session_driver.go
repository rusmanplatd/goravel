package services

import (
	"time"

	"github.com/goravel/framework/facades"
)

type DatabaseSessionDriver struct {
	table      string
	connection string
}

// NewDatabaseSessionDriver creates a new database session driver
func NewDatabaseSessionDriver(table, connection string) *DatabaseSessionDriver {
	if table == "" {
		table = "sessions"
	}
	if connection == "" {
		connection = "default"
	}

	return &DatabaseSessionDriver{
		table:      table,
		connection: connection,
	}
}

// Read retrieves session data from the database
func (d *DatabaseSessionDriver) Read(sessionID string) (string, error) {
	var payload string

	err := facades.DB().Connection(d.connection).
		Table(d.table).
		Where("id", sessionID).
		Where("last_activity", ">=", time.Now().Unix()-int64(facades.Config().GetInt("session.lifetime")*60)).
		Pluck("payload", &payload)

	if err != nil {
		return "", err
	}

	return payload, nil
}

// Write stores session data in the database
func (d *DatabaseSessionDriver) Write(sessionID, data string) error {
	now := time.Now()

	// Check if session exists
	count, err := facades.DB().Connection(d.connection).
		Table(d.table).
		Where("id", sessionID).
		Count()

	if err != nil {
		return err
	}

	if count > 0 {
		// Update existing session
		_, err = facades.DB().Connection(d.connection).
			Table(d.table).
			Where("id", sessionID).
			Update(map[string]interface{}{
				"payload":       data,
				"last_activity": now.Unix(),
				"updated_at":    now,
			})
		return err
	} else {
		// Create new session
		_, err = facades.DB().Connection(d.connection).
			Table(d.table).
			Insert(map[string]interface{}{
				"id":            sessionID,
				"payload":       data,
				"last_activity": now.Unix(),
				"created_at":    now,
				"updated_at":    now,
			})
		return err
	}
}

// Destroy removes a session from the database
func (d *DatabaseSessionDriver) Destroy(sessionID string) error {
	_, err := facades.DB().Connection(d.connection).
		Table(d.table).
		Where("id", sessionID).
		Delete()
	return err
}

// Gc performs garbage collection on expired sessions
func (d *DatabaseSessionDriver) Gc(maxLifetime int) error {
	expiredTime := time.Now().Unix() - int64(maxLifetime)

	_, err := facades.DB().Connection(d.connection).
		Table(d.table).
		Where("last_activity", "<", expiredTime).
		Delete()
	return err
}

// All returns all sessions (used for debugging/admin purposes)
func (d *DatabaseSessionDriver) All() (map[string]string, error) {
	var sessions []map[string]interface{}

	err := facades.DB().Connection(d.connection).
		Table(d.table).
		Where("last_activity", ">=", time.Now().Unix()-int64(facades.Config().GetInt("session.lifetime")*60)).
		Get(&sessions)

	if err != nil {
		return nil, err
	}

	result := make(map[string]string)
	for _, sess := range sessions {
		if id, ok := sess["id"].(string); ok {
			if payload, ok := sess["payload"].(string); ok {
				result[id] = payload
			}
		}
	}

	return result, nil
}

// Flush removes all sessions from the database
func (d *DatabaseSessionDriver) Flush() error {
	_, err := facades.DB().Connection(d.connection).
		Table(d.table).
		Delete()
	return err
}

// SessionData represents the structure of session data in the database
type SessionData struct {
	ID           string    `json:"id"`
	Payload      string    `json:"payload"`
	LastActivity int64     `json:"last_activity"`
	UserID       *string   `json:"user_id,omitempty"`
	IPAddress    *string   `json:"ip_address,omitempty"`
	UserAgent    *string   `json:"user_agent,omitempty"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

// GetSessionsByUser retrieves all sessions for a specific user
func (d *DatabaseSessionDriver) GetSessionsByUser(userID string) ([]SessionData, error) {
	var sessions []SessionData

	err := facades.DB().Connection(d.connection).
		Table(d.table).
		Where("user_id", userID).
		Where("last_activity", ">=", time.Now().Unix()-int64(facades.Config().GetInt("session.lifetime")*60)).
		Get(&sessions)

	return sessions, err
}

// UpdateSessionUser associates a session with a user
func (d *DatabaseSessionDriver) UpdateSessionUser(sessionID, userID, ipAddress, userAgent string) error {
	_, err := facades.DB().Connection(d.connection).
		Table(d.table).
		Where("id", sessionID).
		Update(map[string]interface{}{
			"user_id":    userID,
			"ip_address": ipAddress,
			"user_agent": userAgent,
			"updated_at": time.Now(),
		})
	return err
}

// DestroyUserSessions removes all sessions for a specific user
func (d *DatabaseSessionDriver) DestroyUserSessions(userID string) error {
	_, err := facades.DB().Connection(d.connection).
		Table(d.table).
		Where("user_id", userID).
		Delete()
	return err
}

// Open opens the database session driver (required by session.Driver interface)
func (d *DatabaseSessionDriver) Open(path, name string) error {
	// No initialization needed for database connections as they're managed by the framework
	return nil
}

// Close closes the database session driver (required by session.Driver interface)
func (d *DatabaseSessionDriver) Close() error {
	// No cleanup needed for database connections as they're managed by the framework
	return nil
}
