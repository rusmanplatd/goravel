package models

import (
	"encoding/json"
)

// MeetingSecurityPolicy represents security policies for a meeting
type MeetingSecurityPolicy struct {
	BaseModel
	// Meeting reference
	MeetingID string `gorm:"not null;uniqueIndex" json:"meeting_id"`

	// Waiting room settings
	RequireWaitingRoom bool `gorm:"default:false" json:"require_waiting_room"`

	// Password protection
	RequirePassword bool `gorm:"default:false" json:"require_password"`

	// Anonymous access
	AllowAnonymousJoin bool `gorm:"default:true" json:"allow_anonymous_join"`

	// Participant limits
	MaxParticipants int `gorm:"default:100" json:"max_participants"`

	// Domain restrictions (JSON array of allowed domains)
	AllowedDomainsJSON string   `gorm:"column:allowed_domains;type:json" json:"-"`
	AllowedDomains     []string `gorm:"-" json:"allowed_domains"`

	// Blocked users (JSON array of user IDs)
	BlockedUsersJSON string   `gorm:"column:blocked_users;type:json" json:"-"`
	BlockedUsers     []string `gorm:"-" json:"blocked_users"`

	// Registration requirement
	RequireRegistration bool `gorm:"default:false" json:"require_registration"`

	// Encryption settings
	EnableE2EEncryption bool `gorm:"default:false" json:"enable_e2e_encryption"`

	// Permission settings
	RecordingPermissions   string `gorm:"default:'host'" json:"recording_permissions"`   // host, all, none
	ScreenSharePermissions string `gorm:"default:'all'" json:"screen_share_permissions"` // host, all, none
	ChatPermissions        string `gorm:"default:'all'" json:"chat_permissions"`         // host, all, none

	// Default participant settings
	MuteOnEntry   bool `gorm:"default:false" json:"mute_on_entry"`
	DisableCamera bool `gorm:"default:false" json:"disable_camera"`
	LockMeeting   bool `gorm:"default:false" json:"lock_meeting"`

	// Feature permissions
	EnableBreakoutRooms bool `gorm:"default:true" json:"enable_breakout_rooms"`
	EnablePolls         bool `gorm:"default:true" json:"enable_polls"`
	EnableWhiteboard    bool `gorm:"default:true" json:"enable_whiteboard"`
	EnableFileSharing   bool `gorm:"default:true" json:"enable_file_sharing"`
	EnableReactions     bool `gorm:"default:true" json:"enable_reactions"`
	EnableHandRaise     bool `gorm:"default:true" json:"enable_hand_raise"`

	// Timeout settings
	IdleTimeoutMinutes     int `gorm:"default:0" json:"idle_timeout_minutes"`     // 0 for no timeout
	MeetingDurationMinutes int `gorm:"default:0" json:"meeting_duration_minutes"` // 0 for unlimited

	// Join approval mode
	JoinApprovalMode string `gorm:"default:'automatic'" json:"join_approval_mode"` // automatic, manual, domain_restricted

	// Custom settings (JSON object for additional settings)
	CustomSettingsJSON string                 `gorm:"column:custom_settings;type:json" json:"-"`
	CustomSettings     map[string]interface{} `gorm:"-" json:"custom_settings"`

	// Relationships
	Meeting *Meeting `gorm:"foreignKey:MeetingID" json:"meeting,omitempty"`
}

// TableName returns the table name for MeetingSecurityPolicy
func (MeetingSecurityPolicy) TableName() string {
	return "meeting_security_policies"
}

// BeforeSave handles JSON marshaling before saving to database
func (msp *MeetingSecurityPolicy) BeforeSave() error {
	// Marshal allowed domains
	if msp.AllowedDomains != nil {
		data, err := json.Marshal(msp.AllowedDomains)
		if err != nil {
			return err
		}
		msp.AllowedDomainsJSON = string(data)
	}

	// Marshal blocked users
	if msp.BlockedUsers != nil {
		data, err := json.Marshal(msp.BlockedUsers)
		if err != nil {
			return err
		}
		msp.BlockedUsersJSON = string(data)
	}

	// Marshal custom settings
	if msp.CustomSettings != nil {
		data, err := json.Marshal(msp.CustomSettings)
		if err != nil {
			return err
		}
		msp.CustomSettingsJSON = string(data)
	}

	return nil
}

// AfterFind handles JSON unmarshaling after loading from database
func (msp *MeetingSecurityPolicy) AfterFind() error {
	// Unmarshal allowed domains
	if msp.AllowedDomainsJSON != "" {
		err := json.Unmarshal([]byte(msp.AllowedDomainsJSON), &msp.AllowedDomains)
		if err != nil {
			return err
		}
	}

	// Unmarshal blocked users
	if msp.BlockedUsersJSON != "" {
		err := json.Unmarshal([]byte(msp.BlockedUsersJSON), &msp.BlockedUsers)
		if err != nil {
			return err
		}
	}

	// Unmarshal custom settings
	if msp.CustomSettingsJSON != "" {
		err := json.Unmarshal([]byte(msp.CustomSettingsJSON), &msp.CustomSettings)
		if err != nil {
			return err
		}
	}

	return nil
}

// GetDefaultSecurityPolicy returns default security policy settings
func GetDefaultSecurityPolicy() *MeetingSecurityPolicy {
	return &MeetingSecurityPolicy{
		RequireWaitingRoom:     false,
		RequirePassword:        false,
		AllowAnonymousJoin:     true,
		MaxParticipants:        100,
		AllowedDomains:         []string{},
		BlockedUsers:           []string{},
		RequireRegistration:    false,
		EnableE2EEncryption:    false,
		RecordingPermissions:   "host",
		ScreenSharePermissions: "all",
		ChatPermissions:        "all",
		MuteOnEntry:            false,
		DisableCamera:          false,
		LockMeeting:            false,
		EnableBreakoutRooms:    true,
		EnablePolls:            true,
		EnableWhiteboard:       true,
		EnableFileSharing:      true,
		EnableReactions:        true,
		EnableHandRaise:        true,
		IdleTimeoutMinutes:     0,
		MeetingDurationMinutes: 0,
		JoinApprovalMode:       "automatic",
		CustomSettings:         make(map[string]interface{}),
	}
}

// IsUserBlocked checks if a user ID is in the blocked users list
func (msp *MeetingSecurityPolicy) IsUserBlocked(userID string) bool {
	for _, blockedID := range msp.BlockedUsers {
		if blockedID == userID {
			return true
		}
	}
	return false
}

// IsDomainAllowed checks if an email domain is allowed
func (msp *MeetingSecurityPolicy) IsDomainAllowed(domain string) bool {
	if len(msp.AllowedDomains) == 0 {
		return true // No restrictions
	}

	for _, allowedDomain := range msp.AllowedDomains {
		if allowedDomain == domain {
			return true
		}
	}
	return false
}

// CanRecord checks if a user with the given role can record
func (msp *MeetingSecurityPolicy) CanRecord(userRole string) bool {
	switch msp.RecordingPermissions {
	case "none":
		return false
	case "host":
		return userRole == "host" || userRole == "co-host"
	case "all":
		return true
	default:
		return userRole == "host" || userRole == "co-host"
	}
}

// CanScreenShare checks if a user with the given role can screen share
func (msp *MeetingSecurityPolicy) CanScreenShare(userRole string) bool {
	switch msp.ScreenSharePermissions {
	case "none":
		return false
	case "host":
		return userRole == "host" || userRole == "co-host"
	case "all":
		return true
	default:
		return true
	}
}

// CanChat checks if a user with the given role can chat
func (msp *MeetingSecurityPolicy) CanChat(userRole string) bool {
	switch msp.ChatPermissions {
	case "none":
		return false
	case "host":
		return userRole == "host" || userRole == "co-host"
	case "all":
		return true
	default:
		return true
	}
}
