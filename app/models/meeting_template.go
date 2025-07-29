package models

import (
	"time"
)

// MeetingTemplate represents a reusable meeting template
type MeetingTemplate struct {
	BaseModel

	// Template name
	// @example "Weekly Team Standup Template"
	Name string `gorm:"not null" json:"name" example:"Weekly Team Standup Template"`

	// Template description
	// @example "Standard template for weekly team standup meetings"
	Description string `json:"description,omitempty" example:"Standard template for weekly team standup meetings"`

	// Template category (team_meetings, all_hands, training, interview, etc.)
	// @example "team_meetings"
	Category string `gorm:"default:'general'" json:"category" example:"team_meetings"`

	// User ID who created this template
	// @example "01HXYZ123456789ABCDEFGHIJK"
	CreatedBy string `gorm:"not null;index" json:"created_by" example:"01HXYZ123456789ABCDEFGHIJK"`

	// Whether this template is publicly available
	// @example false
	IsPublic bool `gorm:"default:false" json:"is_public" example:"false"`

	// Whether this template is active/enabled
	// @example true
	IsActive bool `gorm:"default:true" json:"is_active" example:"true"`

	// Number of times this template has been used
	// @example 25
	UsageCount int `gorm:"default:0" json:"usage_count" example:"25"`

	// Template version for tracking changes
	// @example "1.2.0"
	Version string `gorm:"default:'1.0.0'" json:"version" example:"1.2.0"`

	// Template tags for categorization and search
	// @example ["standup", "agile", "weekly"]
	Tags []string `gorm:"type:jsonb" json:"tags,omitempty" example:"standup,agile,weekly"`

	// Default meeting settings stored as JSON
	// @example {"allow_recording": true, "enable_waiting_room": false}
	DefaultSettings map[string]interface{} `gorm:"type:jsonb" json:"default_settings,omitempty" example:"{\"allow_recording\": true, \"enable_waiting_room\": false}"`

	// Meeting agenda template
	// @example "1. Check-ins\n2. Sprint progress\n3. Blockers\n4. Next steps"
	AgendaTemplate string `json:"agenda_template,omitempty" example:"1. Check-ins\n2. Sprint progress\n3. Blockers\n4. Next steps"`

	// Default meeting duration in minutes
	// @example 30
	DefaultDuration int `gorm:"default:60" json:"default_duration" example:"30"`

	// Default meeting type (video, audio, hybrid, in-person)
	// @example "video"
	DefaultMeetingType string `gorm:"default:'video'" json:"default_meeting_type" example:"video"`

	// Default platform (teams, zoom, meet, etc.)
	// @example "teams"
	DefaultPlatform string `gorm:"default:'teams'" json:"default_platform" example:"teams"`

	// Default participant roles and permissions
	// @example {"default_role": "attendee", "allow_anonymous": false}
	DefaultParticipantSettings map[string]interface{} `gorm:"type:jsonb" json:"default_participant_settings,omitempty" example:"{\"default_role\": \"attendee\", \"allow_anonymous\": false}"`

	// Default security settings
	// @example {"require_waiting_room": true, "enable_e2e_encryption": false}
	DefaultSecuritySettings map[string]interface{} `gorm:"type:jsonb" json:"default_security_settings,omitempty" example:"{\"require_waiting_room\": true, \"enable_e2e_encryption\": false}"`

	// Default notification settings
	// @example {"send_reminders": true, "reminder_times": [15, 60]}
	DefaultNotificationSettings map[string]interface{} `gorm:"type:jsonb" json:"default_notification_settings,omitempty" example:"{\"send_reminders\": true, \"reminder_times\": [15, 60]}"`

	// Template thumbnail/icon URL
	// @example "https://example.com/templates/standup-icon.png"
	ThumbnailURL string `json:"thumbnail_url,omitempty" example:"https://example.com/templates/standup-icon.png"`

	// Template color theme
	// @example "#0078d4"
	ColorTheme string `json:"color_theme,omitempty" example:"#0078d4"`

	// Template metadata for extensibility
	// @example {"source": "system", "migration_version": "1.0"}
	Metadata map[string]interface{} `gorm:"type:jsonb" json:"metadata,omitempty" example:"{\"source\": \"system\", \"migration_version\": \"1.0\"}"`

	// When the template was last used
	// @example "2024-01-15T10:00:00Z"
	LastUsedAt *time.Time `json:"last_used_at,omitempty" example:"2024-01-15T10:00:00Z"`

	// Relationships
	// @Description User who created this template
	Creator *User `gorm:"foreignKey:CreatedBy" json:"creator,omitempty"`

	// @Description Meetings created from this template
	Meetings []Meeting `gorm:"foreignKey:MeetingTemplateId;references:ID" json:"meetings,omitempty"`
}

// TableName returns the table name for MeetingTemplate
func (MeetingTemplate) TableName() string {
	return "meeting_templates"
}

// IncrementUsage increments the usage count and updates last used time
func (mt *MeetingTemplate) IncrementUsage() {
	mt.UsageCount++
	now := time.Now()
	mt.LastUsedAt = &now
}

// IsOwner checks if the given user ID is the owner of this template
func (mt *MeetingTemplate) IsOwner(userID string) bool {
	return mt.CreatedBy == userID
}

// CanBeUsedBy checks if the template can be used by the given user
func (mt *MeetingTemplate) CanBeUsedBy(userID string) bool {
	return mt.IsActive && (mt.IsPublic || mt.IsOwner(userID))
}

// GetCategoryDisplayName returns a human-readable category name
func (mt *MeetingTemplate) GetCategoryDisplayName() string {
	categoryNames := map[string]string{
		"team_meetings": "Team Meetings",
		"all_hands":     "All Hands",
		"training":      "Training",
		"interview":     "Interview",
		"client_call":   "Client Call",
		"one_on_one":    "One-on-One",
		"brainstorm":    "Brainstorming",
		"review":        "Review",
		"planning":      "Planning",
		"general":       "General",
	}

	if displayName, exists := categoryNames[mt.Category]; exists {
		return displayName
	}
	return mt.Category
}

// HasTag checks if the template has a specific tag
func (mt *MeetingTemplate) HasTag(tag string) bool {
	for _, t := range mt.Tags {
		if t == tag {
			return true
		}
	}
	return false
}

// AddTag adds a tag to the template if it doesn't already exist
func (mt *MeetingTemplate) AddTag(tag string) {
	if !mt.HasTag(tag) {
		mt.Tags = append(mt.Tags, tag)
	}
}

// RemoveTag removes a tag from the template
func (mt *MeetingTemplate) RemoveTag(tag string) {
	for i, t := range mt.Tags {
		if t == tag {
			mt.Tags = append(mt.Tags[:i], mt.Tags[i+1:]...)
			break
		}
	}
}

// GetDefaultSetting gets a default setting value
func (mt *MeetingTemplate) GetDefaultSetting(key string) interface{} {
	if mt.DefaultSettings == nil {
		return nil
	}
	return mt.DefaultSettings[key]
}

// SetDefaultSetting sets a default setting value
func (mt *MeetingTemplate) SetDefaultSetting(key string, value interface{}) {
	if mt.DefaultSettings == nil {
		mt.DefaultSettings = make(map[string]interface{})
	}
	mt.DefaultSettings[key] = value
}

// ToTeamsFormat converts the template to Teams-compatible format
func (mt *MeetingTemplate) ToTeamsFormat() map[string]interface{} {
	return map[string]interface{}{
		"id":                          mt.ID,
		"name":                        mt.Name,
		"description":                 mt.Description,
		"category":                    mt.Category,
		"categoryDisplayName":         mt.GetCategoryDisplayName(),
		"createdBy":                   mt.CreatedBy,
		"isPublic":                    mt.IsPublic,
		"isActive":                    mt.IsActive,
		"usageCount":                  mt.UsageCount,
		"version":                     mt.Version,
		"tags":                        mt.Tags,
		"defaultSettings":             mt.DefaultSettings,
		"agendaTemplate":              mt.AgendaTemplate,
		"defaultDuration":             mt.DefaultDuration,
		"defaultMeetingType":          mt.DefaultMeetingType,
		"defaultPlatform":             mt.DefaultPlatform,
		"defaultParticipantSettings":  mt.DefaultParticipantSettings,
		"defaultSecuritySettings":     mt.DefaultSecuritySettings,
		"defaultNotificationSettings": mt.DefaultNotificationSettings,
		"thumbnailUrl":                mt.ThumbnailURL,
		"colorTheme":                  mt.ColorTheme,
		"metadata":                    mt.Metadata,
		"lastUsedAt":                  mt.LastUsedAt,
		"createdAt":                   mt.CreatedAt,
		"updatedAt":                   mt.UpdatedAt,
	}
}

// ToCreateMeetingRequest converts template to CreateOnlineMeetingRequest format
func (mt *MeetingTemplate) ToCreateMeetingRequest() map[string]interface{} {
	request := map[string]interface{}{
		"meeting_template_id": mt.ID,
	}

	// Apply default settings
	if mt.DefaultSettings != nil {
		for key, value := range mt.DefaultSettings {
			request[key] = value
		}
	}

	// Apply participant settings
	if mt.DefaultParticipantSettings != nil {
		for key, value := range mt.DefaultParticipantSettings {
			request[key] = value
		}
	}

	// Apply security settings
	if mt.DefaultSecuritySettings != nil {
		for key, value := range mt.DefaultSecuritySettings {
			request[key] = value
		}
	}

	// Apply notification settings
	if mt.DefaultNotificationSettings != nil {
		for key, value := range mt.DefaultNotificationSettings {
			request[key] = value
		}
	}

	return request
}
