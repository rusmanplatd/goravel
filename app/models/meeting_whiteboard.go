package models

// MeetingWhiteboard represents a whiteboard in a meeting
type MeetingWhiteboard struct {
	BaseModel
	// Meeting reference
	MeetingID string `gorm:"not null" json:"meeting_id"`

	// Whiteboard title
	Title string `gorm:"not null" json:"title"`

	// Whiteboard description
	Description string `json:"description"`

	// Whether whiteboard is currently active
	IsActive bool `gorm:"default:true" json:"is_active"`

	// Whether whiteboard is shared with all participants
	IsShared bool `gorm:"default:true" json:"is_shared"`

	// Canvas drawing data as JSON
	CanvasData string `json:"canvas_data"`

	// Canvas version for conflict resolution
	CanvasVersion string `json:"canvas_version"`

	// Canvas width in pixels
	Width int `gorm:"default:1920" json:"width"`

	// Canvas height in pixels
	Height int `gorm:"default:1080" json:"height"`

	// Canvas background color
	BackgroundColor string `gorm:"default:'#ffffff'" json:"background_color"`

	// List of collaborator user IDs as JSON
	Collaborators string `json:"collaborators"`

	// Relationships
	Meeting *Meeting `gorm:"foreignKey:MeetingID" json:"meeting,omitempty"`
}

// TableName returns the table name for MeetingWhiteboard
func (MeetingWhiteboard) TableName() string {
	return "meeting_whiteboards"
}
