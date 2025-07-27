package models

import (
	"time"
)

// MeetingSummary represents an AI-generated meeting summary
type MeetingSummary struct {
	BaseModel
	// Recording reference
	RecordingID string `gorm:"not null" json:"recording_id"`

	// Meeting reference
	MeetingID string `gorm:"not null" json:"meeting_id"`

	// Summary title
	Title string `json:"title"`

	// Brief summary text
	Summary string `gorm:"type:text" json:"summary"`

	// Full AI-generated content (JSON format)
	Content string `gorm:"type:text" json:"content"`

	// Language of the summary
	Language string `gorm:"default:'en'" json:"language"`

	// AI model used for generation
	AIModel string `json:"ai_model"`

	// Confidence score (0-1)
	ConfidenceScore float64 `gorm:"default:0" json:"confidence_score"`

	// Summary type (automatic, manual, hybrid)
	SummaryType string `gorm:"default:'automatic'" json:"summary_type"`

	// Summary status (processing, completed, failed)
	Status string `gorm:"default:'processing'" json:"status"`

	// Error message if processing failed
	ErrorMessage string `json:"error_message"`

	// Number of action items identified
	ActionItemsCount int `gorm:"default:0" json:"action_items_count"`

	// Number of decisions identified
	DecisionsCount int `gorm:"default:0" json:"decisions_count"`

	// Number of key points identified
	KeyPointsCount int `gorm:"default:0" json:"key_points_count"`

	// Overall sentiment (positive, negative, neutral)
	Sentiment string `gorm:"default:'neutral'" json:"sentiment"`

	// Sentiment score (-1 to 1)
	SentimentScore float64 `gorm:"default:0" json:"sentiment_score"`

	// Whether summary is approved by host
	IsApproved bool `gorm:"default:false" json:"is_approved"`

	// Who approved the summary
	ApprovedBy *string `json:"approved_by,omitempty"`

	// When summary was approved
	ApprovedAt *time.Time `json:"approved_at,omitempty"`

	// Whether summary is public
	IsPublic bool `gorm:"default:false" json:"is_public"`

	// When summary was generated
	GeneratedAt time.Time `gorm:"autoCreateTime" json:"generated_at"`

	// When processing completed
	CompletedAt *time.Time `json:"completed_at,omitempty"`

	// Relationships
	Recording *MeetingRecording `gorm:"foreignKey:RecordingID" json:"recording,omitempty"`
	Meeting   *Meeting          `gorm:"foreignKey:MeetingID" json:"meeting,omitempty"`
	Approver  *User             `gorm:"foreignKey:ApprovedBy" json:"approver,omitempty"`
}

// TableName returns the table name for the MeetingSummary model
func (MeetingSummary) TableName() string {
	return "meeting_summaries"
}
