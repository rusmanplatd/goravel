package models

import (
	"time"
)

// MeetingRecording represents a meeting recording
type MeetingRecording struct {
	BaseModel
	// Meeting reference
	MeetingID string `gorm:"not null" json:"meeting_id"`

	// Recording type (video, audio, screen)
	RecordingType string `gorm:"default:'video'" json:"recording_type"`

	// Recording file name
	FileName string `gorm:"not null" json:"file_name"`

	// Recording file path/URL
	FilePath string `gorm:"not null" json:"file_path"`

	// Recording file size in bytes
	FileSize string `json:"file_size"`

	// Recording duration in seconds
	Duration string `json:"duration"`

	// Recording format (mp4, mp3, webm)
	Format string `gorm:"default:'mp4'" json:"format"`

	// Recording quality (low, medium, high, ultra)
	Quality string `gorm:"default:'medium'" json:"quality"`

	// Recording status (processing, completed, failed, deleted)
	Status string `gorm:"default:'processing'" json:"status"`

	// Whether recording has been transcribed
	IsTranscribed bool `gorm:"default:false" json:"is_transcribed"`

	// Transcription file URL
	TranscriptionURL string `json:"transcription_url"`

	// Recording thumbnail URL
	ThumbnailURL string `json:"thumbnail_url"`

	// Additional recording metadata as JSON
	Metadata string `json:"metadata"`

	// Whether recording is publicly accessible
	IsPublic bool `gorm:"default:false" json:"is_public"`

	// Access key for protected recordings
	AccessKey string `json:"access_key"`

	// When recording expires and gets deleted
	ExpiresAt *time.Time `json:"expires_at,omitempty"`

	// When recording started
	StartedAt time.Time `gorm:"autoCreateTime" json:"started_at"`

	// When recording completed
	CompletedAt *time.Time `json:"completed_at,omitempty"`

	// Relationships
	Meeting        *Meeting               `gorm:"foreignKey:MeetingID" json:"meeting,omitempty"`
	Transcriptions []MeetingTranscription `gorm:"foreignKey:RecordingID" json:"transcriptions,omitempty"`
}

// MeetingTranscription represents a meeting transcription
type MeetingTranscription struct {
	BaseModel
	// Meeting reference
	MeetingID string `gorm:"not null" json:"meeting_id"`

	// Associated recording reference
	RecordingID *string `json:"recording_id,omitempty"`

	// Speaker user reference
	SpeakerID *string `json:"speaker_id,omitempty"`

	// Speaker display name
	SpeakerName string `json:"speaker_name"`

	// Transcribed text content
	Content string `gorm:"not null" json:"content"`

	// Transcription language code
	Language string `gorm:"default:'en'" json:"language"`

	// Transcription confidence score (0-1)
	ConfidenceScore float64 `json:"confidence_score"`

	// Start time in milliseconds
	StartTime int `json:"start_time"`

	// End time in milliseconds
	EndTime int `json:"end_time"`

	// Duration in milliseconds
	Duration int `json:"duration"`

	// Type (live, final, correction)
	TranscriptType string `gorm:"default:'live'" json:"transcript_type"`

	// Whether this is the final transcription
	IsFinal bool `gorm:"default:false" json:"is_final"`

	// Additional transcription metadata as JSON
	Metadata string `json:"metadata"`

	// Relationships
	Meeting   *Meeting          `gorm:"foreignKey:MeetingID" json:"meeting,omitempty"`
	Recording *MeetingRecording `gorm:"foreignKey:RecordingID" json:"recording,omitempty"`
	Speaker   *User             `gorm:"foreignKey:SpeakerID" json:"speaker,omitempty"`
}

// MeetingAISummary represents AI-generated meeting insights
type MeetingAISummary struct {
	BaseModel
	// Meeting reference
	MeetingID string `gorm:"not null" json:"meeting_id"`

	// AI-generated summary
	Summary string `json:"summary"`

	// Key points from the meeting
	KeyPoints string `json:"key_points"`

	// Action items as JSON
	ActionItems string `json:"action_items"`

	// Decisions made as JSON
	Decisions string `json:"decisions"`

	// Topics discussed as JSON
	Topics string `json:"topics"`

	// Overall sentiment
	Sentiment string `json:"sentiment"`

	// AI confidence score (0-1)
	Confidence float64 `json:"confidence"`

	// Processing time in seconds
	ProcessingTime float64 `json:"processing_time"`

	// Source of the insights (recording, live_transcription, etc.)
	Source string `gorm:"default:'recording'" json:"source"`

	// Relationships
	Meeting *Meeting `gorm:"foreignKey:MeetingID" json:"meeting,omitempty"`
}

// TableName returns the table name for MeetingRecording
func (MeetingRecording) TableName() string {
	return "meeting_recordings"
}

// TableName returns the table name for MeetingTranscription
func (MeetingTranscription) TableName() string {
	return "meeting_transcriptions"
}

// TableName returns the table name for MeetingAISummary
func (MeetingAISummary) TableName() string {
	return "meeting_ai_summaries"
}
