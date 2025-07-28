package models

import (
	"encoding/json"
)

// MeetingMetric represents meeting performance and monitoring metrics
// @Description Meeting metrics for monitoring and analytics
type MeetingMetric struct {
	BaseModel

	// Meeting reference
	// @example 01HXYZ123456789ABCDEFGHIJK
	MeetingID string `gorm:"not null;index" json:"meeting_id" example:"01HXYZ123456789ABCDEFGHIJK"`

	// Connection metrics
	// @example 25
	TotalConnections int `gorm:"default:0" json:"total_connections" example:"25"`
	// @example 20
	ActiveConnections int `gorm:"default:0" json:"active_connections" example:"20"`
	// @example 5
	FailedConnections int `gorm:"default:0" json:"failed_connections" example:"5"`
	// @example 45.5
	ConnectionLatency float64 `gorm:"default:0" json:"connection_latency" example:"45.5"`
	// @example 3
	ReconnectionCount int `gorm:"default:0" json:"reconnection_count" example:"3"`

	// Audio/Video metrics
	// @example 0.95
	AudioQuality float64 `gorm:"default:0" json:"audio_quality" example:"0.95"`
	// @example 0.88
	VideoQuality float64 `gorm:"default:0" json:"video_quality" example:"0.88"`
	// @example 0.02
	PacketLossRate float64 `gorm:"default:0" json:"packet_loss_rate" example:"0.02"`
	// @example 12.5
	Jitter float64 `gorm:"default:0" json:"jitter" example:"12.5"`
	// @example 1500
	Bitrate int64 `gorm:"default:0" json:"bitrate" example:"1500"`
	// @example 30.0
	FrameRate float64 `gorm:"default:0" json:"frame_rate" example:"30.0"`

	// Participant metrics
	// @example 8
	ParticipantCount int `gorm:"default:0" json:"participant_count" example:"8"`
	// @example {"user1": 120.5, "user2": 95.2}
	SpeakingTimeJSON string             `gorm:"column:speaking_time;type:json" json:"-"`
	SpeakingTime     map[string]float64 `gorm:"-" json:"speaking_time" example:"{\"user1\": 120.5, \"user2\": 95.2}"`
	// @example 3
	MutedParticipants int `gorm:"default:0" json:"muted_participants" example:"3"`
	// @example 2
	VideoOffParticipants int `gorm:"default:0" json:"video_off_participants" example:"2"`

	// Meeting flow metrics
	// @example 3600.0
	Duration float64 `gorm:"default:0" json:"duration" example:"3600.0"`
	// @example 5
	SilencePeriods int `gorm:"default:0" json:"silence_periods" example:"5"`
	// @example 12
	InterruptionCount int `gorm:"default:0" json:"interruption_count" example:"12"`
	// @example 8
	HandRaisedCount int `gorm:"default:0" json:"hand_raised_count" example:"8"`
	// @example 45
	ChatMessageCount int `gorm:"default:0" json:"chat_message_count" example:"45"`

	// Technical metrics
	// @example 65.2
	CPUUsage float64 `gorm:"default:0" json:"cpu_usage" example:"65.2"`
	// @example 1024.5
	MemoryUsage float64 `gorm:"default:0" json:"memory_usage" example:"1024.5"`
	// @example 15.8
	NetworkBandwidth float64 `gorm:"default:0" json:"network_bandwidth" example:"15.8"`
	// @example 0.75
	ServerLoad float64 `gorm:"default:0" json:"server_load" example:"0.75"`

	// Engagement metrics
	// @example 0.82
	EngagementScore float64 `gorm:"default:0" json:"engagement_score" example:"0.82"`
	// @example 0.78
	AttentionScore float64 `gorm:"default:0" json:"attention_score" example:"0.78"`
	// @example 0.85
	ParticipationRate float64 `gorm:"default:0" json:"participation_rate" example:"0.85"`

	// Error metrics
	// @example 2
	ErrorCount int `gorm:"default:0" json:"error_count" example:"2"`
	// @example 5
	WarningCount int `gorm:"default:0" json:"warning_count" example:"5"`
	// @example 0
	CriticalIssues int `gorm:"default:0" json:"critical_issues" example:"0"`

	// Relationships
	Meeting *Meeting `gorm:"foreignKey:MeetingID" json:"meeting,omitempty"`
}

// TableName returns the table name for MeetingMetric
func (MeetingMetric) TableName() string {
	return "meeting_metrics"
}

// BeforeSave handles JSON marshaling before saving to database
func (mm *MeetingMetric) BeforeSave() error {
	// Marshal speaking time
	if mm.SpeakingTime != nil {
		data, err := json.Marshal(mm.SpeakingTime)
		if err != nil {
			return err
		}
		mm.SpeakingTimeJSON = string(data)
	}
	return nil
}

// AfterFind handles JSON unmarshaling after loading from database
func (mm *MeetingMetric) AfterFind() error {
	// Unmarshal speaking time
	if mm.SpeakingTimeJSON != "" {
		err := json.Unmarshal([]byte(mm.SpeakingTimeJSON), &mm.SpeakingTime)
		if err != nil {
			return err
		}
	}
	return nil
}
