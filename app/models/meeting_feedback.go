package models

import (
	"time"
)

// MeetingFeedback represents feedback submitted for a meeting
type MeetingFeedback struct {
	BaseModel

	// Meeting ID that this feedback is for
	// @example "01HXYZ123456789ABCDEFGHIJK"
	MeetingID string `gorm:"not null;index" json:"meeting_id" example:"01HXYZ123456789ABCDEFGHIJK"`

	// User ID who submitted the feedback
	// @example "01HXYZ123456789ABCDEFGHIJK"
	SubmittedBy string `gorm:"not null" json:"submitted_by" example:"01HXYZ123456789ABCDEFGHIJK"`

	// Overall meeting rating (1-5)
	// @example 4
	OverallRating int `gorm:"not null" json:"overall_rating" example:"4"`

	// Audio quality rating (1-5)
	// @example 5
	AudioQuality *int `json:"audio_quality,omitempty" example:"5"`

	// Video quality rating (1-5)
	// @example 4
	VideoQuality *int `json:"video_quality,omitempty" example:"4"`

	// Meeting organization rating (1-5)
	// @example 5
	OrganizationRating *int `json:"organization_rating,omitempty" example:"5"`

	// Content relevance rating (1-5)
	// @example 4
	ContentRelevance *int `json:"content_relevance,omitempty" example:"4"`

	// Written feedback comments
	// @example "Great meeting! The presentation was very informative."
	Comments *string `gorm:"type:text" json:"comments,omitempty" example:"Great meeting! The presentation was very informative."`

	// Specific issues encountered
	// @example ["Audio cutting out", "Screen sharing lag"]
	Issues []string `gorm:"type:jsonb" json:"issues,omitempty" example:"Audio cutting out,Screen sharing lag"`

	// Suggestions for improvement
	// @example "Could use better lighting in the conference room"
	Suggestions *string `gorm:"type:text" json:"suggestions,omitempty" example:"Could use better lighting in the conference room"`

	// Would recommend this meeting format
	// @example true
	WouldRecommend *bool `json:"would_recommend,omitempty" example:"true"`

	// Whether this feedback is anonymous
	// @example false
	IsAnonymous bool `gorm:"default:false" json:"is_anonymous" example:"false"`

	// Feedback category (post_meeting, real_time, issue_report)
	// @example "post_meeting"
	Category string `gorm:"default:'post_meeting'" json:"category" example:"post_meeting"`

	// Feedback status (submitted, reviewed, resolved)
	// @example "submitted"
	Status string `gorm:"default:'submitted'" json:"status" example:"submitted"`

	// Priority level (low, medium, high, critical)
	// @example "medium"
	Priority string `gorm:"default:'medium'" json:"priority" example:"medium"`

	// Tags for categorization
	// @example ["audio-issues", "content-feedback"]
	Tags []string `gorm:"type:jsonb" json:"tags,omitempty" example:"audio-issues,content-feedback"`

	// Additional metadata
	// @example {"device_type": "laptop", "browser": "Chrome", "connection": "wifi"}
	Metadata map[string]interface{} `gorm:"type:jsonb" json:"metadata,omitempty" example:"{\"device_type\": \"laptop\", \"browser\": \"Chrome\", \"connection\": \"wifi\"}"`

	// When the feedback was submitted
	// @example "2024-01-15T11:05:00Z"
	SubmittedAt time.Time `json:"submitted_at" example:"2024-01-15T11:05:00Z"`

	// When the feedback was reviewed
	// @example "2024-01-15T15:30:00Z"
	ReviewedAt *time.Time `json:"reviewed_at,omitempty" example:"2024-01-15T15:30:00Z"`

	// User who reviewed the feedback
	// @example "01HXYZ123456789ABCDEFGHIJK"
	ReviewedBy *string `json:"reviewed_by,omitempty" example:"01HXYZ123456789ABCDEFGHIJK"`

	// Review notes
	// @example "Addressed audio issues with IT team"
	ReviewNotes *string `gorm:"type:text" json:"review_notes,omitempty" example:"Addressed audio issues with IT team"`

	// Relationships
	// @Description Meeting this feedback is for
	Meeting *Meeting `gorm:"foreignKey:MeetingID" json:"meeting,omitempty"`

	// @Description User who submitted the feedback
	Submitter *User `gorm:"foreignKey:SubmittedBy" json:"submitter,omitempty"`

	// @Description User who reviewed the feedback
	Reviewer *User `gorm:"foreignKey:ReviewedBy" json:"reviewer,omitempty"`
}

// TableName returns the table name for MeetingFeedback
func (MeetingFeedback) TableName() string {
	return "meeting_feedback"
}

// IsPositive checks if the feedback is generally positive (rating >= 4)
func (mf *MeetingFeedback) IsPositive() bool {
	return mf.OverallRating >= 4
}

// IsNegative checks if the feedback is generally negative (rating <= 2)
func (mf *MeetingFeedback) IsNegative() bool {
	return mf.OverallRating <= 2
}

// HasIssues checks if the feedback mentions any issues
func (mf *MeetingFeedback) HasIssues() bool {
	return len(mf.Issues) > 0
}

// HasSuggestions checks if the feedback includes suggestions
func (mf *MeetingFeedback) HasSuggestions() bool {
	return mf.Suggestions != nil && *mf.Suggestions != ""
}

// IsReviewed checks if the feedback has been reviewed
func (mf *MeetingFeedback) IsReviewed() bool {
	return mf.ReviewedAt != nil
}

// MarkAsReviewed marks the feedback as reviewed
func (mf *MeetingFeedback) MarkAsReviewed(reviewerID string, notes string) {
	mf.Status = "reviewed"
	mf.ReviewedBy = &reviewerID
	mf.ReviewNotes = &notes
	now := time.Now()
	mf.ReviewedAt = &now
}

// GetAverageQualityRating calculates average quality rating from audio and video
func (mf *MeetingFeedback) GetAverageQualityRating() float64 {
	total := 0
	count := 0

	if mf.AudioQuality != nil {
		total += *mf.AudioQuality
		count++
	}
	if mf.VideoQuality != nil {
		total += *mf.VideoQuality
		count++
	}

	if count == 0 {
		return 0
	}
	return float64(total) / float64(count)
}

// ToTeamsFormat converts the feedback to Teams-compatible format
func (mf *MeetingFeedback) ToTeamsFormat() map[string]interface{} {
	return map[string]interface{}{
		"id":                   mf.ID,
		"meetingId":            mf.MeetingID,
		"submittedBy":          mf.SubmittedBy,
		"overallRating":        mf.OverallRating,
		"audioQuality":         mf.AudioQuality,
		"videoQuality":         mf.VideoQuality,
		"organizationRating":   mf.OrganizationRating,
		"contentRelevance":     mf.ContentRelevance,
		"comments":             mf.Comments,
		"issues":               mf.Issues,
		"suggestions":          mf.Suggestions,
		"wouldRecommend":       mf.WouldRecommend,
		"isAnonymous":          mf.IsAnonymous,
		"category":             mf.Category,
		"status":               mf.Status,
		"priority":             mf.Priority,
		"tags":                 mf.Tags,
		"metadata":             mf.Metadata,
		"submittedAt":          mf.SubmittedAt,
		"reviewedAt":           mf.ReviewedAt,
		"reviewedBy":           mf.ReviewedBy,
		"reviewNotes":          mf.ReviewNotes,
		"isPositive":           mf.IsPositive(),
		"isNegative":           mf.IsNegative(),
		"hasIssues":            mf.HasIssues(),
		"hasSuggestions":       mf.HasSuggestions(),
		"isReviewed":           mf.IsReviewed(),
		"averageQualityRating": mf.GetAverageQualityRating(),
		"createdAt":            mf.CreatedAt,
		"updatedAt":            mf.UpdatedAt,
	}
}

// MeetingIssue represents a reported issue during a meeting
type MeetingIssue struct {
	BaseModel

	// Meeting ID where the issue occurred
	// @example "01HXYZ123456789ABCDEFGHIJK"
	MeetingID string `gorm:"not null;index" json:"meeting_id" example:"01HXYZ123456789ABCDEFGHIJK"`

	// User ID who reported the issue
	// @example "01HXYZ123456789ABCDEFGHIJK"
	ReportedBy string `gorm:"not null" json:"reported_by" example:"01HXYZ123456789ABCDEFGHIJK"`

	// Issue category (audio, video, connection, content, other)
	// @example "audio"
	Category string `gorm:"not null" json:"category" example:"audio"`

	// Issue severity (low, medium, high, critical)
	// @example "medium"
	Severity string `gorm:"not null" json:"severity" example:"medium"`

	// Issue title/summary
	// @example "Audio cutting out during presentation"
	Title string `gorm:"not null" json:"title" example:"Audio cutting out during presentation"`

	// Detailed issue description
	// @example "Audio kept cutting out during the presentation, making it difficult to follow"
	Description string `gorm:"type:text;not null" json:"description" example:"Audio kept cutting out during the presentation, making it difficult to follow"`

	// When the issue occurred
	// @example "2024-01-15T10:30:00Z"
	OccurredAt *time.Time `json:"occurred_at,omitempty" example:"2024-01-15T10:30:00Z"`

	// Steps to reproduce the issue
	// @example ["1. Join meeting", "2. Start presentation", "3. Audio cuts out after 5 minutes"]
	StepsToReproduce []string `gorm:"type:jsonb" json:"steps_to_reproduce,omitempty" example:"1. Join meeting,2. Start presentation,3. Audio cuts out after 5 minutes"`

	// Device information
	// @example {"os": "Windows 11", "browser": "Chrome 120.0.0.0", "device_type": "laptop"}
	DeviceInfo map[string]interface{} `gorm:"type:jsonb" json:"device_info,omitempty" example:"{\"os\": \"Windows 11\", \"browser\": \"Chrome 120.0.0.0\", \"device_type\": \"laptop\"}"`

	// Network information
	// @example {"connection_type": "wifi", "speed": "100 Mbps", "latency": "45ms"}
	NetworkInfo map[string]interface{} `gorm:"type:jsonb" json:"network_info,omitempty" example:"{\"connection_type\": \"wifi\", \"speed\": \"100 Mbps\", \"latency\": \"45ms\"}"`

	// Screenshots or recordings
	// @example ["screenshot1.png", "recording1.mp4"]
	Attachments []string `gorm:"type:jsonb" json:"attachments,omitempty" example:"screenshot1.png,recording1.mp4"`

	// Issue status (open, investigating, resolved, closed)
	// @example "open"
	Status string `gorm:"default:'open'" json:"status" example:"open"`

	// Resolution description
	// @example "Updated audio drivers and reconfigured microphone settings"
	Resolution *string `gorm:"type:text" json:"resolution,omitempty" example:"Updated audio drivers and reconfigured microphone settings"`

	// User who resolved the issue
	// @example "01HXYZ123456789ABCDEFGHIJK"
	ResolvedBy *string `json:"resolved_by,omitempty" example:"01HXYZ123456789ABCDEFGHIJK"`

	// When the issue was resolved
	// @example "2024-01-15T16:00:00Z"
	ResolvedAt *time.Time `json:"resolved_at,omitempty" example:"2024-01-15T16:00:00Z"`

	// Tags for categorization
	// @example ["audio-driver", "hardware-issue"]
	Tags []string `gorm:"type:jsonb" json:"tags,omitempty" example:"audio-driver,hardware-issue"`

	// Additional metadata
	// @example {"error_code": "AUDIO_001", "frequency": "intermittent"}
	Metadata map[string]interface{} `gorm:"type:jsonb" json:"metadata,omitempty" example:"{\"error_code\": \"AUDIO_001\", \"frequency\": \"intermittent\"}"`

	// Relationships
	// @Description Meeting where the issue occurred
	Meeting *Meeting `gorm:"foreignKey:MeetingID" json:"meeting,omitempty"`

	// @Description User who reported the issue
	Reporter *User `gorm:"foreignKey:ReportedBy" json:"reporter,omitempty"`

	// @Description User who resolved the issue
	Resolver *User `gorm:"foreignKey:ResolvedBy" json:"resolver,omitempty"`
}

// TableName returns the table name for MeetingIssue
func (MeetingIssue) TableName() string {
	return "meeting_issues"
}

// IsResolved checks if the issue has been resolved
func (mi *MeetingIssue) IsResolved() bool {
	return mi.Status == "resolved" || mi.Status == "closed"
}

// IsCritical checks if the issue is critical severity
func (mi *MeetingIssue) IsCritical() bool {
	return mi.Severity == "critical"
}

// IsHigh checks if the issue is high severity
func (mi *MeetingIssue) IsHigh() bool {
	return mi.Severity == "high"
}

// HasAttachments checks if the issue has attachments
func (mi *MeetingIssue) HasAttachments() bool {
	return len(mi.Attachments) > 0
}

// MarkAsResolved marks the issue as resolved
func (mi *MeetingIssue) MarkAsResolved(resolverID string, resolution string) {
	mi.Status = "resolved"
	mi.ResolvedBy = &resolverID
	mi.Resolution = &resolution
	now := time.Now()
	mi.ResolvedAt = &now
}

// ToTeamsFormat converts the issue to Teams-compatible format
func (mi *MeetingIssue) ToTeamsFormat() map[string]interface{} {
	return map[string]interface{}{
		"id":               mi.ID,
		"meetingId":        mi.MeetingID,
		"reportedBy":       mi.ReportedBy,
		"category":         mi.Category,
		"severity":         mi.Severity,
		"title":            mi.Title,
		"description":      mi.Description,
		"occurredAt":       mi.OccurredAt,
		"stepsToReproduce": mi.StepsToReproduce,
		"deviceInfo":       mi.DeviceInfo,
		"networkInfo":      mi.NetworkInfo,
		"attachments":      mi.Attachments,
		"status":           mi.Status,
		"resolution":       mi.Resolution,
		"resolvedBy":       mi.ResolvedBy,
		"resolvedAt":       mi.ResolvedAt,
		"tags":             mi.Tags,
		"metadata":         mi.Metadata,
		"isResolved":       mi.IsResolved(),
		"isCritical":       mi.IsCritical(),
		"isHigh":           mi.IsHigh(),
		"hasAttachments":   mi.HasAttachments(),
		"createdAt":        mi.CreatedAt,
		"updatedAt":        mi.UpdatedAt,
	}
}

// MeetingQualityMetric represents quality metrics for a meeting
type MeetingQualityMetric struct {
	BaseModel

	// Meeting ID these metrics belong to
	// @example "01HXYZ123456789ABCDEFGHIJK"
	MeetingID string `gorm:"not null;index" json:"meeting_id" example:"01HXYZ123456789ABCDEFGHIJK"`

	// User ID these metrics are for (optional, can be aggregate)
	// @example "01HXYZ123456789ABCDEFGHIJK"
	UserID *string `json:"user_id,omitempty" example:"01HXYZ123456789ABCDEFGHIJK"`

	// Metric type (audio, video, network, overall)
	// @example "audio"
	MetricType string `gorm:"not null" json:"metric_type" example:"audio"`

	// Overall quality score (1-5)
	// @example 4.2
	QualityScore float64 `json:"quality_score" example:"4.2"`

	// Average latency in milliseconds
	// @example 45
	AverageLatency *int `json:"average_latency,omitempty" example:"45"`

	// Packet loss percentage
	// @example 0.5
	PacketLoss *float64 `json:"packet_loss,omitempty" example:"0.5"`

	// Jitter in milliseconds
	// @example 12
	Jitter *int `json:"jitter,omitempty" example:"12"`

	// Bandwidth usage in kbps
	// @example 512
	Bandwidth *int `json:"bandwidth,omitempty" example:"512"`

	// Frame rate (for video)
	// @example 30
	FrameRate *int `json:"frame_rate,omitempty" example:"30"`

	// Resolution (for video)
	// @example "1080p"
	Resolution *string `json:"resolution,omitempty" example:"1080p"`

	// Number of disconnections
	// @example 2
	Disconnections *int `json:"disconnections,omitempty" example:"2"`

	// Number of reconnections
	// @example 1
	Reconnections *int `json:"reconnections,omitempty" example:"1"`

	// Audio bitrate
	// @example 64
	AudioBitrate *int `json:"audio_bitrate,omitempty" example:"64"`

	// Video bitrate
	// @example 1000
	VideoBitrate *int `json:"video_bitrate,omitempty" example:"1000"`

	// CPU usage percentage
	// @example 45.5
	CPUUsage *float64 `json:"cpu_usage,omitempty" example:"45.5"`

	// Memory usage in MB
	// @example 256
	MemoryUsage *int `json:"memory_usage,omitempty" example:"256"`

	// Network type (wifi, ethernet, cellular)
	// @example "wifi"
	NetworkType *string `json:"network_type,omitempty" example:"wifi"`

	// Additional metric data
	// @example {"echo_cancellation": true, "noise_suppression": true}
	MetricData map[string]interface{} `gorm:"type:jsonb" json:"metric_data,omitempty" example:"{\"echo_cancellation\": true, \"noise_suppression\": true}"`

	// When the metrics were recorded
	// @example "2024-01-15T10:30:00Z"
	RecordedAt time.Time `json:"recorded_at" example:"2024-01-15T10:30:00Z"`

	// Relationships
	// @Description Meeting these metrics belong to
	Meeting *Meeting `gorm:"foreignKey:MeetingID" json:"meeting,omitempty"`

	// @Description User these metrics are for
	User *User `gorm:"foreignKey:UserID" json:"user,omitempty"`
}

// TableName returns the table name for MeetingQualityMetric
func (MeetingQualityMetric) TableName() string {
	return "meeting_quality_metrics"
}

// IsGoodQuality checks if the quality score is good (>= 4.0)
func (mqm *MeetingQualityMetric) IsGoodQuality() bool {
	return mqm.QualityScore >= 4.0
}

// IsPoorQuality checks if the quality score is poor (<= 2.0)
func (mqm *MeetingQualityMetric) IsPoorQuality() bool {
	return mqm.QualityScore <= 2.0
}

// HasConnectionIssues checks if there were connection issues
func (mqm *MeetingQualityMetric) HasConnectionIssues() bool {
	return (mqm.Disconnections != nil && *mqm.Disconnections > 0) ||
		(mqm.PacketLoss != nil && *mqm.PacketLoss > 1.0)
}

// ToTeamsFormat converts the quality metric to Teams-compatible format
func (mqm *MeetingQualityMetric) ToTeamsFormat() map[string]interface{} {
	return map[string]interface{}{
		"id":                  mqm.ID,
		"meetingId":           mqm.MeetingID,
		"userId":              mqm.UserID,
		"metricType":          mqm.MetricType,
		"qualityScore":        mqm.QualityScore,
		"averageLatency":      mqm.AverageLatency,
		"packetLoss":          mqm.PacketLoss,
		"jitter":              mqm.Jitter,
		"bandwidth":           mqm.Bandwidth,
		"frameRate":           mqm.FrameRate,
		"resolution":          mqm.Resolution,
		"disconnections":      mqm.Disconnections,
		"reconnections":       mqm.Reconnections,
		"audioBitrate":        mqm.AudioBitrate,
		"videoBitrate":        mqm.VideoBitrate,
		"cpuUsage":            mqm.CPUUsage,
		"memoryUsage":         mqm.MemoryUsage,
		"networkType":         mqm.NetworkType,
		"metricData":          mqm.MetricData,
		"recordedAt":          mqm.RecordedAt,
		"isGoodQuality":       mqm.IsGoodQuality(),
		"isPoorQuality":       mqm.IsPoorQuality(),
		"hasConnectionIssues": mqm.HasConnectionIssues(),
		"createdAt":           mqm.CreatedAt,
		"updatedAt":           mqm.UpdatedAt,
	}
}
