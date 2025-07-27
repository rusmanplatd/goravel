package models

import (
	"time"
)

// MeetingPoll represents a poll in a meeting
type MeetingPoll struct {
	BaseModel
	// Meeting reference
	MeetingID string `gorm:"not null" json:"meeting_id"`

	// Poll creator
	CreatorID string `gorm:"not null" json:"creator_id"`

	// Poll title/question
	Title string `gorm:"not null" json:"title"`

	// Poll description
	Description string `json:"description"`

	// Poll type (single_choice, multiple_choice, rating, text)
	PollType string `gorm:"default:'single_choice'" json:"poll_type"`

	// Whether poll responses are anonymous
	IsAnonymous bool `gorm:"default:false" json:"is_anonymous"`

	// Whether participants can vote multiple times
	AllowMultipleVotes bool `gorm:"default:false" json:"allow_multiple_votes"`

	// Whether poll is currently active
	IsActive bool `gorm:"default:true" json:"is_active"`

	// When poll becomes active
	StartsAt *time.Time `json:"starts_at,omitempty"`

	// When poll closes
	EndsAt *time.Time `json:"ends_at,omitempty"`

	// Total number of votes
	TotalVotes int `gorm:"default:0" json:"total_votes"`

	// Additional poll settings as JSON
	Settings string `json:"settings"`

	// Relationships
	Meeting *Meeting            `gorm:"foreignKey:MeetingID" json:"meeting,omitempty"`
	Creator *User               `gorm:"foreignKey:CreatorID" json:"creator,omitempty"`
	Options []MeetingPollOption `gorm:"foreignKey:PollID" json:"options,omitempty"`
	Votes   []MeetingPollVote   `gorm:"foreignKey:PollID" json:"votes,omitempty"`
}

// MeetingPollOption represents an option in a poll
type MeetingPollOption struct {
	BaseModel
	// Poll reference
	PollID string `gorm:"not null" json:"poll_id"`

	// Option text/description
	OptionText string `gorm:"not null" json:"option_text"`

	// Number of votes for this option
	VoteCount int `gorm:"default:0" json:"vote_count"`

	// Display order of option
	OrderIndex int `gorm:"default:0" json:"order_index"`

	// Relationships
	Poll  *MeetingPoll      `gorm:"foreignKey:PollID" json:"poll,omitempty"`
	Votes []MeetingPollVote `gorm:"foreignKey:OptionID" json:"votes,omitempty"`
}

// MeetingPollVote represents a vote in a poll
type MeetingPollVote struct {
	BaseModel
	// Poll reference
	PollID string `gorm:"not null" json:"poll_id"`

	// Selected option reference (null for text responses)
	OptionID *string `json:"option_id,omitempty"`

	// Voter reference
	VoterID string `gorm:"not null" json:"voter_id"`

	// Text response for open-ended polls
	TextResponse string `json:"text_response"`

	// Rating value for rating polls
	RatingValue *int `json:"rating_value,omitempty"`

	// When vote was cast
	VotedAt time.Time `gorm:"autoCreateTime" json:"voted_at"`

	// Relationships
	Poll   *MeetingPoll       `gorm:"foreignKey:PollID" json:"poll,omitempty"`
	Option *MeetingPollOption `gorm:"foreignKey:OptionID" json:"option,omitempty"`
	Voter  *User              `gorm:"foreignKey:VoterID" json:"voter,omitempty"`
}

// TableName returns the table name for MeetingPoll
func (MeetingPoll) TableName() string {
	return "meeting_polls"
}

// TableName returns the table name for MeetingPollOption
func (MeetingPollOption) TableName() string {
	return "meeting_poll_options"
}

// TableName returns the table name for MeetingPollVote
func (MeetingPollVote) TableName() string {
	return "meeting_poll_votes"
}
