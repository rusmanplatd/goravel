package models

import (
	"time"
)

// FileComment represents a comment on a file
// @Description File comment model for collaboration
type FileComment struct {
	BaseModel
	// Comment content
	// @example This looks good, but please update the conclusion
	Content string `gorm:"not null" json:"content" example:"This looks good, but please update the conclusion"`

	// Whether comment is resolved
	// @example false
	IsResolved bool `gorm:"default:false" json:"is_resolved" example:"false"`

	// When comment was resolved
	// @example 2024-01-15T10:30:00Z
	ResolvedAt *time.Time `json:"resolved_at,omitempty" example:"2024-01-15T10:30:00Z"`

	// Comment position/anchor (for document comments)
	// @example {"page": 1, "x": 100, "y": 200}
	Position string `gorm:"type:json" json:"position,omitempty" example:"{\"page\": 1, \"x\": 100, \"y\": 200}"`

	// File ID the comment belongs to
	// @example 01HQZX1VQZX1VQZX1VQZX1VQZX
	FileID string `gorm:"not null;index" json:"file_id" example:"01HQZX1VQZX1VQZX1VQZX1VQZX"`
	File   *File  `gorm:"foreignKey:FileID" json:"file,omitempty"`

	// User who created the comment
	// @example 01HQZX1VQZX1VQZX1VQZX1VQZX
	AuthorID string `gorm:"not null;index" json:"author_id" example:"01HQZX1VQZX1VQZX1VQZX1VQZX"`
	Author   *User  `gorm:"foreignKey:AuthorID" json:"author,omitempty"`

	// Parent comment ID (for replies)
	// @example 01HQZX1VQZX1VQZX1VQZX1VQZX
	ParentID *string      `gorm:"index" json:"parent_id,omitempty" example:"01HQZX1VQZX1VQZX1VQZX1VQZX"`
	Parent   *FileComment `gorm:"foreignKey:ParentID" json:"parent,omitempty"`

	// Reply comments
	Replies []FileComment `gorm:"foreignKey:ParentID" json:"replies,omitempty"`

	// User who resolved the comment
	// @example 01HQZX1VQZX1VQZX1VQZX1VQZX
	ResolvedByID *string `gorm:"index" json:"resolved_by_id,omitempty" example:"01HQZX1VQZX1VQZX1VQZX1VQZX"`
	ResolvedBy   *User   `gorm:"foreignKey:ResolvedByID" json:"resolved_by,omitempty"`
}

// TableName returns the table name for the FileComment model
func (FileComment) TableName() string {
	return "file_comments"
}

// IsReply checks if this is a reply to another comment
func (fc *FileComment) IsReply() bool {
	return fc.ParentID != nil
}

// GetReplyCount returns the number of replies to this comment
func (fc *FileComment) GetReplyCount() int {
	return len(fc.Replies)
}
