package models

import (
	"fmt"
	"time"
)

// File represents a file in the drive system
// @Description File model for Google Drive-like functionality
type File struct {
	BaseModel
	// File name
	// @example document.pdf
	Name string `gorm:"not null" json:"name" example:"document.pdf"`

	// Original filename when uploaded
	// @example my-document.pdf
	OriginalName string `gorm:"not null" json:"original_name" example:"my-document.pdf"`

	// File path on storage
	// @example files/2024/01/15/abc123.pdf
	Path string `gorm:"not null" json:"path" example:"files/2024/01/15/abc123.pdf"`

	// File size in bytes
	// @example 1048576
	Size int64 `gorm:"not null" json:"size" example:"1048576"`

	// MIME type
	// @example application/pdf
	MimeType string `gorm:"not null" json:"mime_type" example:"application/pdf"`

	// File extension
	// @example pdf
	Extension string `json:"extension" example:"pdf"`

	// File hash for deduplication
	// @example sha256:abc123def456
	Hash string `gorm:"index" json:"hash" example:"sha256:abc123def456"`

	// Storage provider
	// @example minio
	StorageProvider string `gorm:"default:minio" json:"storage_provider" example:"minio"`

	// File description
	// @example Important project document
	Description string `json:"description,omitempty" example:"Important project document"`

	// File tags
	// @example ["work", "project", "important"]
	Tags string `gorm:"type:json" json:"tags,omitempty" example:"[\"work\", \"project\", \"important\"]"`

	// File metadata
	// @example {"width": 1920, "height": 1080}
	Metadata string `gorm:"type:json" json:"metadata,omitempty" example:"{\"width\": 1920, \"height\": 1080}"`

	// Whether file is public
	// @example false
	IsPublic bool `gorm:"default:false" json:"is_public" example:"false"`

	// Whether file is starred/favorited
	// @example false
	IsStarred bool `gorm:"default:false" json:"is_starred" example:"false"`

	// Whether file is in trash
	// @example false
	IsTrashed bool `gorm:"default:false" json:"is_trashed" example:"false"`

	// When file was trashed
	// @example 2024-01-15T10:30:00Z
	TrashedAt *time.Time `json:"trashed_at,omitempty" example:"2024-01-15T10:30:00Z"`

	// File status (active, processing, failed, deleted)
	// @example active
	Status string `gorm:"default:active" json:"status" example:"active"`

	// Download count
	// @example 5
	DownloadCount int64 `gorm:"default:0" json:"download_count" example:"5"`

	// View count
	// @example 10
	ViewCount int64 `gorm:"default:0" json:"view_count" example:"10"`

	// Last accessed time
	// @example 2024-01-15T10:30:00Z
	LastAccessedAt *time.Time `json:"last_accessed_at,omitempty" example:"2024-01-15T10:30:00Z"`

	// Virus scan status
	// @example clean
	VirusScanStatus string `gorm:"default:pending" json:"virus_scan_status" example:"clean"`

	// Virus scan result
	// @example No threats detected
	VirusScanResult string `json:"virus_scan_result,omitempty" example:"No threats detected"`

	// When virus scan was performed
	// @example 2024-01-15T10:30:00Z
	VirusScannedAt *time.Time `json:"virus_scanned_at,omitempty" example:"2024-01-15T10:30:00Z"`

	// Ownership and relationships
	// Owner of the file
	// @example 01HQZX1VQZX1VQZX1VQZX1VQZX
	OwnerID string `gorm:"not null;index" json:"owner_id" example:"01HQZX1VQZX1VQZX1VQZX1VQZX"`
	Owner   *User  `gorm:"foreignKey:OwnerID" json:"owner,omitempty"`

	// Parent folder ID (null for root files)
	// @example 01HQZX1VQZX1VQZX1VQZX1VQZX
	FolderID *string `gorm:"index" json:"folder_id,omitempty" example:"01HQZX1VQZX1VQZX1VQZX1VQZX"`
	Folder   *Folder `gorm:"foreignKey:FolderID" json:"folder,omitempty"`

	// Organization/Organization ID for multi-tenancy
	// @example 01HQZX1VQZX1VQZX1VQZX1VQZX
	OrganizationID *string       `gorm:"index" json:"organization_id,omitempty" example:"01HQZX1VQZX1VQZX1VQZX1VQZX"`
	Organization   *Organization `gorm:"foreignKey:OrganizationID" json:"organization,omitempty"`

	// Relationships
	// File versions
	Versions []FileVersion `gorm:"foreignKey:FileID" json:"versions,omitempty"`

	// File shares
	Shares []FileShare `gorm:"foreignKey:FileID" json:"shares,omitempty"`

	// File comments
	Comments []FileComment `gorm:"foreignKey:FileID" json:"comments,omitempty"`

	// File activities
	Activities []FileActivity `gorm:"foreignKey:FileID" json:"activities,omitempty"`
}

// TableName returns the table name for the File model
func (File) TableName() string {
	return "files"
}

// GetPublicURL returns public URL for the file
func (f *File) GetPublicURL() string {
	if f.IsPublic {
		return "/api/v1/drive/files/" + f.ID + "/download"
	}
	return ""
}

// GetPreviewURL returns preview URL for the file
func (f *File) GetPreviewURL() string {
	return "/api/v1/drive/files/" + f.ID + "/preview"
}

// IsImage checks if file is an image
func (f *File) IsImage() bool {
	switch f.MimeType {
	case "image/jpeg", "image/jpg", "image/png", "image/gif", "image/webp", "image/svg+xml":
		return true
	}
	return false
}

// IsVideo checks if file is a video
func (f *File) IsVideo() bool {
	switch f.MimeType {
	case "video/mp4", "video/webm", "video/ogg", "video/avi", "video/mov":
		return true
	}
	return false
}

// IsAudio checks if file is audio
func (f *File) IsAudio() bool {
	switch f.MimeType {
	case "audio/mp3", "audio/wav", "audio/ogg", "audio/m4a", "audio/flac":
		return true
	}
	return false
}

// IsDocument checks if file is a document
func (f *File) IsDocument() bool {
	switch f.MimeType {
	case "application/pdf", "application/msword", "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
		"application/vnd.ms-excel", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
		"application/vnd.ms-powerpoint", "application/vnd.openxmlformats-officedocument.presentationml.presentation",
		"text/plain", "text/csv":
		return true
	}
	return false
}

// FormatSize returns human-readable file size
func (f *File) FormatSize() string {
	const unit = 1024
	if f.Size < unit {
		return fmt.Sprintf("%d B", f.Size)
	}
	div, exp := int64(unit), 0
	for n := f.Size / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(f.Size)/float64(div), "KMGTPE"[exp])
}
