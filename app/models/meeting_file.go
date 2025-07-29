package models

import (
	"fmt"
	"time"
)

// MeetingFile represents a file shared in a meeting
type MeetingFile struct {
	BaseModel

	// Meeting ID that this file belongs to
	// @example "01HXYZ123456789ABCDEFGHIJK"
	MeetingID string `gorm:"not null;index" json:"meeting_id" example:"01HXYZ123456789ABCDEFGHIJK"`

	// User ID who uploaded the file
	// @example "01HXYZ123456789ABCDEFGHIJK"
	UploadedBy string `gorm:"not null" json:"uploaded_by" example:"01HXYZ123456789ABCDEFGHIJK"`

	// Chat message ID if file was shared via chat
	// @example "01HXYZ123456789ABCDEFGHIJK"
	MessageID *string `json:"message_id,omitempty" example:"01HXYZ123456789ABCDEFGHIJK"`

	// Original file name
	// @example "presentation.pptx"
	FileName string `gorm:"not null" json:"file_name" example:"presentation.pptx"`

	// File size in bytes
	// @example 2048576
	FileSize int64 `gorm:"not null" json:"file_size" example:"2048576"`

	// File MIME type
	// @example "application/vnd.openxmlformats-officedocument.presentationml.presentation"
	MimeType string `gorm:"not null" json:"mime_type" example:"application/vnd.openxmlformats-officedocument.presentationml.presentation"`

	// File storage path or URL
	// @example "/storage/meetings/01HXYZ123456789ABCDEFGHIJK/presentation.pptx"
	FilePath string `gorm:"not null" json:"file_path" example:"/storage/meetings/01HXYZ123456789ABCDEFGHIJK/presentation.pptx"`

	// Public download URL
	// @example "https://example.com/download/file_123"
	DownloadURL string `json:"download_url,omitempty" example:"https://example.com/download/file_123"`

	// Thumbnail URL for images/videos
	// @example "https://example.com/thumbnails/presentation_thumb.jpg"
	ThumbnailURL *string `json:"thumbnail_url,omitempty" example:"https://example.com/thumbnails/presentation_thumb.jpg"`

	// File description
	// @example "Q4 Sales Presentation"
	Description *string `json:"description,omitempty" example:"Q4 Sales Presentation"`

	// File category (document, image, video, audio, other)
	// @example "document"
	Category string `gorm:"default:'other'" json:"category" example:"document"`

	// File status (uploading, uploaded, processing, ready, error)
	// @example "ready"
	Status string `gorm:"default:'uploading'" json:"status" example:"ready"`

	// Whether the file is public (accessible to all meeting participants)
	// @example true
	IsPublic bool `gorm:"default:true" json:"is_public" example:"true"`

	// Whether the file is encrypted
	// @example false
	IsEncrypted bool `gorm:"default:false" json:"is_encrypted" example:"false"`

	// Encryption key ID (if encrypted)
	// @example "key_123"
	EncryptionKeyID *string `json:"encryption_key_id,omitempty" example:"key_123"`

	// File hash for integrity verification
	// @example "sha256:abcd1234..."
	FileHash string `json:"file_hash,omitempty" example:"sha256:abcd1234..."`

	// Number of downloads
	// @example 5
	DownloadCount int `gorm:"default:0" json:"download_count" example:"5"`

	// Last download time
	// @example "2024-01-15T10:20:00Z"
	LastDownloadAt *time.Time `json:"last_download_at,omitempty" example:"2024-01-15T10:20:00Z"`

	// File expiration time (for temporary files)
	// @example "2024-01-30T10:15:00Z"
	ExpiresAt *time.Time `json:"expires_at,omitempty" example:"2024-01-30T10:15:00Z"`

	// Whether the file has been scanned for viruses
	// @example true
	IsScanned bool `gorm:"default:false" json:"is_scanned" example:"true"`

	// Virus scan result (clean, infected, error)
	// @example "clean"
	ScanResult *string `json:"scan_result,omitempty" example:"clean"`

	// When the file was scanned
	// @example "2024-01-15T10:16:00Z"
	ScannedAt *time.Time `json:"scanned_at,omitempty" example:"2024-01-15T10:16:00Z"`

	// File metadata (dimensions, duration, etc.)
	// @example {"width": 1920, "height": 1080, "duration": 300}
	Metadata map[string]interface{} `gorm:"type:jsonb" json:"metadata,omitempty" example:"{\"width\": 1920, \"height\": 1080, \"duration\": 300}"`

	// Tags associated with the file
	// @example ["presentation", "sales", "q4"]
	Tags []string `gorm:"type:jsonb" json:"tags,omitempty" example:"presentation,sales,q4"`

	// Relationships
	// @Description Meeting this file belongs to
	Meeting *Meeting `gorm:"foreignKey:MeetingID" json:"meeting,omitempty"`

	// @Description User who uploaded the file
	Uploader *User `gorm:"foreignKey:UploadedBy" json:"uploader,omitempty"`

	// @Description Chat message this file was shared with (if applicable)
	Message *MeetingChat `gorm:"foreignKey:MessageID" json:"message,omitempty"`

	// @Description Download history
	Downloads []MeetingFileDownload `gorm:"foreignKey:FileID" json:"downloads,omitempty"`

	// @Description File sharing permissions
	Permissions []MeetingFilePermission `gorm:"foreignKey:FileID" json:"permissions,omitempty"`
}

// TableName returns the table name for MeetingFile
func (MeetingFile) TableName() string {
	return "meeting_files"
}

// IsImage checks if the file is an image
func (mf *MeetingFile) IsImage() bool {
	return mf.Category == "image" ||
		mf.MimeType == "image/jpeg" ||
		mf.MimeType == "image/png" ||
		mf.MimeType == "image/gif" ||
		mf.MimeType == "image/webp"
}

// IsVideo checks if the file is a video
func (mf *MeetingFile) IsVideo() bool {
	return mf.Category == "video" ||
		mf.MimeType == "video/mp4" ||
		mf.MimeType == "video/webm" ||
		mf.MimeType == "video/avi" ||
		mf.MimeType == "video/mov"
}

// IsDocument checks if the file is a document
func (mf *MeetingFile) IsDocument() bool {
	return mf.Category == "document" ||
		mf.MimeType == "application/pdf" ||
		mf.MimeType == "application/msword" ||
		mf.MimeType == "application/vnd.openxmlformats-officedocument.wordprocessingml.document" ||
		mf.MimeType == "application/vnd.ms-powerpoint" ||
		mf.MimeType == "application/vnd.openxmlformats-officedocument.presentationml.presentation"
}

// IsExpired checks if the file has expired
func (mf *MeetingFile) IsExpired() bool {
	if mf.ExpiresAt == nil {
		return false
	}
	return time.Now().After(*mf.ExpiresAt)
}

// IsReady checks if the file is ready for download
func (mf *MeetingFile) IsReady() bool {
	return mf.Status == "ready"
}

// HasThumbnail checks if the file has a thumbnail
func (mf *MeetingFile) HasThumbnail() bool {
	return mf.ThumbnailURL != nil && *mf.ThumbnailURL != ""
}

// IncrementDownloadCount increments the download counter
func (mf *MeetingFile) IncrementDownloadCount() {
	mf.DownloadCount++
	now := time.Now()
	mf.LastDownloadAt = &now
}

// MarkAsScanned marks the file as scanned with result
func (mf *MeetingFile) MarkAsScanned(result string) {
	mf.IsScanned = true
	mf.ScanResult = &result
	now := time.Now()
	mf.ScannedAt = &now
}

// GetFileExtension returns the file extension
func (mf *MeetingFile) GetFileExtension() string {
	for i := len(mf.FileName) - 1; i >= 0; i-- {
		if mf.FileName[i] == '.' {
			return mf.FileName[i+1:]
		}
	}
	return ""
}

// GetFormattedSize returns human-readable file size
func (mf *MeetingFile) GetFormattedSize() string {
	const unit = 1024
	if mf.FileSize < unit {
		return fmt.Sprintf("%d B", mf.FileSize)
	}
	div, exp := int64(unit), 0
	for n := mf.FileSize / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(mf.FileSize)/float64(div), "KMGTPE"[exp])
}

// ToTeamsFormat converts the file to Teams-compatible format
func (mf *MeetingFile) ToTeamsFormat() map[string]interface{} {
	return map[string]interface{}{
		"id":              mf.ID,
		"meetingId":       mf.MeetingID,
		"uploadedBy":      mf.UploadedBy,
		"messageId":       mf.MessageID,
		"fileName":        mf.FileName,
		"fileSize":        mf.FileSize,
		"formattedSize":   mf.GetFormattedSize(),
		"mimeType":        mf.MimeType,
		"filePath":        mf.FilePath,
		"downloadUrl":     mf.DownloadURL,
		"thumbnailUrl":    mf.ThumbnailURL,
		"description":     mf.Description,
		"category":        mf.Category,
		"status":          mf.Status,
		"isPublic":        mf.IsPublic,
		"isEncrypted":     mf.IsEncrypted,
		"encryptionKeyId": mf.EncryptionKeyID,
		"fileHash":        mf.FileHash,
		"downloadCount":   mf.DownloadCount,
		"lastDownloadAt":  mf.LastDownloadAt,
		"expiresAt":       mf.ExpiresAt,
		"isScanned":       mf.IsScanned,
		"scanResult":      mf.ScanResult,
		"scannedAt":       mf.ScannedAt,
		"metadata":        mf.Metadata,
		"tags":            mf.Tags,
		"fileExtension":   mf.GetFileExtension(),
		"isImage":         mf.IsImage(),
		"isVideo":         mf.IsVideo(),
		"isDocument":      mf.IsDocument(),
		"isExpired":       mf.IsExpired(),
		"isReady":         mf.IsReady(),
		"hasThumbnail":    mf.HasThumbnail(),
		"createdAt":       mf.CreatedAt,
		"updatedAt":       mf.UpdatedAt,
	}
}

// MeetingFileDownload represents a file download record
type MeetingFileDownload struct {
	BaseModel

	// File ID
	// @example "01HXYZ123456789ABCDEFGHIJK"
	FileID string `gorm:"not null;index" json:"file_id" example:"01HXYZ123456789ABCDEFGHIJK"`

	// User ID who downloaded the file
	// @example "01HXYZ123456789ABCDEFGHIJK"
	UserID string `gorm:"not null" json:"user_id" example:"01HXYZ123456789ABCDEFGHIJK"`

	// Download timestamp
	// @example "2024-01-15T10:20:00Z"
	DownloadedAt time.Time `json:"downloaded_at" example:"2024-01-15T10:20:00Z"`

	// User's IP address
	// @example "192.168.1.100"
	IPAddress string `json:"ip_address,omitempty" example:"192.168.1.100"`

	// User agent string
	// @example "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
	UserAgent string `json:"user_agent,omitempty" example:"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"`

	// Download success status
	// @example true
	IsSuccessful bool `gorm:"default:true" json:"is_successful" example:"true"`

	// Error message if download failed
	// @example "File not found"
	ErrorMessage *string `json:"error_message,omitempty" example:"File not found"`

	// Relationships
	// @Description File that was downloaded
	File *MeetingFile `gorm:"foreignKey:FileID" json:"file,omitempty"`

	// @Description User who downloaded the file
	User *User `gorm:"foreignKey:UserID" json:"user,omitempty"`
}

// TableName returns the table name for MeetingFileDownload
func (MeetingFileDownload) TableName() string {
	return "meeting_file_downloads"
}

// MeetingFilePermission represents file sharing permissions
type MeetingFilePermission struct {
	BaseModel

	// File ID
	// @example "01HXYZ123456789ABCDEFGHIJK"
	FileID string `gorm:"not null;index" json:"file_id" example:"01HXYZ123456789ABCDEFGHIJK"`

	// User ID with permission
	// @example "01HXYZ123456789ABCDEFGHIJK"
	UserID string `gorm:"not null" json:"user_id" example:"01HXYZ123456789ABCDEFGHIJK"`

	// Permission type (view, download, edit, delete)
	// @example "download"
	Permission string `gorm:"not null" json:"permission" example:"download"`

	// Whether the permission is granted
	// @example true
	IsGranted bool `gorm:"default:true" json:"is_granted" example:"true"`

	// Permission expiration time
	// @example "2024-01-30T10:15:00Z"
	ExpiresAt *time.Time `json:"expires_at,omitempty" example:"2024-01-30T10:15:00Z"`

	// User who granted the permission
	// @example "01HXYZ123456789ABCDEFGHIJK"
	GrantedBy string `gorm:"not null" json:"granted_by" example:"01HXYZ123456789ABCDEFGHIJK"`

	// When the permission was granted
	// @example "2024-01-15T10:15:00Z"
	GrantedAt time.Time `json:"granted_at" example:"2024-01-15T10:15:00Z"`

	// Relationships
	// @Description File this permission applies to
	File *MeetingFile `gorm:"foreignKey:FileID" json:"file,omitempty"`

	// @Description User with permission
	User *User `gorm:"foreignKey:UserID" json:"user,omitempty"`

	// @Description User who granted the permission
	Granter *User `gorm:"foreignKey:GrantedBy" json:"granter,omitempty"`
}

// TableName returns the table name for MeetingFilePermission
func (MeetingFilePermission) TableName() string {
	return "meeting_file_permissions"
}

// IsExpired checks if the permission has expired
func (mfp *MeetingFilePermission) IsExpired() bool {
	if mfp.ExpiresAt == nil {
		return false
	}
	return time.Now().After(*mfp.ExpiresAt)
}

// IsValid checks if the permission is valid (granted and not expired)
func (mfp *MeetingFilePermission) IsValid() bool {
	return mfp.IsGranted && !mfp.IsExpired()
}
