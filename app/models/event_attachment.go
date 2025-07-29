package models

import (
	"time"
)

// EventAttachment represents a file attachment for calendar events
// @Description File attachment associated with calendar events
type EventAttachment struct {
	BaseModel
	// Event ID this attachment belongs to
	// @example 01HXYZ123456789ABCDEFGHIJK
	EventID string `gorm:"not null" json:"event_id" example:"01HXYZ123456789ABCDEFGHIJK"`

	// Original filename
	// @example "meeting-agenda.pdf"
	FileName string `gorm:"not null" json:"file_name" example:"meeting-agenda.pdf"`

	// File display name (can be different from filename)
	// @example "Meeting Agenda - Q1 Planning"
	DisplayName string `json:"display_name" example:"Meeting Agenda - Q1 Planning"`

	// File path in storage
	// @example "attachments/events/01HXYZ123456789ABCDEFGHIJK/meeting-agenda.pdf"
	FilePath string `gorm:"not null" json:"file_path" example:"attachments/events/01HXYZ123456789ABCDEFGHIJK/meeting-agenda.pdf"`

	// File size in bytes
	// @example 1048576
	FileSize int64 `json:"file_size" example:"1048576"`

	// MIME type
	// @example "application/pdf"
	MimeType string `json:"mime_type" example:"application/pdf"`

	// File extension
	// @example ".pdf"
	FileExtension string `json:"file_extension" example:".pdf"`

	// Upload status (pending, uploading, completed, failed)
	// @example "completed"
	UploadStatus string `gorm:"default:'pending'" json:"upload_status" example:"completed"`

	// Whether the file is publicly accessible
	// @example false
	IsPublic bool `gorm:"default:false" json:"is_public" example:"false"`

	// Download count
	// @example 15
	DownloadCount int `gorm:"default:0" json:"download_count" example:"15"`

	// File description/notes
	// @example "Agenda for Q1 planning meeting with key discussion points"
	Description string `json:"description" example:"Agenda for Q1 planning meeting with key discussion points"`

	// File tags as JSON array
	// @example ["agenda", "planning", "q1"]
	Tags string `json:"tags" example:"[\"agenda\", \"planning\", \"q1\"]"`

	// Virus scan status (pending, clean, infected, failed)
	// @example "clean"
	VirusScanStatus string `gorm:"default:'pending'" json:"virus_scan_status" example:"clean"`

	// When virus scan was completed
	// @example 2024-01-15T10:05:00Z
	VirusScanAt *time.Time `json:"virus_scan_at,omitempty" example:"2024-01-15T10:05:00Z"`

	// File hash for integrity verification
	// @example "sha256:a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3"
	FileHash string `json:"file_hash" example:"sha256:a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3"`

	// User who uploaded the file
	// @example 01HXYZ123456789ABCDEFGHIJK
	UploadedBy string `gorm:"not null" json:"uploaded_by" example:"01HXYZ123456789ABCDEFGHIJK"`

	// Expiration date for temporary attachments
	// @example 2024-12-31T23:59:59Z
	ExpiresAt *time.Time `json:"expires_at,omitempty" example:"2024-12-31T23:59:59Z"`

	// Organization ID for multi-tenancy
	// @example 01HXYZ123456789ABCDEFGHIJK
	organizationId string `gorm:"not null" json:"organization_id" example:"01HXYZ123456789ABCDEFGHIJK"`

	// Relationships
	// @Description Associated calendar event
	Event *CalendarEvent `gorm:"foreignKey:EventID" json:"event,omitempty"`

	// @Description User who uploaded the file
	Uploader *User `gorm:"foreignKey:UploadedBy" json:"uploader,omitempty"`

	// @Description Associated organization
	Organization *Organization `gorm:"foreignKey:OrganizationID" json:"organization,omitempty"`

	// @Description Access permissions for this attachment
	AccessPermissions []AttachmentPermission `gorm:"foreignKey:AttachmentID" json:"access_permissions,omitempty"`

	// @Description Download history
	DownloadHistory []AttachmentDownload `gorm:"foreignKey:AttachmentID" json:"download_history,omitempty"`
}

// AttachmentPermission represents access permissions for event attachments
// @Description Access control for event attachments
type AttachmentPermission struct {
	BaseModel
	// Attachment ID
	// @example 01HXYZ123456789ABCDEFGHIJK
	AttachmentID string `gorm:"not null" json:"attachment_id" example:"01HXYZ123456789ABCDEFGHIJK"`

	// User ID who has permission
	// @example 01HXYZ123456789ABCDEFGHIJK
	UserID string `gorm:"not null" json:"user_id" example:"01HXYZ123456789ABCDEFGHIJK"`

	// Permission type (view, download, edit, delete)
	// @example "download"
	Permission string `gorm:"not null" json:"permission" example:"download"`

	// Whether the permission is granted
	// @example true
	IsGranted bool `gorm:"default:true" json:"is_granted" example:"true"`

	// Permission source (direct, inherited, shared)
	// @example "inherited"
	Source string `gorm:"not null" json:"source" example:"inherited"`

	// Permission expiration
	// @example 2024-12-31T23:59:59Z
	ExpiresAt *time.Time `json:"expires_at,omitempty" example:"2024-12-31T23:59:59Z"`

	// Relationships
	// @Description Associated attachment
	Attachment *EventAttachment `gorm:"foreignKey:AttachmentID" json:"attachment,omitempty"`

	// @Description User with permission
	User *User `gorm:"foreignKey:UserID" json:"user,omitempty"`
}

// AttachmentDownload represents a download record for event attachments
// @Description Download history tracking for event attachments
type AttachmentDownload struct {
	BaseModel
	// Attachment ID
	// @example 01HXYZ123456789ABCDEFGHIJK
	AttachmentID string `gorm:"not null" json:"attachment_id" example:"01HXYZ123456789ABCDEFGHIJK"`

	// User who downloaded the file
	// @example 01HXYZ123456789ABCDEFGHIJK
	UserID string `gorm:"not null" json:"user_id" example:"01HXYZ123456789ABCDEFGHIJK"`

	// Download timestamp
	// @example 2024-01-15T10:30:00Z
	DownloadedAt time.Time `gorm:"not null" json:"downloaded_at" example:"2024-01-15T10:30:00Z"`

	// User's IP address
	// @example "192.168.1.100"
	IPAddress string `json:"ip_address" example:"192.168.1.100"`

	// User agent string
	// @example "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
	UserAgent string `json:"user_agent" example:"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"`

	// Download method (direct, email, share_link)
	// @example "direct"
	DownloadMethod string `json:"download_method" example:"direct"`

	// File size at time of download
	// @example 1048576
	FileSizeAtDownload int64 `json:"file_size_at_download" example:"1048576"`

	// Whether download completed successfully
	// @example true
	DownloadSuccessful bool `gorm:"default:true" json:"download_successful" example:"true"`

	// Relationships
	// @Description Associated attachment
	Attachment *EventAttachment `gorm:"foreignKey:AttachmentID" json:"attachment,omitempty"`

	// @Description User who downloaded
	User *User `gorm:"foreignKey:UserID" json:"user,omitempty"`
}

// SharedAttachmentLink represents a shareable link for event attachments
// @Description Shareable links for event attachments with access control
type SharedAttachmentLink struct {
	BaseModel
	// Attachment ID
	// @example 01HXYZ123456789ABCDEFGHIJK
	AttachmentID string `gorm:"not null" json:"attachment_id" example:"01HXYZ123456789ABCDEFGHIJK"`

	// Unique share token
	// @example "att_share_01HXYZ123456789ABCDEFGHIJK"
	ShareToken string `gorm:"not null;unique" json:"share_token" example:"att_share_01HXYZ123456789ABCDEFGHIJK"`

	// Link title/description
	// @example "Meeting Agenda - Shared Link"
	Title string `json:"title" example:"Meeting Agenda - Shared Link"`

	// Whether the link is active
	// @example true
	IsActive bool `gorm:"default:true" json:"is_active" example:"true"`

	// Whether the link requires password
	// @example false
	RequiresPassword bool `gorm:"default:false" json:"requires_password" example:"false"`

	// Password hash (if required)
	PasswordHash string `json:"-"`

	// Maximum number of downloads allowed
	// @example 10
	MaxDownloads *int `json:"max_downloads,omitempty" example:"10"`

	// Current download count
	// @example 3
	DownloadCount int `gorm:"default:0" json:"download_count" example:"3"`

	// Link expiration date
	// @example 2024-02-15T23:59:59Z
	ExpiresAt *time.Time `json:"expires_at,omitempty" example:"2024-02-15T23:59:59Z"`

	// User who created the share link
	// @example 01HXYZ123456789ABCDEFGHIJK
	CreatedBy string `gorm:"not null" json:"created_by" example:"01HXYZ123456789ABCDEFGHIJK"`

	// Last accessed timestamp
	// @example 2024-01-20T14:30:00Z
	LastAccessedAt *time.Time `json:"last_accessed_at,omitempty" example:"2024-01-20T14:30:00Z"`

	// Access restrictions as JSON
	// @example {"allowed_domains": ["company.com"], "ip_whitelist": ["192.168.1.0/24"]}
	AccessRestrictions string `json:"access_restrictions" example:"{\"allowed_domains\": [\"company.com\"], \"ip_whitelist\": [\"192.168.1.0/24\"]}"`

	// Relationships
	// @Description Associated attachment
	Attachment *EventAttachment `gorm:"foreignKey:AttachmentID" json:"attachment,omitempty"`

	// @Description User who created the link
	Creator *User `gorm:"foreignKey:CreatedBy" json:"creator,omitempty"`

	// @Description Access logs for this share link
	AccessLogs []SharedLinkAccess `gorm:"foreignKey:ShareLinkID" json:"access_logs,omitempty"`
}

// SharedLinkAccess represents access logs for shared attachment links
// @Description Access tracking for shared attachment links
type SharedLinkAccess struct {
	BaseModel
	// Share link ID
	// @example 01HXYZ123456789ABCDEFGHIJK
	ShareLinkID string `gorm:"not null" json:"share_link_id" example:"01HXYZ123456789ABCDEFGHIJK"`

	// Access timestamp
	// @example 2024-01-20T14:30:00Z
	AccessedAt time.Time `gorm:"not null" json:"accessed_at" example:"2024-01-20T14:30:00Z"`

	// Accessor's IP address
	// @example "203.0.113.100"
	IPAddress string `json:"ip_address" example:"203.0.113.100"`

	// User agent string
	// @example "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36"
	UserAgent string `json:"user_agent" example:"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36"`

	// Access type (view, download, failed_auth)
	// @example "download"
	AccessType string `gorm:"not null" json:"access_type" example:"download"`

	// Whether access was successful
	// @example true
	AccessSuccessful bool `gorm:"default:true" json:"access_successful" example:"true"`

	// Failure reason (if access failed)
	// @example "password_incorrect"
	FailureReason string `json:"failure_reason,omitempty" example:"password_incorrect"`

	// Referrer URL
	// @example "https://calendar.company.com/events/123"
	Referrer string `json:"referrer,omitempty" example:"https://calendar.company.com/events/123"`

	// Geographic location data as JSON
	// @example {"country": "US", "region": "CA", "city": "San Francisco"}
	LocationData string `json:"location_data" example:"{\"country\": \"US\", \"region\": \"CA\", \"city\": \"San Francisco\"}"`

	// Relationships
	// @Description Associated share link
	ShareLink *SharedAttachmentLink `gorm:"foreignKey:ShareLinkID" json:"share_link,omitempty"`
}

// AttachmentSummary represents a summary view of event attachments
// @Description Summary statistics for event attachments
type AttachmentSummary struct {
	// Event ID
	EventID string `json:"event_id"`

	// Total number of attachments
	TotalAttachments int `json:"total_attachments"`

	// Total size of all attachments in bytes
	TotalSize int64 `json:"total_size"`

	// Attachments grouped by type
	AttachmentsByType map[string]int `json:"attachments_by_type"`

	// Most downloaded attachment
	MostDownloaded *EventAttachment `json:"most_downloaded,omitempty"`

	// Recent uploads (last 7 days)
	RecentUploads int `json:"recent_uploads"`

	// Active share links count
	ActiveShareLinks int `json:"active_share_links"`
}
