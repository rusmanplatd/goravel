package models

// FileActivity represents an activity on a file
// @Description File activity model for audit trail
type FileActivity struct {
	BaseModel
	// Activity type (upload, download, view, edit, delete, share, comment, etc.)
	// @example download
	Action string `gorm:"not null;index" json:"action" example:"download"`

	// Activity description
	// @example File downloaded
	Description string `json:"description,omitempty" example:"File downloaded"`

	// IP address of the user
	// @example 192.168.1.1
	IPAddress string `json:"ip_address,omitempty" example:"192.168.1.1"`

	// User agent
	// @example Mozilla/5.0...
	UserAgent string `json:"user_agent,omitempty" example:"Mozilla/5.0..."`

	// Additional metadata
	// @example {"file_size": 1048576, "download_method": "direct"}
	Metadata string `gorm:"type:json" json:"metadata,omitempty" example:"{\"file_size\": 1048576, \"download_method\": \"direct\"}"`

	// File ID the activity belongs to
	// @example 01HQZX1VQZX1VQZX1VQZX1VQZX
	FileID string `gorm:"not null;index" json:"file_id" example:"01HQZX1VQZX1VQZX1VQZX1VQZX"`
	File   *File  `gorm:"foreignKey:FileID" json:"file,omitempty"`

	// User who performed the activity
	// @example 01HQZX1VQZX1VQZX1VQZX1VQZX
	UserID *string `gorm:"index" json:"user_id,omitempty" example:"01HQZX1VQZX1VQZX1VQZX1VQZX"`
	User   *User   `gorm:"foreignKey:UserID" json:"user,omitempty"`

	// Tenant/Organization ID for multi-tenancy
	// @example 01HQZX1VQZX1VQZX1VQZX1VQZX
	TenantID *string `gorm:"index" json:"tenant_id,omitempty" example:"01HQZX1VQZX1VQZX1VQZX1VQZX"`
	Tenant   *Tenant `gorm:"foreignKey:TenantID" json:"tenant,omitempty"`
}

// TableName returns the table name for the FileActivity model
func (FileActivity) TableName() string {
	return "file_activities"
}

// IsUserAction checks if the activity was performed by a user
func (fa *FileActivity) IsUserAction() bool {
	return fa.UserID != nil
}

// IsSystemAction checks if the activity was performed by the system
func (fa *FileActivity) IsSystemAction() bool {
	return fa.UserID == nil
}
