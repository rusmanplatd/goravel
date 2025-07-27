package models

// FolderActivity represents an activity on a folder
// @Description Folder activity model for audit trail
type FolderActivity struct {
	BaseModel
	// Activity type (create, rename, move, delete, share, etc.)
	// @example create
	Action string `gorm:"not null;index" json:"action" example:"create"`

	// Activity description
	// @example Folder created
	Description string `json:"description,omitempty" example:"Folder created"`

	// IP address of the user
	// @example 192.168.1.1
	IPAddress string `json:"ip_address,omitempty" example:"192.168.1.1"`

	// User agent
	// @example Mozilla/5.0...
	UserAgent string `json:"user_agent,omitempty" example:"Mozilla/5.0..."`

	// Additional metadata
	// @example {"old_name": "Old Folder", "new_name": "New Folder"}
	Metadata string `gorm:"type:json" json:"metadata,omitempty" example:"{\"old_name\": \"Old Folder\", \"new_name\": \"New Folder\"}"`

	// Folder ID the activity belongs to
	// @example 01HQZX1VQZX1VQZX1VQZX1VQZX
	FolderID string  `gorm:"not null;index" json:"folder_id" example:"01HQZX1VQZX1VQZX1VQZX1VQZX"`
	Folder   *Folder `gorm:"foreignKey:FolderID" json:"folder,omitempty"`

	// User who performed the activity
	// @example 01HQZX1VQZX1VQZX1VQZX1VQZX
	UserID *string `gorm:"index" json:"user_id,omitempty" example:"01HQZX1VQZX1VQZX1VQZX1VQZX"`
	User   *User   `gorm:"foreignKey:UserID" json:"user,omitempty"`

	// Tenant/Organization ID for multi-tenancy
	// @example 01HQZX1VQZX1VQZX1VQZX1VQZX
	TenantID *string `gorm:"index" json:"tenant_id,omitempty" example:"01HQZX1VQZX1VQZX1VQZX1VQZX"`
	Tenant   *Tenant `gorm:"foreignKey:TenantID" json:"tenant,omitempty"`
}

// TableName returns the table name for the FolderActivity model
func (FolderActivity) TableName() string {
	return "folder_activities"
}

// IsUserAction checks if the activity was performed by a user
func (fa *FolderActivity) IsUserAction() bool {
	return fa.UserID != nil
}

// IsSystemAction checks if the activity was performed by the system
func (fa *FolderActivity) IsSystemAction() bool {
	return fa.UserID == nil
}
