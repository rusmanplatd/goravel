package models

// FileVersion represents a version of a file
// @Description File version model for version control
type FileVersion struct {
	BaseModel
	// Version number
	// @example 2
	Version int `gorm:"not null" json:"version" example:"2"`

	// File path on storage
	// @example files/2024/01/15/abc123_v2.pdf
	Path string `gorm:"not null" json:"path" example:"files/2024/01/15/abc123_v2.pdf"`

	// File size in bytes
	// @example 1048576
	Size int64 `gorm:"not null" json:"size" example:"1048576"`

	// File hash
	// @example sha256:def456abc123
	Hash string `gorm:"index" json:"hash" example:"sha256:def456abc123"`

	// Version comment/description
	// @example Updated with corrections
	Comment string `json:"comment,omitempty" example:"Updated with corrections"`

	// Whether this is the current version
	// @example true
	IsCurrent bool `gorm:"default:false" json:"is_current" example:"true"`

	// Storage provider
	// @example minio
	StorageProvider string `gorm:"default:minio" json:"storage_provider" example:"minio"`

	// File ID this version belongs to
	// @example 01HQZX1VQZX1VQZX1VQZX1VQZX
	FileID string `gorm:"not null;index" json:"file_id" example:"01HQZX1VQZX1VQZX1VQZX1VQZX"`
	File   *File  `gorm:"foreignKey:FileID" json:"file,omitempty"`

	// User who created this version
	// @example 01HQZX1VQZX1VQZX1VQZX1VQZX
	CreatedByID string `gorm:"not null;index" json:"created_by_id" example:"01HQZX1VQZX1VQZX1VQZX1VQZX"`
	CreatedBy   *User  `gorm:"foreignKey:CreatedByID" json:"created_by,omitempty"`
}

// TableName returns the table name for the FileVersion model
func (FileVersion) TableName() string {
	return "file_versions"
}
