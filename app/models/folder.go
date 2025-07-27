package models

import (
	"time"
)

// Folder represents a folder in the drive system
// @Description Folder model for organizing files
type Folder struct {
	BaseModel
	// Folder name
	// @example Documents
	Name string `gorm:"not null" json:"name" example:"Documents"`

	// Folder description
	// @example Important project documents
	Description string `json:"description,omitempty" example:"Important project documents"`

	// Folder color (hex code)
	// @example #FF5722
	Color string `json:"color,omitempty" example:"#FF5722"`

	// Whether folder is public
	// @example false
	IsPublic bool `gorm:"default:false" json:"is_public" example:"false"`

	// Whether folder is starred/favorited
	// @example false
	IsStarred bool `gorm:"default:false" json:"is_starred" example:"false"`

	// Whether folder is in trash
	// @example false
	IsTrashed bool `gorm:"default:false" json:"is_trashed" example:"false"`

	// When folder was trashed
	// @example 2024-01-15T10:30:00Z
	TrashedAt *time.Time `json:"trashed_at,omitempty" example:"2024-01-15T10:30:00Z"`

	// Folder path (for breadcrumbs)
	// @example /Documents/Projects
	Path string `json:"path,omitempty" example:"/Documents/Projects"`

	// Folder level (depth in hierarchy)
	// @example 2
	Level int `gorm:"default:0" json:"level" example:"2"`

	// Sort order
	// @example 1
	SortOrder int `gorm:"default:0" json:"sort_order" example:"1"`

	// Ownership and relationships
	// Owner of the folder
	// @example 01HQZX1VQZX1VQZX1VQZX1VQZX
	OwnerID string `gorm:"not null;index" json:"owner_id" example:"01HQZX1VQZX1VQZX1VQZX1VQZX"`
	Owner   *User  `gorm:"foreignKey:OwnerID" json:"owner,omitempty"`

	// Parent folder ID (null for root folders)
	// @example 01HQZX1VQZX1VQZX1VQZX1VQZX
	ParentID *string `gorm:"index" json:"parent_id,omitempty" example:"01HQZX1VQZX1VQZX1VQZX1VQZX"`
	Parent   *Folder `gorm:"foreignKey:ParentID" json:"parent,omitempty"`

	// Tenant/Organization ID for multi-tenancy
	// @example 01HQZX1VQZX1VQZX1VQZX1VQZX
	TenantID *string `gorm:"index" json:"tenant_id,omitempty" example:"01HQZX1VQZX1VQZX1VQZX1VQZX"`
	Tenant   *Tenant `gorm:"foreignKey:TenantID" json:"tenant,omitempty"`

	// Relationships
	// Child folders
	Children []Folder `gorm:"foreignKey:ParentID" json:"children,omitempty"`

	// Files in this folder
	Files []File `gorm:"foreignKey:FolderID" json:"files,omitempty"`

	// Folder shares
	Shares []FolderShare `gorm:"foreignKey:FolderID" json:"shares,omitempty"`

	// Folder activities
	Activities []FolderActivity `gorm:"foreignKey:FolderID" json:"activities,omitempty"`
}

// TableName returns the table name for the Folder model
func (Folder) TableName() string {
	return "folders"
}

// GetFullPath returns the full path of the folder
func (f *Folder) GetFullPath() string {
	if f.Parent == nil {
		return "/" + f.Name
	}
	return f.Parent.GetFullPath() + "/" + f.Name
}

// IsRoot checks if folder is a root folder
func (f *Folder) IsRoot() bool {
	return f.ParentID == nil
}

// GetFileCount returns the number of files in the folder
func (f *Folder) GetFileCount() int {
	return len(f.Files)
}

// GetSubfolderCount returns the number of subfolders
func (f *Folder) GetSubfolderCount() int {
	return len(f.Children)
}

// GetTotalSize returns the total size of all files in the folder
func (f *Folder) GetTotalSize() int64 {
	var totalSize int64
	for _, file := range f.Files {
		totalSize += file.Size
	}
	return totalSize
}

// GetBreadcrumbs returns breadcrumb trail to this folder
func (f *Folder) GetBreadcrumbs() []Folder {
	var breadcrumbs []Folder
	current := f

	for current != nil {
		breadcrumbs = append([]Folder{*current}, breadcrumbs...)
		current = current.Parent
	}

	return breadcrumbs
}
