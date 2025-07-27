package requests

import (
	"time"

	"github.com/goravel/framework/contracts/http"
	"github.com/goravel/framework/contracts/validation"
)

// FileUploadRequest validates file upload requests
// @Description Request model for file upload validation
type FileUploadRequest struct {
	// Folder ID to upload file to (optional)
	// @example 01HXYZ123456789ABCDEFGHIJK
	FolderID *string `form:"folder_id" json:"folder_id" example:"01HXYZ123456789ABCDEFGHIJK"`
}

func (r *FileUploadRequest) Authorize(ctx http.Context) error {
	return nil
}

func (r *FileUploadRequest) Rules(ctx http.Context) map[string]string {
	return map[string]string{
		"folder_id": "sometimes|string",
	}
}

func (r *FileUploadRequest) Messages(ctx http.Context) map[string]string {
	return map[string]string{}
}

func (r *FileUploadRequest) Attributes(ctx http.Context) map[string]string {
	return map[string]string{}
}

func (r *FileUploadRequest) PrepareForValidation(ctx http.Context, data validation.Data) error {
	return nil
}

// CreateFolderRequest validates folder creation requests
// @Description Request model for folder creation validation
type CreateFolderRequest struct {
	// Folder name
	// @example My Documents
	Name string `form:"name" json:"name" example:"My Documents"`

	// Parent folder ID (optional)
	// @example 01HXYZ123456789ABCDEFGHIJK
	ParentID *string `form:"parent_id" json:"parent_id" example:"01HXYZ123456789ABCDEFGHIJK"`

	// Folder description
	// @example Important documents folder
	Description string `form:"description" json:"description" example:"Important documents folder"`

	// Folder color for UI
	// @example #3B82F6
	Color string `form:"color" json:"color" example:"#3B82F6"`
}

func (r *CreateFolderRequest) Authorize(ctx http.Context) error {
	return nil
}

func (r *CreateFolderRequest) Rules(ctx http.Context) map[string]string {
	return map[string]string{
		"name":        "required|string|max:255",
		"parent_id":   "sometimes|string",
		"description": "sometimes|string|max:1000",
		"color":       "sometimes|string|regex:^#[0-9A-Fa-f]{6}$",
	}
}

func (r *CreateFolderRequest) Messages(ctx http.Context) map[string]string {
	return map[string]string{
		"name.required":   "Folder name is required",
		"name.max":        "Folder name cannot exceed 255 characters",
		"color.regex":     "Color must be a valid hex color code",
		"description.max": "Description cannot exceed 1000 characters",
	}
}

func (r *CreateFolderRequest) Attributes(ctx http.Context) map[string]string {
	return map[string]string{}
}

func (r *CreateFolderRequest) PrepareForValidation(ctx http.Context, data validation.Data) error {
	return nil
}

// ShareFileRequest validates file sharing requests
type ShareFileRequest struct {
	ShareType       string     `form:"share_type" json:"share_type"`
	Permission      string     `form:"permission" json:"permission"`
	Email           string     `form:"email" json:"email"`
	Message         string     `form:"message" json:"message"`
	ExpiresAt       *time.Time `form:"expires_at" json:"expires_at"`
	RequirePassword bool       `form:"require_password" json:"require_password"`
	Password        string     `form:"password" json:"password"`
}

func (r *ShareFileRequest) Authorize(ctx http.Context) error {
	return nil
}

func (r *ShareFileRequest) Rules(ctx http.Context) map[string]string {
	return map[string]string{
		"share_type":       "required|in:user,link,email",
		"permission":       "required|in:view,edit,comment,owner",
		"email":            "required_if:share_type,email|email",
		"message":          "sometimes|string|max:1000",
		"expires_at":       "sometimes|date|after:now",
		"require_password": "sometimes|boolean",
		"password":         "required_if:require_password,true|min:6",
	}
}

func (r *ShareFileRequest) Messages(ctx http.Context) map[string]string {
	return map[string]string{
		"share_type.required":  "Share type is required",
		"share_type.in":        "Share type must be user, link, or email",
		"permission.required":  "Permission level is required",
		"permission.in":        "Permission must be view, edit, comment, or owner",
		"email.required_if":    "Email is required for email sharing",
		"email.email":          "Email must be a valid email address",
		"expires_at.after":     "Expiration date must be in the future",
		"password.required_if": "Password is required when password protection is enabled",
		"password.min":         "Password must be at least 6 characters",
	}
}

func (r *ShareFileRequest) Attributes(ctx http.Context) map[string]string {
	return map[string]string{}
}

func (r *ShareFileRequest) PrepareForValidation(ctx http.Context, data validation.Data) error {
	return nil
}

// MoveFileRequest validates file move requests
type MoveFileRequest struct {
	FolderID *string `form:"folder_id" json:"folder_id"`
}

func (r *MoveFileRequest) Authorize(ctx http.Context) error {
	return nil
}

func (r *MoveFileRequest) Rules(ctx http.Context) map[string]string {
	return map[string]string{
		"folder_id": "sometimes|string",
	}
}

func (r *MoveFileRequest) Messages(ctx http.Context) map[string]string {
	return map[string]string{}
}

func (r *MoveFileRequest) Attributes(ctx http.Context) map[string]string {
	return map[string]string{}
}

func (r *MoveFileRequest) PrepareForValidation(ctx http.Context, data validation.Data) error {
	return nil
}
