package services

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"goravel/app/models"
	"image"
	"image/jpeg"
	"image/png"
	"io"
	"mime"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/disintegration/imaging"
	"github.com/google/uuid"
	"github.com/goravel/framework/facades"
)

// DriveService handles Google Drive-like file operations
type DriveService struct {
	storageService *StorageService
	auditService   *AuditService
	auditHelper    *AuditHelper
}

// PreviewConfig holds configuration for file previews
type PreviewConfig struct {
	ThumbnailWidth  int
	ThumbnailHeight int
	PreviewWidth    int
	PreviewHeight   int
	Quality         int
}

// NewDriveService creates a new drive service
func NewDriveService() *DriveService {
	auditService := GetAuditService()
	return &DriveService{
		storageService: NewStorageService(),
		auditService:   auditService,
		auditHelper:    NewAuditHelper(auditService),
	}
}

// GetPreviewConfig returns default preview configuration
func (ds *DriveService) GetPreviewConfig() *PreviewConfig {
	return &PreviewConfig{
		ThumbnailWidth:  200,
		ThumbnailHeight: 200,
		PreviewWidth:    800,
		PreviewHeight:   600,
		Quality:         85,
	}
}

// GenerateThumbnail generates a thumbnail for supported file types
func (ds *DriveService) GenerateThumbnail(ctx context.Context, file *models.File) error {
	if !file.IsImage() && !file.IsVideo() {
		return nil // Skip non-media files
	}

	config := ds.GetPreviewConfig()

	// Get original file content
	_, content, err := ds.storageService.Get(ctx, file.ID)
	if err != nil {
		return fmt.Errorf("failed to get file content: %v", err)
	}
	defer content.Close()

	var thumbnailData []byte

	if file.IsImage() {
		thumbnailData, err = ds.generateImageThumbnail(content, config)
	} else if file.IsVideo() {
		thumbnailData, err = ds.generateVideoThumbnail(file.Path, config)
	}

	if err != nil {
		return fmt.Errorf("failed to generate thumbnail: %v", err)
	}

	// Store thumbnail
	thumbnailPath := fmt.Sprintf("thumbnails/%s_thumb.jpg", file.ID)
	thumbnailReader := bytes.NewReader(thumbnailData)

	metadata := map[string]interface{}{
		"original_file_id": file.ID,
		"type":             "thumbnail",
	}

	_, err = ds.storageService.Store(ctx, thumbnailPath, thumbnailReader, metadata)
	if err != nil {
		return fmt.Errorf("failed to store thumbnail: %v", err)
	}

	// Update file record with thumbnail path
	file.Metadata = fmt.Sprintf(`{"thumbnail_path": "%s"}`, thumbnailPath)
	facades.Orm().Query().Save(file)

	return nil
}

// generateImageThumbnail creates a thumbnail from an image
func (ds *DriveService) generateImageThumbnail(content io.Reader, config *PreviewConfig) ([]byte, error) {
	// Decode image
	img, _, err := image.Decode(content)
	if err != nil {
		return nil, fmt.Errorf("failed to decode image: %v", err)
	}

	// Resize to thumbnail size
	thumbnail := imaging.Thumbnail(img, config.ThumbnailWidth, config.ThumbnailHeight, imaging.Lanczos)

	// Encode as JPEG
	var buf bytes.Buffer
	err = jpeg.Encode(&buf, thumbnail, &jpeg.Options{Quality: config.Quality})
	if err != nil {
		return nil, fmt.Errorf("failed to encode thumbnail: %v", err)
	}

	return buf.Bytes(), nil
}

// generateVideoThumbnail creates a thumbnail from a video using ffmpeg
func (ds *DriveService) generateVideoThumbnail(videoPath string, config *PreviewConfig) ([]byte, error) {
	// Use ffmpeg to extract a frame at 1 second
	cmd := exec.Command("ffmpeg",
		"-i", videoPath,
		"-ss", "00:00:01.000",
		"-vframes", "1",
		"-f", "image2pipe",
		"-vcodec", "png",
		"-")

	var out bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		return nil, fmt.Errorf("ffmpeg error: %v, stderr: %s", err, stderr.String())
	}

	// Decode the PNG frame
	img, err := png.Decode(&out)
	if err != nil {
		return nil, fmt.Errorf("failed to decode video frame: %v", err)
	}

	// Resize to thumbnail size
	thumbnail := imaging.Thumbnail(img, config.ThumbnailWidth, config.ThumbnailHeight, imaging.Lanczos)

	// Encode as JPEG
	var buf bytes.Buffer
	err = jpeg.Encode(&buf, thumbnail, &jpeg.Options{Quality: config.Quality})
	if err != nil {
		return nil, fmt.Errorf("failed to encode video thumbnail: %v", err)
	}

	return buf.Bytes(), nil
}

// GetFilePreview returns a preview-sized version of the file
func (ds *DriveService) GetFilePreview(ctx context.Context, fileID string, userID *string) (*models.File, io.ReadCloser, error) {
	// Get file record
	var file models.File
	if err := facades.Orm().Query().Find(&file, fileID); err != nil {
		return nil, nil, fmt.Errorf("file not found: %v", err)
	}

	// Check access permissions
	if !ds.CanAccessFile(&file, userID) {
		return nil, nil, fmt.Errorf("access denied")
	}

	// For images, generate preview if not exists
	if file.IsImage() {
		previewPath := fmt.Sprintf("previews/%s_preview.jpg", file.ID)

		// Try to get existing preview
		_, previewContent, err := ds.storageService.Get(ctx, previewPath)
		if err == nil {
			return &file, previewContent, nil
		}

		// Generate preview
		err = ds.generatePreview(ctx, &file)
		if err != nil {
			// Fall back to original file
			_, content, err := ds.storageService.Get(ctx, file.ID)
			return &file, content, err
		}

		// Get the generated preview
		_, previewContent, err = ds.storageService.Get(ctx, previewPath)
		return &file, previewContent, err
	}

	// For non-images, return original file
	_, content, err := ds.storageService.Get(ctx, file.ID)
	return &file, content, err
}

// generatePreview creates a preview-sized version of an image
func (ds *DriveService) generatePreview(ctx context.Context, file *models.File) error {
	if !file.IsImage() {
		return nil
	}

	config := ds.GetPreviewConfig()

	// Get original file content
	_, content, err := ds.storageService.Get(ctx, file.ID)
	if err != nil {
		return fmt.Errorf("failed to get file content: %v", err)
	}
	defer content.Close()

	// Decode image
	img, _, err := image.Decode(content)
	if err != nil {
		return fmt.Errorf("failed to decode image: %v", err)
	}

	// Resize to preview size
	preview := imaging.Resize(img, config.PreviewWidth, config.PreviewHeight, imaging.Lanczos)

	// Encode as JPEG
	var buf bytes.Buffer
	err = jpeg.Encode(&buf, preview, &jpeg.Options{Quality: config.Quality})
	if err != nil {
		return fmt.Errorf("failed to encode preview: %v", err)
	}

	// Store preview
	previewPath := fmt.Sprintf("previews/%s_preview.jpg", file.ID)
	previewReader := bytes.NewReader(buf.Bytes())

	metadata := map[string]interface{}{
		"original_file_id": file.ID,
		"type":             "preview",
	}

	_, err = ds.storageService.Store(ctx, previewPath, previewReader, metadata)
	return err
}

// UploadFile uploads a file to the drive
func (ds *DriveService) UploadFile(ctx context.Context, userID string, folderID *string, filename string, content io.Reader, size int64, tenantID *string) (*models.File, error) {
	// Check storage quota before upload
	if err := ds.CheckStorageQuota(ctx, userID, size); err != nil {
		return nil, fmt.Errorf("storage quota exceeded: %v", err)
	}

	// Calculate file hash
	hash, err := ds.calculateHash(content)
	if err != nil {
		return nil, fmt.Errorf("failed to calculate file hash: %v", err)
	}

	// Check if file with same hash already exists for this user
	var existingFile models.File
	query := facades.Orm().Query().Where("owner_id", userID).Where("hash", hash)
	if err := query.First(&existingFile); err == nil {
		// File already exists, create a new version instead
		return ds.CreateFileVersion(ctx, existingFile.ID, userID, content, size, "Duplicate upload")
	}

	// Get file extension and MIME type
	ext := strings.ToLower(filepath.Ext(filename))
	mimeType := ds.detectMimeType(filename)

	// Store file using storage service
	metadata := map[string]interface{}{
		"original_name": filename,
		"uploaded_by":   userID,
		"folder_id":     folderID,
	}

	fileInfo, err := ds.storageService.Store(ctx, filename, content, metadata)
	if err != nil {
		return nil, fmt.Errorf("failed to store file: %v", err)
	}

	// Create file record
	file := &models.File{
		Name:            ds.generateUniqueFilename(filename, userID, folderID),
		OriginalName:    filename,
		Path:            fileInfo.Path,
		Size:            size,
		MimeType:        mimeType,
		Extension:       strings.TrimPrefix(ext, "."),
		Hash:            hash,
		StorageProvider: fileInfo.Metadata["storage_provider"].(string),
		Status:          "active",
		OwnerID:         userID,
		FolderID:        folderID,
		TenantID:        tenantID,
	}

	if err := facades.Orm().Query().Create(&file); err != nil {
		// Clean up stored file if database insert fails
		ds.storageService.Delete(ctx, fileInfo.ID)
		return nil, fmt.Errorf("failed to create file record: %v", err)
	}

	// Log activity
	ds.logFileActivity(file.ID, userID, "upload", "File uploaded", ctx)

	// Generate thumbnail asynchronously for media files
	go func() {
		if err := ds.GenerateThumbnail(context.Background(), file); err != nil {
			facades.Log().Warning("Failed to generate thumbnail", map[string]interface{}{
				"file_id": file.ID,
				"error":   err.Error(),
			})
		}
	}()

	return file, nil
}

// CreateFolder creates a new folder
func (ds *DriveService) CreateFolder(ctx context.Context, userID string, parentID *string, name string, tenantID *string) (*models.Folder, error) {
	// Check if folder with same name exists in parent
	query := facades.Orm().Query().Where("owner_id", userID).Where("name", name)
	if parentID != nil {
		query = query.Where("parent_id", *parentID)
	} else {
		query = query.WhereNull("parent_id")
	}

	var existingFolder models.Folder
	if err := query.First(&existingFolder); err == nil {
		return nil, fmt.Errorf("folder with name '%s' already exists", name)
	}

	// Calculate folder level and path
	level := 0
	path := "/" + name
	if parentID != nil {
		var parent models.Folder
		if err := facades.Orm().Query().Find(&parent, *parentID); err != nil {
			return nil, fmt.Errorf("parent folder not found: %v", err)
		}
		level = parent.Level + 1
		path = parent.Path + "/" + name
	}

	// Create folder record
	folder := &models.Folder{
		Name:     name,
		Path:     path,
		Level:    level,
		OwnerID:  userID,
		ParentID: parentID,
		TenantID: tenantID,
	}

	if err := facades.Orm().Query().Create(&folder); err != nil {
		return nil, fmt.Errorf("failed to create folder: %v", err)
	}

	// Log activity
	ds.logFolderActivity(folder.ID, userID, "create", "Folder created", ctx)

	return folder, nil
}

// GetFiles retrieves files in a folder
func (ds *DriveService) GetFiles(userID string, folderID *string, page, limit int, search string) ([]models.File, int64, error) {
	query := facades.Orm().Query().Where("owner_id", userID).Where("is_trashed", false)

	if folderID != nil {
		query = query.Where("folder_id", *folderID)
	} else {
		query = query.WhereNull("folder_id")
	}

	if search != "" {
		query = query.Where("name", "LIKE", "%"+search+"%")
	}

	// Get total count
	total, _ := query.Count()

	// Get paginated results
	var files []models.File
	offset := (page - 1) * limit
	err := query.With("Owner").With("Folder").Offset(offset).Limit(limit).OrderBy("created_at", "desc").Find(&files)

	return files, total, err
}

// GetFolders retrieves folders in a parent folder
func (ds *DriveService) GetFolders(userID string, parentID *string, page, limit int, search string) ([]models.Folder, int64, error) {
	query := facades.Orm().Query().Where("owner_id", userID).Where("is_trashed", false)

	if parentID != nil {
		query = query.Where("parent_id", *parentID)
	} else {
		query = query.WhereNull("parent_id")
	}

	if search != "" {
		query = query.Where("name", "LIKE", "%"+search+"%")
	}

	// Get total count
	total, _ := query.Count()

	// Get paginated results
	var folders []models.Folder
	offset := (page - 1) * limit
	err := query.With("Owner").With("Parent").Offset(offset).Limit(limit).OrderBy("created_at", "desc").Find(&folders)

	return folders, total, err
}

// DownloadFile downloads a file
func (ds *DriveService) DownloadFile(ctx context.Context, fileID string, userID *string) (*models.File, io.ReadCloser, error) {
	// Get file record
	var file models.File
	if err := facades.Orm().Query().Find(&file, fileID); err != nil {
		return nil, nil, fmt.Errorf("file not found: %v", err)
	}

	// Check access permissions
	if !ds.CanAccessFile(&file, userID) {
		return nil, nil, fmt.Errorf("access denied")
	}

	// Get file content
	_, content, err := ds.storageService.Get(ctx, fileID)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get file content: %v", err)
	}

	// Update download count and last accessed time
	now := time.Now()
	facades.Orm().Query().Model(&file).Update(map[string]interface{}{
		"download_count":   file.DownloadCount + 1,
		"last_accessed_at": &now,
	})

	// Log activity
	if userID != nil {
		ds.logFileActivity(file.ID, *userID, "download", "File downloaded", ctx)
	}

	return &file, content, nil
}

// ShareFile creates a file share
func (ds *DriveService) ShareFile(ctx context.Context, fileID, userID string, shareType, permission string, options map[string]interface{}) (*models.FileShare, error) {
	// Verify file ownership or permission
	var file models.File
	if err := facades.Orm().Query().Find(&file, fileID); err != nil {
		return nil, fmt.Errorf("file not found: %v", err)
	}

	if file.OwnerID != userID {
		return nil, fmt.Errorf("only file owner can share")
	}

	// Create share record
	share := &models.FileShare{
		ShareType:  shareType,
		Permission: permission,
		FileID:     fileID,
		SharedByID: userID,
	}

	// Set optional fields
	if email, ok := options["email"].(string); ok {
		share.Email = email
	}
	if message, ok := options["message"].(string); ok {
		share.Message = message
	}
	if expiresAt, ok := options["expires_at"].(*time.Time); ok {
		share.ExpiresAt = expiresAt
	}
	if requirePassword, ok := options["require_password"].(bool); ok {
		share.RequirePassword = requirePassword
	}
	if password, ok := options["password"].(string); ok {
		share.Password = password
	}

	// Generate share token for link shares
	if shareType == "link" {
		share.ShareToken = ds.generateShareToken()
	}

	if err := facades.Orm().Query().Create(&share); err != nil {
		return nil, fmt.Errorf("failed to create share: %v", err)
	}

	// Log activity
	ds.logFileActivity(file.ID, userID, "share", "File shared", ctx)

	return share, nil
}

// MoveFile moves a file to a different folder
func (ds *DriveService) MoveFile(ctx context.Context, fileID, userID string, newFolderID *string) error {
	// Get file
	var file models.File
	if err := facades.Orm().Query().Find(&file, fileID); err != nil {
		return fmt.Errorf("file not found: %v", err)
	}

	// Check ownership
	if file.OwnerID != userID {
		return fmt.Errorf("access denied")
	}

	// Verify destination folder exists and user has access
	if newFolderID != nil {
		var folder models.Folder
		if err := facades.Orm().Query().Find(&folder, *newFolderID); err != nil {
			return fmt.Errorf("destination folder not found: %v", err)
		}
		if folder.OwnerID != userID {
			return fmt.Errorf("access denied to destination folder")
		}
	}

	// Update file folder
	oldFolderID := file.FolderID
	if _, err := facades.Orm().Query().Model(&file).Update("folder_id", newFolderID); err != nil {
		return fmt.Errorf("failed to move file: %v", err)
	}

	// Log activity
	metadata := map[string]interface{}{
		"old_folder_id": oldFolderID,
		"new_folder_id": newFolderID,
	}
	ds.logFileActivityWithMetadata(file.ID, userID, "move", "File moved", metadata, ctx)

	return nil
}

// TrashFile moves a file to trash
func (ds *DriveService) TrashFile(ctx context.Context, fileID, userID string) error {
	var file models.File
	if err := facades.Orm().Query().Find(&file, fileID); err != nil {
		return fmt.Errorf("file not found: %v", err)
	}

	if file.OwnerID != userID {
		return fmt.Errorf("access denied")
	}

	now := time.Now()
	updates := map[string]interface{}{
		"is_trashed": true,
		"trashed_at": &now,
	}

	if _, err := facades.Orm().Query().Model(&file).Update(updates); err != nil {
		return fmt.Errorf("failed to trash file: %v", err)
	}

	// Log activity
	ds.logFileActivity(file.ID, userID, "trash", "File moved to trash", ctx)

	return nil
}

// RestoreFile restores a file from trash
func (ds *DriveService) RestoreFile(ctx context.Context, fileID, userID string) error {
	var file models.File
	if err := facades.Orm().Query().Find(&file, fileID); err != nil {
		return fmt.Errorf("file not found: %v", err)
	}

	if file.OwnerID != userID {
		return fmt.Errorf("access denied")
	}

	updates := map[string]interface{}{
		"is_trashed": false,
		"trashed_at": nil,
	}

	if _, err := facades.Orm().Query().Model(&file).Update(updates); err != nil {
		return fmt.Errorf("failed to restore file: %v", err)
	}

	// Log activity
	ds.logFileActivity(file.ID, userID, "restore", "File restored from trash", ctx)

	return nil
}

// CreateFileVersion creates a new version of a file
func (ds *DriveService) CreateFileVersion(ctx context.Context, fileID, userID string, content io.Reader, size int64, comment string) (*models.File, error) {
	// Get original file
	var file models.File
	if err := facades.Orm().Query().Find(&file, fileID); err != nil {
		return nil, fmt.Errorf("file not found: %v", err)
	}

	if file.OwnerID != userID {
		return nil, fmt.Errorf("access denied")
	}

	// Calculate hash for new version
	hash, err := ds.calculateHash(content)
	if err != nil {
		return nil, fmt.Errorf("failed to calculate file hash: %v", err)
	}

	// Get next version number
	var maxVersion int
	facades.Orm().Query().Model(&models.FileVersion{}).Where("file_id", fileID).Select("COALESCE(MAX(version), 0)").Scan(&maxVersion)
	nextVersion := maxVersion + 1

	// Store new version
	metadata := map[string]interface{}{
		"file_id": fileID,
		"version": nextVersion,
		"comment": comment,
	}

	fileInfo, err := ds.storageService.Store(ctx, file.OriginalName, content, metadata)
	if err != nil {
		return nil, fmt.Errorf("failed to store file version: %v", err)
	}

	// Create version record
	version := &models.FileVersion{
		Version:         nextVersion,
		Path:            fileInfo.Path,
		Size:            size,
		Hash:            hash,
		Comment:         comment,
		IsCurrent:       true,
		StorageProvider: fileInfo.Metadata["storage_provider"].(string),
		FileID:          fileID,
		CreatedByID:     userID,
	}

	// Mark previous versions as not current
	if _, err := facades.Orm().Query().Model(&models.FileVersion{}).Where("file_id", fileID).Update("is_current", false); err != nil {
		return nil, fmt.Errorf("failed to update previous versions: %v", err)
	}

	// Create new version
	if err := facades.Orm().Query().Create(&version); err != nil {
		return nil, fmt.Errorf("failed to create version: %v", err)
	}

	// Update file with new version info
	updates := map[string]interface{}{
		"path": fileInfo.Path,
		"size": size,
		"hash": hash,
	}
	if _, err := facades.Orm().Query().Model(&file).Update(updates); err != nil {
		return nil, fmt.Errorf("failed to update file: %v", err)
	}

	// Log activity
	ds.logFileActivity(file.ID, userID, "version", "New file version created", ctx)

	return &file, nil
}

// SearchFilters represents search criteria for files
type SearchFilters struct {
	Query     string     `json:"query"`
	FileTypes []string   `json:"file_types"`
	MinSize   *int64     `json:"min_size"`
	MaxSize   *int64     `json:"max_size"`
	DateFrom  *time.Time `json:"date_from"`
	DateTo    *time.Time `json:"date_to"`
	Tags      []string   `json:"tags"`
	IsStarred *bool      `json:"is_starred"`
	IsTrashed *bool      `json:"is_trashed"`
	OwnerID   *string    `json:"owner_id"`
	FolderID  *string    `json:"folder_id"`
	SortBy    string     `json:"sort_by"`    // name, size, created_at, modified_at
	SortOrder string     `json:"sort_order"` // asc, desc
}

// GetFilesAdvanced retrieves files with advanced filtering and search
func (ds *DriveService) GetFilesAdvanced(userID string, filters *SearchFilters, page, limit int) ([]models.File, int64, error) {
	query := facades.Orm().Query().Where("owner_id", userID)

	// Apply basic filters
	if filters.IsTrashed != nil {
		query = query.Where("is_trashed", *filters.IsTrashed)
	} else {
		query = query.Where("is_trashed", false) // Default to non-trashed
	}

	if filters.IsStarred != nil {
		query = query.Where("is_starred", *filters.IsStarred)
	}

	if filters.FolderID != nil {
		query = query.Where("folder_id", *filters.FolderID)
	} else if filters.FolderID == nil && filters.Query == "" {
		// If no folder specified and no search, show root files
		query = query.WhereNull("folder_id")
	}

	// Text search
	if filters.Query != "" {
		searchTerm := "%" + filters.Query + "%"
		query = query.Where("name", "LIKE", searchTerm).
			OrWhere("original_name", "LIKE", searchTerm).
			OrWhere("description", "LIKE", searchTerm)
	}

	// File type filters
	if len(filters.FileTypes) > 0 {
		// Convert []string to []interface{}
		fileTypes := make([]interface{}, len(filters.FileTypes))
		for i, v := range filters.FileTypes {
			fileTypes[i] = v
		}
		query = query.WhereIn("extension", fileTypes)
	}

	// Size filters
	if filters.MinSize != nil {
		query = query.Where("size", ">=", *filters.MinSize)
	}
	if filters.MaxSize != nil {
		query = query.Where("size", "<=", *filters.MaxSize)
	}

	// Date filters
	if filters.DateFrom != nil {
		query = query.Where("created_at", ">=", *filters.DateFrom)
	}
	if filters.DateTo != nil {
		query = query.Where("created_at", "<=", *filters.DateTo)
	}

	// Tag filters
	if len(filters.Tags) > 0 {
		for _, tag := range filters.Tags {
			query = query.Where("tags", "LIKE", "%\""+tag+"\"%")
		}
	}

	// Get total count
	total, _ := query.Count()

	// Apply sorting
	sortBy := "created_at"
	sortOrder := "desc"

	if filters.SortBy != "" {
		allowedSorts := map[string]bool{
			"name": true, "size": true, "created_at": true,
			"updated_at": true, "download_count": true,
		}
		if allowedSorts[filters.SortBy] {
			sortBy = filters.SortBy
		}
	}

	if filters.SortOrder == "asc" {
		sortOrder = "asc"
	}

	// Get paginated results
	var files []models.File
	offset := (page - 1) * limit
	err := query.With("Owner").With("Folder").
		Offset(offset).Limit(limit).
		OrderBy(sortBy, sortOrder).
		Find(&files)

	return files, total, err
}

// GetRecentFiles retrieves recently accessed files
func (ds *DriveService) GetRecentFiles(userID string, limit int) ([]models.File, error) {
	var files []models.File
	err := facades.Orm().Query().
		Where("owner_id", userID).
		Where("is_trashed", false).
		WhereNotNull("last_accessed_at").
		With("Owner").With("Folder").
		OrderBy("last_accessed_at", "desc").
		Limit(limit).
		Find(&files)

	return files, err
}

// GetStarredFiles retrieves starred files
func (ds *DriveService) GetStarredFiles(userID string, page, limit int) ([]models.File, int64, error) {
	query := facades.Orm().Query().
		Where("owner_id", userID).
		Where("is_starred", true).
		Where("is_trashed", false)

	// Get total count
	total, _ := query.Count()

	// Get paginated results
	var files []models.File
	offset := (page - 1) * limit
	err := query.With("Owner").With("Folder").
		Offset(offset).Limit(limit).
		OrderBy("updated_at", "desc").
		Find(&files)

	return files, total, err
}

// ToggleFileStar toggles the starred status of a file
func (ds *DriveService) ToggleFileStar(ctx context.Context, fileID, userID string) (*models.File, error) {
	var file models.File
	if err := facades.Orm().Query().Find(&file, fileID); err != nil {
		return nil, fmt.Errorf("file not found: %v", err)
	}

	if file.OwnerID != userID {
		return nil, fmt.Errorf("access denied")
	}

	// Toggle starred status
	file.IsStarred = !file.IsStarred
	if err := facades.Orm().Query().Save(&file); err != nil {
		return nil, fmt.Errorf("failed to update file: %v", err)
	}

	// Log activity
	action := "unstar"
	description := "File unstarred"
	if file.IsStarred {
		action = "star"
		description = "File starred"
	}
	ds.logFileActivity(file.ID, userID, action, description, ctx)

	return &file, nil
}

// GetFilesByType retrieves files filtered by MIME type category
func (ds *DriveService) GetFilesByType(userID, fileType string, page, limit int) ([]models.File, int64, error) {
	query := facades.Orm().Query().
		Where("owner_id", userID).
		Where("is_trashed", false)

	// Apply type-specific filters
	switch fileType {
	case "images":
		query = query.Where("mime_type", "LIKE", "image/%")
	case "videos":
		query = query.Where("mime_type", "LIKE", "video/%")
	case "audio":
		query = query.Where("mime_type", "LIKE", "audio/%")
	case "documents":
		query = query.Where("mime_type", "LIKE", "application/pdf").
			OrWhere("mime_type", "LIKE", "application/msword").
			OrWhere("mime_type", "LIKE", "application/vnd.openxmlformats%").
			OrWhere("mime_type", "LIKE", "text/%")
	case "archives":
		query = query.Where("mime_type", "LIKE", "application/zip").
			OrWhere("mime_type", "LIKE", "application/x-rar%").
			OrWhere("mime_type", "LIKE", "application/x-tar").
			OrWhere("mime_type", "LIKE", "application/gzip")
	default:
		return nil, 0, fmt.Errorf("invalid file type: %s", fileType)
	}

	// Get total count
	total, _ := query.Count()

	// Get paginated results
	var files []models.File
	offset := (page - 1) * limit
	err := query.With("Owner").With("Folder").
		Offset(offset).Limit(limit).
		OrderBy("created_at", "desc").
		Find(&files)

	return files, total, err
}

// BulkOperationRequest represents a bulk operation request
type BulkOperationRequest struct {
	FileIDs   []string `json:"file_ids"`
	Operation string   `json:"operation"` // move, trash, restore, star, unstar, delete
	FolderID  *string  `json:"folder_id,omitempty"`
}

// BulkOperationResult represents the result of a bulk operation
type BulkOperationResult struct {
	SuccessCount int                  `json:"success_count"`
	FailureCount int                  `json:"failure_count"`
	Errors       []BulkOperationError `json:"errors,omitempty"`
	Results      []BulkOperationItem  `json:"results"`
}

// BulkOperationError represents an error in bulk operation
type BulkOperationError struct {
	FileID  string `json:"file_id"`
	Message string `json:"message"`
}

// BulkOperationItem represents a single item result
type BulkOperationItem struct {
	FileID  string `json:"file_id"`
	Success bool   `json:"success"`
	Message string `json:"message"`
}

// BulkMoveFiles moves multiple files to a folder
func (ds *DriveService) BulkMoveFiles(ctx context.Context, userID string, fileIDs []string, folderID *string) (*BulkOperationResult, error) {
	result := &BulkOperationResult{
		Results: make([]BulkOperationItem, 0, len(fileIDs)),
	}

	// Validate destination folder if provided
	if folderID != nil {
		var folder models.Folder
		if err := facades.Orm().Query().Find(&folder, *folderID); err != nil {
			return nil, fmt.Errorf("destination folder not found: %v", err)
		}
		if folder.OwnerID != userID {
			return nil, fmt.Errorf("access denied to destination folder")
		}
	}

	for _, fileID := range fileIDs {
		err := ds.MoveFile(ctx, fileID, userID, folderID)
		if err != nil {
			result.FailureCount++
			result.Errors = append(result.Errors, BulkOperationError{
				FileID:  fileID,
				Message: err.Error(),
			})
			result.Results = append(result.Results, BulkOperationItem{
				FileID:  fileID,
				Success: false,
				Message: err.Error(),
			})
		} else {
			result.SuccessCount++
			result.Results = append(result.Results, BulkOperationItem{
				FileID:  fileID,
				Success: true,
				Message: "File moved successfully",
			})
		}
	}

	return result, nil
}

// BulkTrashFiles moves multiple files to trash
func (ds *DriveService) BulkTrashFiles(ctx context.Context, userID string, fileIDs []string) (*BulkOperationResult, error) {
	result := &BulkOperationResult{
		Results: make([]BulkOperationItem, 0, len(fileIDs)),
	}

	for _, fileID := range fileIDs {
		err := ds.TrashFile(ctx, fileID, userID)
		if err != nil {
			result.FailureCount++
			result.Errors = append(result.Errors, BulkOperationError{
				FileID:  fileID,
				Message: err.Error(),
			})
			result.Results = append(result.Results, BulkOperationItem{
				FileID:  fileID,
				Success: false,
				Message: err.Error(),
			})
		} else {
			result.SuccessCount++
			result.Results = append(result.Results, BulkOperationItem{
				FileID:  fileID,
				Success: true,
				Message: "File moved to trash",
			})
		}
	}

	return result, nil
}

// BulkRestoreFiles restores multiple files from trash
func (ds *DriveService) BulkRestoreFiles(ctx context.Context, userID string, fileIDs []string) (*BulkOperationResult, error) {
	result := &BulkOperationResult{
		Results: make([]BulkOperationItem, 0, len(fileIDs)),
	}

	for _, fileID := range fileIDs {
		err := ds.RestoreFile(ctx, fileID, userID)
		if err != nil {
			result.FailureCount++
			result.Errors = append(result.Errors, BulkOperationError{
				FileID:  fileID,
				Message: err.Error(),
			})
			result.Results = append(result.Results, BulkOperationItem{
				FileID:  fileID,
				Success: false,
				Message: err.Error(),
			})
		} else {
			result.SuccessCount++
			result.Results = append(result.Results, BulkOperationItem{
				FileID:  fileID,
				Success: true,
				Message: "File restored",
			})
		}
	}

	return result, nil
}

// BulkStarFiles toggles star status for multiple files
func (ds *DriveService) BulkStarFiles(ctx context.Context, userID string, fileIDs []string, starred bool) (*BulkOperationResult, error) {
	result := &BulkOperationResult{
		Results: make([]BulkOperationItem, 0, len(fileIDs)),
	}

	for _, fileID := range fileIDs {
		var file models.File
		if err := facades.Orm().Query().Find(&file, fileID); err != nil {
			result.FailureCount++
			result.Errors = append(result.Errors, BulkOperationError{
				FileID:  fileID,
				Message: "File not found",
			})
			result.Results = append(result.Results, BulkOperationItem{
				FileID:  fileID,
				Success: false,
				Message: "File not found",
			})
			continue
		}

		if file.OwnerID != userID {
			result.FailureCount++
			result.Errors = append(result.Errors, BulkOperationError{
				FileID:  fileID,
				Message: "Access denied",
			})
			result.Results = append(result.Results, BulkOperationItem{
				FileID:  fileID,
				Success: false,
				Message: "Access denied",
			})
			continue
		}

		// Update starred status
		file.IsStarred = starred
		if err := facades.Orm().Query().Save(&file); err != nil {
			result.FailureCount++
			result.Errors = append(result.Errors, BulkOperationError{
				FileID:  fileID,
				Message: err.Error(),
			})
			result.Results = append(result.Results, BulkOperationItem{
				FileID:  fileID,
				Success: false,
				Message: err.Error(),
			})
			continue
		}

		// Log activity
		action := "unstar"
		description := "File unstarred"
		if starred {
			action = "star"
			description = "File starred"
		}
		ds.logFileActivity(file.ID, userID, action, description, ctx)

		result.SuccessCount++
		message := "File unstarred"
		if starred {
			message = "File starred"
		}
		result.Results = append(result.Results, BulkOperationItem{
			FileID:  fileID,
			Success: true,
			Message: message,
		})
	}

	return result, nil
}

// BulkDeleteFiles permanently deletes multiple files
func (ds *DriveService) BulkDeleteFiles(ctx context.Context, userID string, fileIDs []string) (*BulkOperationResult, error) {
	result := &BulkOperationResult{
		Results: make([]BulkOperationItem, 0, len(fileIDs)),
	}

	for _, fileID := range fileIDs {
		var file models.File
		if err := facades.Orm().Query().Find(&file, fileID); err != nil {
			result.FailureCount++
			result.Errors = append(result.Errors, BulkOperationError{
				FileID:  fileID,
				Message: "File not found",
			})
			result.Results = append(result.Results, BulkOperationItem{
				FileID:  fileID,
				Success: false,
				Message: "File not found",
			})
			continue
		}

		if file.OwnerID != userID {
			result.FailureCount++
			result.Errors = append(result.Errors, BulkOperationError{
				FileID:  fileID,
				Message: "Access denied",
			})
			result.Results = append(result.Results, BulkOperationItem{
				FileID:  fileID,
				Success: false,
				Message: "Access denied",
			})
			continue
		}

		// Delete from storage
		if err := ds.storageService.Delete(ctx, fileID); err != nil {
			facades.Log().Warning("Failed to delete file from storage", map[string]interface{}{
				"file_id": fileID,
				"error":   err.Error(),
			})
		}

		// Delete from database
		if _, err := facades.Orm().Query().Delete(&file); err != nil {
			result.FailureCount++
			result.Errors = append(result.Errors, BulkOperationError{
				FileID:  fileID,
				Message: err.Error(),
			})
			result.Results = append(result.Results, BulkOperationItem{
				FileID:  fileID,
				Success: false,
				Message: err.Error(),
			})
			continue
		}

		// Log activity
		ds.logFileActivity(file.ID, userID, "delete", "File permanently deleted", ctx)

		result.SuccessCount++
		result.Results = append(result.Results, BulkOperationItem{
			FileID:  fileID,
			Success: true,
			Message: "File deleted permanently",
		})
	}

	return result, nil
}

// ProcessBulkOperation processes a bulk operation request
func (ds *DriveService) ProcessBulkOperation(ctx context.Context, userID string, request *BulkOperationRequest) (*BulkOperationResult, error) {
	if len(request.FileIDs) == 0 {
		return nil, fmt.Errorf("no file IDs provided")
	}

	if len(request.FileIDs) > 100 {
		return nil, fmt.Errorf("too many files selected (max 100)")
	}

	switch request.Operation {
	case "move":
		return ds.BulkMoveFiles(ctx, userID, request.FileIDs, request.FolderID)
	case "trash":
		return ds.BulkTrashFiles(ctx, userID, request.FileIDs)
	case "restore":
		return ds.BulkRestoreFiles(ctx, userID, request.FileIDs)
	case "star":
		return ds.BulkStarFiles(ctx, userID, request.FileIDs, true)
	case "unstar":
		return ds.BulkStarFiles(ctx, userID, request.FileIDs, false)
	case "delete":
		return ds.BulkDeleteFiles(ctx, userID, request.FileIDs)
	default:
		return nil, fmt.Errorf("invalid operation: %s", request.Operation)
	}
}

// AddFileComment adds a comment to a file
func (ds *DriveService) AddFileComment(ctx context.Context, fileID, userID, content string) (*models.FileComment, error) {
	// Verify file exists and user has access
	var file models.File
	if err := facades.Orm().Query().Find(&file, fileID); err != nil {
		return nil, fmt.Errorf("file not found: %v", err)
	}

	if !ds.CanAccessFile(&file, &userID) {
		return nil, fmt.Errorf("access denied")
	}

	// Create comment
	comment := &models.FileComment{
		Content:  content,
		FileID:   fileID,
		AuthorID: userID,
	}

	if err := facades.Orm().Query().Create(&comment); err != nil {
		return nil, fmt.Errorf("failed to create comment: %v", err)
	}

	// Load user relationship
	facades.Orm().Query().With("Author").Find(&comment, comment.ID)

	// Log activity
	ds.logFileActivity(fileID, userID, "comment", "Comment added to file", ctx)

	// Send notification to file owner if different from commenter
	if file.OwnerID != userID {
		notificationErr := ds.sendFileCommentNotification(&file, userID, comment.Content)
		if notificationErr != nil {
			facades.Log().Error("Failed to send file comment notification", map[string]interface{}{
				"file_id":   fileID,
				"commenter": userID,
				"owner":     file.OwnerID,
				"error":     notificationErr.Error(),
			})
		} else {
			facades.Log().Info("File comment notification sent", map[string]interface{}{
				"file_id":    fileID,
				"commenter":  userID,
				"owner":      file.OwnerID,
				"comment_id": comment.ID,
			})
		}
	}

	return comment, nil
}

// GetFileComments retrieves comments for a file
func (ds *DriveService) GetFileComments(ctx context.Context, fileID, userID string, page, limit int) ([]models.FileComment, int64, error) {
	// Verify file exists and user has access
	var file models.File
	if err := facades.Orm().Query().Find(&file, fileID); err != nil {
		return nil, 0, fmt.Errorf("file not found: %v", err)
	}

	if !ds.CanAccessFile(&file, &userID) {
		return nil, 0, fmt.Errorf("access denied")
	}

	// Get comments with pagination
	query := facades.Orm().Query().Where("file_id", fileID)

	// Get total count
	total, _ := query.Count()

	// Get paginated results
	var comments []models.FileComment
	offset := (page - 1) * limit
	err := query.With("Author").
		Offset(offset).Limit(limit).
		OrderBy("created_at", "asc").
		Find(&comments)

	return comments, total, err
}

// UpdateFileComment updates a comment
func (ds *DriveService) UpdateFileComment(ctx context.Context, commentID, userID, content string) (*models.FileComment, error) {
	var comment models.FileComment
	if err := facades.Orm().Query().Find(&comment, commentID); err != nil {
		return nil, fmt.Errorf("comment not found: %v", err)
	}

	// Only comment author can update
	if comment.AuthorID != userID {
		return nil, fmt.Errorf("access denied")
	}

	// Update content
	comment.Content = content
	if err := facades.Orm().Query().Save(&comment); err != nil {
		return nil, fmt.Errorf("failed to update comment: %v", err)
	}

	// Load user relationship
	facades.Orm().Query().With("Author").Find(&comment, comment.ID)

	// Log activity
	ds.logFileActivity(comment.FileID, userID, "comment_update", "Comment updated", ctx)

	return &comment, nil
}

// DeleteFileComment deletes a comment
func (ds *DriveService) DeleteFileComment(ctx context.Context, commentID, userID string) error {
	var comment models.FileComment
	if err := facades.Orm().Query().Find(&comment, commentID); err != nil {
		return fmt.Errorf("comment not found: %v", err)
	}

	// Check permissions - author or file owner can delete
	var file models.File
	if err := facades.Orm().Query().Find(&file, comment.FileID); err != nil {
		return fmt.Errorf("file not found: %v", err)
	}

	if comment.AuthorID != userID && file.OwnerID != userID {
		return fmt.Errorf("access denied")
	}

	// Delete comment
	if _, err := facades.Orm().Query().Delete(&comment); err != nil {
		return fmt.Errorf("failed to delete comment: %v", err)
	}

	// Log activity
	ds.logFileActivity(comment.FileID, userID, "comment_delete", "Comment deleted", ctx)

	return nil
}

// GetFileActivity retrieves activity history for a file
func (ds *DriveService) GetFileActivity(ctx context.Context, fileID, userID string, page, limit int) ([]models.FileActivity, int64, error) {
	// Verify file exists and user has access
	var file models.File
	if err := facades.Orm().Query().Find(&file, fileID); err != nil {
		return nil, 0, fmt.Errorf("file not found: %v", err)
	}

	if !ds.CanAccessFile(&file, &userID) {
		return nil, 0, fmt.Errorf("access denied")
	}

	// Get activity with pagination
	query := facades.Orm().Query().Where("file_id", fileID)

	// Get total count
	total, _ := query.Count()

	// Get paginated results
	var activities []models.FileActivity
	offset := (page - 1) * limit
	err := query.With("User").
		Offset(offset).Limit(limit).
		OrderBy("created_at", "desc").
		Find(&activities)

	return activities, total, err
}

// ShareFolder creates a folder share
func (ds *DriveService) ShareFolder(ctx context.Context, folderID, userID string, shareType, permission string, options map[string]interface{}) (*models.FolderShare, error) {
	// Verify folder ownership or permission
	var folder models.Folder
	if err := facades.Orm().Query().Find(&folder, folderID); err != nil {
		return nil, fmt.Errorf("folder not found: %v", err)
	}

	if folder.OwnerID != userID {
		return nil, fmt.Errorf("only folder owner can share")
	}

	// Create share record
	share := &models.FolderShare{
		ShareType:  shareType,
		Permission: permission,
		FolderID:   folderID,
		SharedByID: userID,
	}

	// Set optional fields
	if email, ok := options["email"].(string); ok {
		share.Email = email
	}
	if message, ok := options["message"].(string); ok {
		share.Message = message
	}
	if expiresAt, ok := options["expires_at"].(*time.Time); ok {
		share.ExpiresAt = expiresAt
	}
	if requirePassword, ok := options["require_password"].(bool); ok {
		share.RequirePassword = requirePassword
	}
	if password, ok := options["password"].(string); ok {
		share.Password = password
	}

	// Generate share token for link shares
	if shareType == "link" {
		share.ShareToken = ds.generateShareToken()
	}

	if err := facades.Orm().Query().Create(&share); err != nil {
		return nil, fmt.Errorf("failed to create folder share: %v", err)
	}

	// Log activity
	ds.logFolderActivity(folder.ID, userID, "share", "Folder shared", ctx)

	return share, nil
}

// GetSharedFolders retrieves folders shared with a user
func (ds *DriveService) GetSharedFolders(userID string, page, limit int) ([]models.Folder, int64, error) {
	// Get folder IDs that are shared with this user
	var shares []models.FolderShare
	err := facades.Orm().Query().
		Where("shared_with_id", userID).
		Where("is_active", true).
		Find(&shares)
	if err != nil {
		return nil, 0, err
	}

	if len(shares) == 0 {
		return []models.Folder{}, 0, nil
	}

	// Extract folder IDs
	folderIDs := make([]interface{}, len(shares))
	for i, share := range shares {
		folderIDs[i] = share.FolderID
	}

	// Get folders
	query := facades.Orm().Query().
		WhereIn("id", folderIDs).
		Where("is_trashed", false)

	// Get total count
	total, _ := query.Count()

	// Get paginated results
	var folders []models.Folder
	offset := (page - 1) * limit
	err = query.With("Owner").
		Offset(offset).Limit(limit).
		OrderBy("name", "asc").
		Find(&folders)

	return folders, total, err
}

// CanAccessFolder checks if a user can access a folder
func (ds *DriveService) CanAccessFolder(folder *models.Folder, userID *string) bool {
	// Owner always has access
	if userID != nil && folder.OwnerID == *userID {
		return true
	}

	// Public folders are accessible
	if folder.IsPublic {
		return true
	}

	// Check if folder is shared with user
	if userID != nil {
		var share models.FolderShare
		err := facades.Orm().Query().Where("folder_id", folder.ID).
			Where("shared_with_id", *userID).
			Where("is_active", true).
			First(&share)
		if err == nil && !share.IsExpired() {
			return true
		}
	}

	return false
}

// GetFolderContents retrieves files and subfolders in a folder with access control
func (ds *DriveService) GetFolderContents(userID string, folderID *string, page, limit int) (map[string]interface{}, error) {
	// Verify folder access if folderID is provided
	if folderID != nil {
		var folder models.Folder
		if err := facades.Orm().Query().Find(&folder, *folderID); err != nil {
			return nil, fmt.Errorf("folder not found: %v", err)
		}

		if !ds.CanAccessFolder(&folder, &userID) {
			return nil, fmt.Errorf("access denied")
		}
	}

	// Get files
	files, filesTotal, err := ds.GetFiles(userID, folderID, page, limit, "")
	if err != nil {
		return nil, fmt.Errorf("failed to get files: %v", err)
	}

	// Get folders
	folders, foldersTotal, err := ds.GetFolders(userID, folderID, page, limit, "")
	if err != nil {
		return nil, fmt.Errorf("failed to get folders: %v", err)
	}

	result := map[string]interface{}{
		"files": map[string]interface{}{
			"data":  files,
			"total": filesTotal,
		},
		"folders": map[string]interface{}{
			"data":  folders,
			"total": foldersTotal,
		},
		"pagination": map[string]interface{}{
			"page":  page,
			"limit": limit,
		},
	}

	return result, nil
}

// MoveFolderToTrash moves a folder and its contents to trash
func (ds *DriveService) MoveFolderToTrash(ctx context.Context, folderID, userID string) error {
	var folder models.Folder
	if err := facades.Orm().Query().Find(&folder, folderID); err != nil {
		return fmt.Errorf("folder not found: %v", err)
	}

	if folder.OwnerID != userID {
		return fmt.Errorf("access denied")
	}

	// Move folder to trash
	now := time.Now()
	updates := map[string]interface{}{
		"is_trashed": true,
		"trashed_at": &now,
	}

	if _, err := facades.Orm().Query().Model(&folder).Update(updates); err != nil {
		return fmt.Errorf("failed to trash folder: %v", err)
	}

	// Move all files in folder to trash
	_, err := facades.Orm().Query().Model(&models.File{}).
		Where("folder_id", folderID).
		Update(updates)
	if err != nil {
		facades.Log().Warning("Failed to trash some files in folder", map[string]interface{}{
			"folder_id": folderID,
			"error":     err.Error(),
		})
	}

	// Recursively trash subfolders
	var subfolders []models.Folder
	err = facades.Orm().Query().Where("parent_id", folderID).Find(&subfolders)
	if err == nil {
		for _, subfolder := range subfolders {
			ds.MoveFolderToTrash(ctx, subfolder.ID, userID)
		}
	}

	// Log activity
	ds.logFolderActivity(folder.ID, userID, "trash", "Folder moved to trash", ctx)

	return nil
}

// RestoreFolderFromTrash restores a folder and its contents from trash
func (ds *DriveService) RestoreFolderFromTrash(ctx context.Context, folderID, userID string) error {
	var folder models.Folder
	if err := facades.Orm().Query().Find(&folder, folderID); err != nil {
		return fmt.Errorf("folder not found: %v", err)
	}

	if folder.OwnerID != userID {
		return fmt.Errorf("access denied")
	}

	if !folder.IsTrashed {
		return fmt.Errorf("folder is not in trash")
	}

	// Restore folder
	updates := map[string]interface{}{
		"is_trashed": false,
		"trashed_at": nil,
	}

	if _, err := facades.Orm().Query().Model(&folder).Update(updates); err != nil {
		return fmt.Errorf("failed to restore folder: %v", err)
	}

	// Restore all files in folder
	_, err := facades.Orm().Query().Model(&models.File{}).
		Where("folder_id", folderID).
		Update(updates)
	if err != nil {
		facades.Log().Warning("Failed to restore some files in folder", map[string]interface{}{
			"folder_id": folderID,
			"error":     err.Error(),
		})
	}

	// Recursively restore subfolders
	var subfolders []models.Folder
	err = facades.Orm().Query().Where("parent_id", folderID).Find(&subfolders)
	if err == nil {
		for _, subfolder := range subfolders {
			ds.RestoreFolderFromTrash(ctx, subfolder.ID, userID)
		}
	}

	// Log activity
	ds.logFolderActivity(folder.ID, userID, "restore", "Folder restored from trash", ctx)

	return nil
}

// GetTrashedItems retrieves files and folders in trash
func (ds *DriveService) GetTrashedItems(userID string, page, limit int) (map[string]interface{}, error) {
	// Get trashed files
	trashedFiles := &SearchFilters{
		IsTrashed: &[]bool{true}[0],
	}
	files, filesTotal, err := ds.GetFilesAdvanced(userID, trashedFiles, page, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to get trashed files: %v", err)
	}

	// Get trashed folders
	query := facades.Orm().Query().
		Where("owner_id", userID).
		Where("is_trashed", true)

	foldersTotal, _ := query.Count()

	var folders []models.Folder
	offset := (page - 1) * limit
	err = query.With("Owner").
		Offset(offset).Limit(limit).
		OrderBy("trashed_at", "desc").
		Find(&folders)
	if err != nil {
		return nil, fmt.Errorf("failed to get trashed folders: %v", err)
	}

	result := map[string]interface{}{
		"files": map[string]interface{}{
			"data":  files,
			"total": filesTotal,
		},
		"folders": map[string]interface{}{
			"data":  folders,
			"total": foldersTotal,
		},
		"pagination": map[string]interface{}{
			"page":  page,
			"limit": limit,
		},
	}

	return result, nil
}

// StorageQuota represents storage quota information
type StorageQuota struct {
	UserID       string  `json:"user_id"`
	TotalQuota   int64   `json:"total_quota"` // in bytes
	UsedSpace    int64   `json:"used_space"`  // in bytes
	AvailSpace   int64   `json:"avail_space"` // in bytes
	UsagePercent float64 `json:"usage_percent"`
	FileCount    int64   `json:"file_count"`
	FolderCount  int64   `json:"folder_count"`
}

// GetStorageQuota retrieves storage quota information for a user
func (ds *DriveService) GetStorageQuota(ctx context.Context, userID string) (*StorageQuota, error) {
	// Get user's total quota (default 5GB, could be stored in user profile)
	totalQuota := int64(5 * 1024 * 1024 * 1024) // 5GB default

	// Calculate used space from files
	totalSize, err := facades.Orm().Query().
		Model(&models.File{}).
		Where("owner_id", userID).
		Where("is_trashed", false).
		Sum("size")
	if err != nil {
		return nil, fmt.Errorf("failed to calculate used space: %v", err)
	}

	// Count files
	var fileCount int64
	fileCount, err = facades.Orm().Query().
		Model(&models.File{}).
		Where("owner_id", userID).
		Where("is_trashed", false).
		Count()
	if err != nil {
		return nil, fmt.Errorf("failed to count files: %v", err)
	}

	// Count folders
	var folderCount int64
	folderCount, err = facades.Orm().Query().
		Model(&models.Folder{}).
		Where("owner_id", userID).
		Where("is_trashed", false).
		Count()
	if err != nil {
		return nil, fmt.Errorf("failed to count folders: %v", err)
	}

	// Calculate available space and usage percentage
	availSpace := totalQuota - totalSize
	if availSpace < 0 {
		availSpace = 0
	}

	usagePercent := 0.0
	if totalQuota > 0 {
		usagePercent = (float64(totalSize) / float64(totalQuota)) * 100
	}

	quota := &StorageQuota{
		UserID:       userID,
		TotalQuota:   totalQuota,
		UsedSpace:    totalSize,
		AvailSpace:   availSpace,
		UsagePercent: usagePercent,
		FileCount:    fileCount,
		FolderCount:  folderCount,
	}

	return quota, nil
}

// CheckStorageQuota checks if user has enough space for a file
func (ds *DriveService) CheckStorageQuota(ctx context.Context, userID string, fileSize int64) error {
	quota, err := ds.GetStorageQuota(ctx, userID)
	if err != nil {
		return fmt.Errorf("failed to get storage quota: %v", err)
	}

	if fileSize > quota.AvailSpace {
		return fmt.Errorf("insufficient storage space: need %d bytes, available %d bytes", fileSize, quota.AvailSpace)
	}

	return nil
}

// GetStorageUsageByType retrieves storage usage breakdown by file type
func (ds *DriveService) GetStorageUsageByType(ctx context.Context, userID string) (map[string]interface{}, error) {
	usage := make(map[string]interface{})

	// Define file type categories
	categories := map[string][]string{
		"images":    {"image/%"},
		"videos":    {"video/%"},
		"audio":     {"audio/%"},
		"documents": {"application/pdf", "application/msword", "application/vnd.openxmlformats%", "text/%"},
		"archives":  {"application/zip", "application/x-rar%", "application/x-tar", "application/gzip"},
	}

	for category, mimeTypes := range categories {
		var totalSize int64
		var fileCount int64

		query := facades.Orm().Query().
			Model(&models.File{}).
			Where("owner_id", userID).
			Where("is_trashed", false)

		// Apply MIME type filters
		for i, mimeType := range mimeTypes {
			if i == 0 {
				query = query.Where("mime_type", "LIKE", mimeType)
			} else {
				query = query.OrWhere("mime_type", "LIKE", mimeType)
			}
		}

		// Get total size
		totalSize, err := query.Sum("size")
		if err != nil {
			facades.Log().Warning("Failed to calculate size for category", map[string]interface{}{
				"category": category,
				"error":    err.Error(),
			})
			continue
		}

		// Get file count
		fileCount, err = query.Count()
		if err != nil {
			facades.Log().Warning("Failed to count files for category", map[string]interface{}{
				"category": category,
				"error":    err.Error(),
			})
			continue
		}

		usage[category] = map[string]interface{}{
			"size":       totalSize,
			"file_count": fileCount,
			"size_mb":    float64(totalSize) / (1024 * 1024),
		}
	}

	// Get "other" files
	var otherSize int64
	var otherCount int64

	// Build exclusion query for known categories
	otherQuery := facades.Orm().Query().
		Model(&models.File{}).
		Where("owner_id", userID).
		Where("is_trashed", false)

	// Exclude known MIME types
	for _, mimeTypes := range categories {
		for _, mimeType := range mimeTypes {
			otherQuery = otherQuery.Where("mime_type", "NOT LIKE", mimeType)
		}
	}

	otherSize, _ = otherQuery.Sum("size")
	otherCount, _ = otherQuery.Count()

	usage["other"] = map[string]interface{}{
		"size":       otherSize,
		"file_count": otherCount,
		"size_mb":    float64(otherSize) / (1024 * 1024),
	}

	return usage, nil
}

// GetLargestFiles retrieves the largest files for a user
func (ds *DriveService) GetLargestFiles(ctx context.Context, userID string, limit int) ([]models.File, error) {
	var files []models.File
	err := facades.Orm().Query().
		Where("owner_id", userID).
		Where("is_trashed", false).
		With("Folder").
		OrderBy("size", "desc").
		Limit(limit).
		Find(&files)

	return files, err
}

// CleanupTrashedFiles permanently deletes old trashed files
func (ds *DriveService) CleanupTrashedFiles(ctx context.Context, userID string, olderThanDays int) (int, error) {
	cutoffDate := time.Now().AddDate(0, 0, -olderThanDays)

	// Get trashed files older than cutoff date
	var files []models.File
	err := facades.Orm().Query().
		Where("owner_id", userID).
		Where("is_trashed", true).
		Where("trashed_at", "<", cutoffDate).
		Find(&files)
	if err != nil {
		return 0, fmt.Errorf("failed to get trashed files: %v", err)
	}

	deletedCount := 0
	for _, file := range files {
		// Delete from storage
		if err := ds.storageService.Delete(ctx, file.ID); err != nil {
			facades.Log().Warning("Failed to delete file from storage during cleanup", map[string]interface{}{
				"file_id": file.ID,
				"error":   err.Error(),
			})
		}

		// Delete from database
		if _, err := facades.Orm().Query().Delete(&file); err != nil {
			facades.Log().Warning("Failed to delete file from database during cleanup", map[string]interface{}{
				"file_id": file.ID,
				"error":   err.Error(),
			})
			continue
		}

		deletedCount++
		ds.logFileActivity(file.ID, userID, "cleanup", "File permanently deleted during cleanup", ctx)
	}

	return deletedCount, nil
}

// GetStorageAnalytics retrieves storage analytics for a user
func (ds *DriveService) GetStorageAnalytics(ctx context.Context, userID string) (map[string]interface{}, error) {
	analytics := make(map[string]interface{})

	// Get basic quota info
	quota, err := ds.GetStorageQuota(ctx, userID)
	if err != nil {
		return nil, err
	}
	analytics["quota"] = quota

	// Get usage by type
	usageByType, err := ds.GetStorageUsageByType(ctx, userID)
	if err != nil {
		return nil, err
	}
	analytics["usage_by_type"] = usageByType

	// Get largest files
	largestFiles, err := ds.GetLargestFiles(ctx, userID, 10)
	if err != nil {
		return nil, err
	}
	analytics["largest_files"] = largestFiles

	// Get recent activity count
	var recentActivityCount int64
	weekAgo := time.Now().AddDate(0, 0, -7)
	recentActivityCount, err = facades.Orm().Query().
		Model(&models.FileActivity{}).
		Where("user_id", userID).
		Where("created_at", ">=", weekAgo).
		Count()
	if err == nil {
		analytics["recent_activity_count"] = recentActivityCount
	}

	// Get trash info
	var trashSize int64
	var trashCount int64

	trashSize, _ = facades.Orm().Query().
		Model(&models.File{}).
		Where("owner_id", userID).
		Where("is_trashed", true).
		Sum("size")

	trashCount, _ = facades.Orm().Query().
		Model(&models.File{}).
		Where("owner_id", userID).
		Where("is_trashed", true).
		Count()

	analytics["trash"] = map[string]interface{}{
		"size":       trashSize,
		"file_count": trashCount,
		"size_mb":    float64(trashSize) / (1024 * 1024),
	}

	return analytics, nil
}

// TagFile adds tags to a file
func (ds *DriveService) TagFile(ctx context.Context, fileID, userID string, tags []string) (*models.File, error) {
	var file models.File
	if err := facades.Orm().Query().Find(&file, fileID); err != nil {
		return nil, fmt.Errorf("file not found: %v", err)
	}

	if file.OwnerID != userID {
		return nil, fmt.Errorf("access denied")
	}

	// Validate and clean tags
	cleanTags := make([]string, 0, len(tags))
	tagMap := make(map[string]bool)

	for _, tag := range tags {
		// Clean and validate tag
		cleanTag := strings.TrimSpace(strings.ToLower(tag))
		if len(cleanTag) > 0 && len(cleanTag) <= 50 && !tagMap[cleanTag] {
			// Only allow alphanumeric, spaces, hyphens, and underscores
			if matched, _ := regexp.MatchString(`^[a-zA-Z0-9\s\-_]+$`, cleanTag); matched {
				cleanTags = append(cleanTags, cleanTag)
				tagMap[cleanTag] = true
			}
		}
	}

	// Limit to 10 tags per file
	if len(cleanTags) > 10 {
		cleanTags = cleanTags[:10]
	}

	// Convert tags to JSON
	tagsJSON, err := json.Marshal(cleanTags)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize tags: %v", err)
	}

	// Update file with tags
	file.Tags = string(tagsJSON)
	if err := facades.Orm().Query().Save(&file); err != nil {
		return nil, fmt.Errorf("failed to update file tags: %v", err)
	}

	// Log activity
	ds.logFileActivity(file.ID, userID, "tag", fmt.Sprintf("File tagged with: %s", strings.Join(cleanTags, ", ")), ctx)

	return &file, nil
}

// RemoveTagsFromFile removes specific tags from a file
func (ds *DriveService) RemoveTagsFromFile(ctx context.Context, fileID, userID string, tagsToRemove []string) (*models.File, error) {
	var file models.File
	if err := facades.Orm().Query().Find(&file, fileID); err != nil {
		return nil, fmt.Errorf("file not found: %v", err)
	}

	if file.OwnerID != userID {
		return nil, fmt.Errorf("access denied")
	}

	// Parse existing tags
	var existingTags []string
	if file.Tags != "" {
		if err := json.Unmarshal([]byte(file.Tags), &existingTags); err != nil {
			return nil, fmt.Errorf("failed to parse existing tags: %v", err)
		}
	}

	// Create map of tags to remove
	removeMap := make(map[string]bool)
	for _, tag := range tagsToRemove {
		removeMap[strings.TrimSpace(strings.ToLower(tag))] = true
	}

	// Filter out tags to remove
	var filteredTags []string
	for _, tag := range existingTags {
		if !removeMap[tag] {
			filteredTags = append(filteredTags, tag)
		}
	}

	// Update file with filtered tags
	tagsJSON, err := json.Marshal(filteredTags)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize tags: %v", err)
	}

	file.Tags = string(tagsJSON)
	if err := facades.Orm().Query().Save(&file); err != nil {
		return nil, fmt.Errorf("failed to update file tags: %v", err)
	}

	// Log activity
	ds.logFileActivity(file.ID, userID, "untag", fmt.Sprintf("Tags removed: %s", strings.Join(tagsToRemove, ", ")), ctx)

	return &file, nil
}

// GetAllUserTags retrieves all unique tags used by a user
func (ds *DriveService) GetAllUserTags(userID string) ([]string, error) {
	var files []models.File
	err := facades.Orm().Query().
		Where("owner_id", userID).
		Where("is_trashed", false).
		WhereNotNull("tags").
		Where("tags", "!=", "").
		Where("tags", "!=", "[]").
		Select("tags").
		Find(&files)
	if err != nil {
		return nil, fmt.Errorf("failed to get user files: %v", err)
	}

	// Collect all unique tags
	tagMap := make(map[string]bool)
	for _, file := range files {
		var fileTags []string
		if err := json.Unmarshal([]byte(file.Tags), &fileTags); err == nil {
			for _, tag := range fileTags {
				tagMap[tag] = true
			}
		}
	}

	// Convert map to sorted slice
	tags := make([]string, 0, len(tagMap))
	for tag := range tagMap {
		tags = append(tags, tag)
	}

	// Sort tags alphabetically
	sort.Strings(tags)

	return tags, nil
}

// GetTagUsageStats retrieves statistics about tag usage
func (ds *DriveService) GetTagUsageStats(userID string) (map[string]interface{}, error) {
	var files []models.File
	err := facades.Orm().Query().
		Where("owner_id", userID).
		Where("is_trashed", false).
		WhereNotNull("tags").
		Where("tags", "!=", "").
		Where("tags", "!=", "[]").
		Select("tags").
		Find(&files)
	if err != nil {
		return nil, fmt.Errorf("failed to get user files: %v", err)
	}

	// Count tag usage
	tagCounts := make(map[string]int)
	totalTaggedFiles := 0

	for _, file := range files {
		var fileTags []string
		if err := json.Unmarshal([]byte(file.Tags), &fileTags); err == nil && len(fileTags) > 0 {
			totalTaggedFiles++
			for _, tag := range fileTags {
				tagCounts[tag]++
			}
		}
	}

	// Create sorted list of tags by usage
	type tagStat struct {
		Tag   string `json:"tag"`
		Count int    `json:"count"`
	}

	var tagStats []tagStat
	for tag, count := range tagCounts {
		tagStats = append(tagStats, tagStat{Tag: tag, Count: count})
	}

	// Sort by count (descending) then by name
	sort.Slice(tagStats, func(i, j int) bool {
		if tagStats[i].Count == tagStats[j].Count {
			return tagStats[i].Tag < tagStats[j].Tag
		}
		return tagStats[i].Count > tagStats[j].Count
	})

	result := map[string]interface{}{
		"total_tags":         len(tagCounts),
		"total_tagged_files": totalTaggedFiles,
		"tag_usage":          tagStats,
		"most_used_tags": func() []tagStat {
			if len(tagStats) > 10 {
				return tagStats[:10]
			}
			return tagStats
		}(), // Top 10
	}

	return result, nil
}

// GetFilesByTags retrieves files that have specific tags
func (ds *DriveService) GetFilesByTags(userID string, tags []string, matchAll bool, page, limit int) ([]models.File, int64, error) {
	if len(tags) == 0 {
		return []models.File{}, 0, nil
	}

	// Clean tags
	cleanTags := make([]string, 0, len(tags))
	for _, tag := range tags {
		cleanTag := strings.TrimSpace(strings.ToLower(tag))
		if cleanTag != "" {
			cleanTags = append(cleanTags, cleanTag)
		}
	}

	if len(cleanTags) == 0 {
		return []models.File{}, 0, nil
	}

	query := facades.Orm().Query().
		Where("owner_id", userID).
		Where("is_trashed", false).
		WhereNotNull("tags").
		Where("tags", "!=", "").
		Where("tags", "!=", "[]")

	if matchAll {
		// Must have ALL specified tags
		for _, tag := range cleanTags {
			query = query.Where("tags", "LIKE", "%\""+tag+"\"%")
		}
	} else {
		// Must have ANY of the specified tags
		for i, tag := range cleanTags {
			if i == 0 {
				query = query.Where("tags", "LIKE", "%\""+tag+"\"%")
			} else {
				query = query.OrWhere("tags", "LIKE", "%\""+tag+"\"%")
			}
		}
	}

	// Get total count
	total, _ := query.Count()

	// Get paginated results
	var files []models.File
	offset := (page - 1) * limit
	err := query.With("Owner").With("Folder").
		Offset(offset).Limit(limit).
		OrderBy("updated_at", "desc").
		Find(&files)

	return files, total, err
}

// SuggestTags suggests tags based on file name and existing tags
func (ds *DriveService) SuggestTags(userID, filename string) ([]string, error) {
	suggestions := make(map[string]bool)

	// Get user's existing tags
	userTags, err := ds.GetAllUserTags(userID)
	if err == nil {
		// Suggest tags based on filename similarity
		filenameLower := strings.ToLower(filename)
		for _, tag := range userTags {
			// Simple similarity check
			if strings.Contains(filenameLower, tag) || strings.Contains(tag, filenameLower) {
				suggestions[tag] = true
			}
		}
	}

	// Suggest common tags based on file extension
	ext := strings.ToLower(filepath.Ext(filename))
	commonTags := map[string][]string{
		".pdf":  {"document", "pdf", "report"},
		".doc":  {"document", "word", "text"},
		".docx": {"document", "word", "text"},
		".xls":  {"spreadsheet", "excel", "data"},
		".xlsx": {"spreadsheet", "excel", "data"},
		".ppt":  {"presentation", "powerpoint", "slides"},
		".pptx": {"presentation", "powerpoint", "slides"},
		".jpg":  {"image", "photo", "picture"},
		".jpeg": {"image", "photo", "picture"},
		".png":  {"image", "graphic", "picture"},
		".gif":  {"image", "animation", "graphic"},
		".mp4":  {"video", "movie", "media"},
		".avi":  {"video", "movie", "media"},
		".mp3":  {"audio", "music", "sound"},
		".wav":  {"audio", "music", "sound"},
		".zip":  {"archive", "compressed", "backup"},
		".rar":  {"archive", "compressed", "backup"},
	}

	if extTags, exists := commonTags[ext]; exists {
		for _, tag := range extTags {
			suggestions[tag] = true
		}
	}

	// Convert to slice
	result := make([]string, 0, len(suggestions))
	for tag := range suggestions {
		result = append(result, tag)
	}

	// Sort suggestions
	sort.Strings(result)

	// Limit to 5 suggestions
	if len(result) > 5 {
		result = result[:5]
	}

	return result, nil
}

// OrganizeFilesByTags creates a hierarchical organization of files by tags
func (ds *DriveService) OrganizeFilesByTags(userID string) (map[string]interface{}, error) {
	var files []models.File
	err := facades.Orm().Query().
		Where("owner_id", userID).
		Where("is_trashed", false).
		WhereNotNull("tags").
		Where("tags", "!=", "").
		Where("tags", "!=", "[]").
		With("Folder").
		Find(&files)
	if err != nil {
		return nil, fmt.Errorf("failed to get user files: %v", err)
	}

	organization := make(map[string]interface{})
	taggedFiles := make(map[string][]models.File)
	untaggedFiles := make([]models.File, 0)

	// Organize files by tags
	for _, file := range files {
		var fileTags []string
		if err := json.Unmarshal([]byte(file.Tags), &fileTags); err == nil && len(fileTags) > 0 {
			for _, tag := range fileTags {
				taggedFiles[tag] = append(taggedFiles[tag], file)
			}
		} else {
			untaggedFiles = append(untaggedFiles, file)
		}
	}

	// Sort tags by number of files (descending)
	type tagGroup struct {
		Tag   string        `json:"tag"`
		Count int           `json:"count"`
		Files []models.File `json:"files"`
	}

	var tagGroups []tagGroup
	for tag, files := range taggedFiles {
		tagGroups = append(tagGroups, tagGroup{
			Tag:   tag,
			Count: len(files),
			Files: files,
		})
	}

	sort.Slice(tagGroups, func(i, j int) bool {
		if tagGroups[i].Count == tagGroups[j].Count {
			return tagGroups[i].Tag < tagGroups[j].Tag
		}
		return tagGroups[i].Count > tagGroups[j].Count
	})

	organization["by_tags"] = tagGroups
	organization["untagged"] = map[string]interface{}{
		"count": len(untaggedFiles),
		"files": untaggedFiles,
	}
	organization["summary"] = map[string]interface{}{
		"total_tags":           len(tagGroups),
		"total_tagged_files":   len(files),
		"total_untagged_files": len(untaggedFiles),
	}

	return organization, nil
}

// Helper methods

func (ds *DriveService) calculateHash(content io.Reader) (string, error) {
	hasher := sha256.New()
	if _, err := io.Copy(hasher, content); err != nil {
		return "", err
	}
	return "sha256:" + hex.EncodeToString(hasher.Sum(nil)), nil
}

func (ds *DriveService) detectMimeType(filename string) string {
	mimeType := mime.TypeByExtension(filepath.Ext(filename))
	if mimeType == "" {
		return "application/octet-stream"
	}
	return mimeType
}

func (ds *DriveService) generateUniqueFilename(filename, userID string, folderID *string) string {
	// Check if filename already exists
	query := facades.Orm().Query().Where("owner_id", userID).Where("name", filename)
	if folderID != nil {
		query = query.Where("folder_id", *folderID)
	} else {
		query = query.WhereNull("folder_id")
	}

	count, _ := query.Count()

	if count == 0 {
		return filename
	}

	// Generate unique filename
	ext := filepath.Ext(filename)
	base := strings.TrimSuffix(filename, ext)

	for i := 1; ; i++ {
		newName := fmt.Sprintf("%s (%d)%s", base, i, ext)
		query = facades.Orm().Query().Where("owner_id", userID).Where("name", newName)
		if folderID != nil {
			query = query.Where("folder_id", *folderID)
		} else {
			query = query.WhereNull("folder_id")
		}

		count, _ = query.Count()
		if count == 0 {
			return newName
		}
	}
}

func (ds *DriveService) generateShareToken() string {
	return strings.ReplaceAll(uuid.New().String(), "-", "")
}

func (ds *DriveService) CanAccessFile(file *models.File, userID *string) bool {
	// Owner always has access
	if userID != nil && file.OwnerID == *userID {
		return true
	}

	// Public files are accessible
	if file.IsPublic {
		return true
	}

	// Check if file is shared with user
	if userID != nil {
		var share models.FileShare
		err := facades.Orm().Query().Where("file_id", file.ID).
			Where("shared_with_id", *userID).
			Where("is_active", true).
			First(&share)
		if err == nil && !share.IsExpired() {
			return true
		}
	}

	return false
}

func (ds *DriveService) logFileActivity(fileID, userID, action, description string, ctx context.Context) {
	ds.logFileActivityWithMetadata(fileID, userID, action, description, nil, ctx)
}

func (ds *DriveService) logFileActivityWithMetadata(fileID, userID, action, description string, metadata map[string]interface{}, ctx context.Context) {
	activity := &models.FileActivity{
		Action:      action,
		Description: description,
		FileID:      fileID,
		UserID:      &userID,
	}

	if metadata != nil {
		// Convert metadata to JSON string
		activity.Metadata = fmt.Sprintf("%v", metadata)
	}

	facades.Orm().Query().Create(&activity)
}

func (ds *DriveService) logFolderActivity(folderID, userID, action, description string, ctx context.Context) {
	activity := &models.FolderActivity{
		Action:      action,
		Description: description,
		FolderID:    folderID,
		UserID:      &userID,
	}

	facades.Orm().Query().Create(&activity)
}

// DuplicateFile represents a duplicate file
type DuplicateFile struct {
	Hash          string        `json:"hash"`
	Size          int64         `json:"size"`
	Count         int           `json:"count"`
	TotalSize     int64         `json:"total_size"`
	Files         []models.File `json:"files"`
	PotentialSave int64         `json:"potential_save"`
}

// FindDuplicateFiles finds duplicate files based on hash
func (ds *DriveService) FindDuplicateFiles(userID string) ([]DuplicateFile, error) {
	// Get all files with their hashes
	var files []models.File
	err := facades.Orm().Query().
		Where("owner_id", userID).
		Where("is_trashed", false).
		WhereNotNull("hash").
		Where("hash", "!=", "").
		With("Folder").
		OrderBy("hash", "asc").
		OrderBy("created_at", "asc").
		Find(&files)
	if err != nil {
		return nil, fmt.Errorf("failed to get user files: %v", err)
	}

	// Group files by hash
	hashGroups := make(map[string][]models.File)
	for _, file := range files {
		hashGroups[file.Hash] = append(hashGroups[file.Hash], file)
	}

	// Find duplicates (groups with more than 1 file)
	var duplicates []DuplicateFile
	for hash, groupFiles := range hashGroups {
		if len(groupFiles) > 1 {
			totalSize := int64(len(groupFiles)) * groupFiles[0].Size
			potentialSave := int64(len(groupFiles)-1) * groupFiles[0].Size

			duplicate := DuplicateFile{
				Hash:          hash,
				Size:          groupFiles[0].Size,
				Count:         len(groupFiles),
				TotalSize:     totalSize,
				Files:         groupFiles,
				PotentialSave: potentialSave,
			}
			duplicates = append(duplicates, duplicate)
		}
	}

	// Sort by potential space savings (descending)
	sort.Slice(duplicates, func(i, j int) bool {
		return duplicates[i].PotentialSave > duplicates[j].PotentialSave
	})

	return duplicates, nil
}

// GetDuplicateStats returns statistics about duplicate files
func (ds *DriveService) GetDuplicateStats(userID string) (map[string]interface{}, error) {
	duplicates, err := ds.FindDuplicateFiles(userID)
	if err != nil {
		return nil, err
	}

	totalDuplicateFiles := 0
	totalPotentialSave := int64(0)
	duplicateGroups := len(duplicates)

	for _, dup := range duplicates {
		totalDuplicateFiles += dup.Count
		totalPotentialSave += dup.PotentialSave
	}

	stats := map[string]interface{}{
		"duplicate_groups":      duplicateGroups,
		"total_duplicate_files": totalDuplicateFiles,
		"potential_save_bytes":  totalPotentialSave,
		"potential_save_mb":     float64(totalPotentialSave) / (1024 * 1024),
		"largest_duplicates": func() []DuplicateFile {
			if len(duplicates) > 5 {
				return duplicates[:5]
			}
			return duplicates
		}(),
	}

	return stats, nil
}

// ResolveDuplicates handles duplicate resolution by keeping one file and removing others
func (ds *DriveService) ResolveDuplicates(ctx context.Context, userID, hash, keepFileID string) (*BulkOperationResult, error) {
	// Get all files with this hash
	var files []models.File
	err := facades.Orm().Query().
		Where("owner_id", userID).
		Where("hash", hash).
		Where("is_trashed", false).
		Find(&files)
	if err != nil {
		return nil, fmt.Errorf("failed to get duplicate files: %v", err)
	}

	if len(files) <= 1 {
		return nil, fmt.Errorf("no duplicates found for this hash")
	}

	// Verify the file to keep exists in the group
	var keepFile *models.File
	var filesToRemove []string

	for _, file := range files {
		if file.ID == keepFileID {
			keepFile = &file
		} else {
			filesToRemove = append(filesToRemove, file.ID)
		}
	}

	if keepFile == nil {
		return nil, fmt.Errorf("file to keep not found in duplicate group")
	}

	// Use bulk delete to remove duplicates
	result, err := ds.BulkDeleteFiles(ctx, userID, filesToRemove)
	if err != nil {
		return nil, fmt.Errorf("failed to remove duplicate files: %v", err)
	}

	// Log the resolution
	ds.logFileActivity(keepFile.ID, userID, "duplicate_resolve",
		fmt.Sprintf("Resolved duplicates, kept this file, removed %d duplicates", len(filesToRemove)), ctx)

	return result, nil
}

// FindSimilarFiles finds files with similar names or content
func (ds *DriveService) FindSimilarFiles(userID string, threshold float64) ([]map[string]interface{}, error) {
	if threshold <= 0 || threshold > 1 {
		threshold = 0.8 // Default 80% similarity
	}

	var files []models.File
	err := facades.Orm().Query().
		Where("owner_id", userID).
		Where("is_trashed", false).
		With("Folder").
		OrderBy("name", "asc").
		Find(&files)
	if err != nil {
		return nil, fmt.Errorf("failed to get user files: %v", err)
	}

	var similarGroups []map[string]interface{}
	processed := make(map[string]bool)

	for i, file1 := range files {
		if processed[file1.ID] {
			continue
		}

		var similarFiles []models.File
		similarFiles = append(similarFiles, file1)

		for j := i + 1; j < len(files); j++ {
			file2 := files[j]
			if processed[file2.ID] {
				continue
			}

			// Check name similarity
			similarity := ds.calculateStringSimilarity(file1.Name, file2.Name)

			// Also check if they have same size (potential duplicates)
			sameSizeBonus := 0.0
			if file1.Size == file2.Size && file1.Size > 0 {
				sameSizeBonus = 0.2
			}

			totalSimilarity := similarity + sameSizeBonus
			if totalSimilarity >= threshold {
				similarFiles = append(similarFiles, file2)
				processed[file2.ID] = true
			}
		}

		if len(similarFiles) > 1 {
			// Calculate potential space savings if these are duplicates
			potentialSave := int64(0)
			if len(similarFiles) > 1 {
				// Assume we keep the oldest file and remove others
				for i := 1; i < len(similarFiles); i++ {
					potentialSave += similarFiles[i].Size
				}
			}

			group := map[string]interface{}{
				"similarity_score":  threshold,
				"file_count":        len(similarFiles),
				"files":             similarFiles,
				"potential_save":    potentialSave,
				"potential_save_mb": float64(potentialSave) / (1024 * 1024),
			}
			similarGroups = append(similarGroups, group)
		}

		processed[file1.ID] = true
	}

	// Sort by potential savings
	sort.Slice(similarGroups, func(i, j int) bool {
		return similarGroups[i]["potential_save"].(int64) > similarGroups[j]["potential_save"].(int64)
	})

	return similarGroups, nil
}

// calculateStringSimilarity calculates similarity between two strings using Levenshtein distance
func (ds *DriveService) calculateStringSimilarity(s1, s2 string) float64 {
	s1 = strings.ToLower(s1)
	s2 = strings.ToLower(s2)

	if s1 == s2 {
		return 1.0
	}

	if len(s1) == 0 || len(s2) == 0 {
		return 0.0
	}

	// Simple similarity based on common substrings
	longer := s1
	shorter := s2
	if len(s2) > len(s1) {
		longer = s2
		shorter = s1
	}

	longerLen := len(longer)
	if longerLen == 0 {
		return 1.0
	}

	// Count common characters
	commonChars := 0
	for _, char := range shorter {
		if strings.ContainsRune(longer, char) {
			commonChars++
		}
	}

	return float64(commonChars) / float64(longerLen)
}

// GetDuplicateManagementSuggestions provides suggestions for managing duplicates
func (ds *DriveService) GetDuplicateManagementSuggestions(userID string) (map[string]interface{}, error) {
	// Get duplicate stats
	duplicateStats, err := ds.GetDuplicateStats(userID)
	if err != nil {
		return nil, err
	}

	// Get similar files
	similarFiles, err := ds.FindSimilarFiles(userID, 0.7)
	if err != nil {
		return nil, err
	}

	// Get storage quota to show impact
	quota, err := ds.GetStorageQuota(context.Background(), userID)
	if err != nil {
		return nil, err
	}

	suggestions := map[string]interface{}{
		"duplicate_stats": duplicateStats,
		"similar_files":   similarFiles[:minInt(5, len(similarFiles))], // Top 5
		"storage_impact": map[string]interface{}{
			"current_usage_percent": quota.UsagePercent,
			"potential_reduction":   float64(duplicateStats["potential_save_bytes"].(int64)) / float64(quota.TotalQuota) * 100,
		},
		"recommendations": []string{
			"Review duplicate files and keep only the most recent or relevant versions",
			"Use tags to organize similar files instead of creating duplicates",
			"Consider using file versioning instead of keeping multiple copies",
			"Regularly clean up old files to maintain storage efficiency",
		},
	}

	return suggestions, nil
}

// minInt helper function
func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// ActivityInsight represents user activity insights
type ActivityInsight struct {
	Period           string                 `json:"period"`
	TotalActions     int64                  `json:"total_actions"`
	TopActions       []ActionStat           `json:"top_actions"`
	ActiveDays       int                    `json:"active_days"`
	PeakHours        []int                  `json:"peak_hours"`
	FileTypeActivity map[string]int         `json:"file_type_activity"`
	FolderActivity   map[string]int         `json:"folder_activity"`
	Trends           map[string]interface{} `json:"trends"`
}

// ActionStat represents statistics for a specific action
type ActionStat struct {
	Action string `json:"action"`
	Count  int64  `json:"count"`
}

// SmartRecommendation represents a smart recommendation for the user
type SmartRecommendation struct {
	Type        string                 `json:"type"`
	Title       string                 `json:"title"`
	Description string                 `json:"description"`
	Priority    string                 `json:"priority"` // high, medium, low
	ActionURL   string                 `json:"action_url,omitempty"`
	Data        map[string]interface{} `json:"data,omitempty"`
	CreatedAt   time.Time              `json:"created_at"`
}

// GetUserActivityInsights provides detailed insights about user activity
func (ds *DriveService) GetUserActivityInsights(userID string, period string) (*ActivityInsight, error) {
	var startDate time.Time
	var periodName string

	switch period {
	case "week":
		startDate = time.Now().AddDate(0, 0, -7)
		periodName = "Last 7 days"
	case "month":
		startDate = time.Now().AddDate(0, -1, 0)
		periodName = "Last 30 days"
	case "quarter":
		startDate = time.Now().AddDate(0, -3, 0)
		periodName = "Last 3 months"
	default:
		startDate = time.Now().AddDate(0, 0, -7)
		periodName = "Last 7 days"
	}

	// Get all activities in the period
	var activities []models.FileActivity
	err := facades.Orm().Query().
		Where("user_id", userID).
		Where("created_at", ">=", startDate).
		With("File").
		OrderBy("created_at", "desc").
		Find(&activities)
	if err != nil {
		return nil, fmt.Errorf("failed to get user activities: %v", err)
	}

	// Analyze activities
	actionCounts := make(map[string]int64)
	hourCounts := make(map[int]int)
	daySet := make(map[string]bool)
	fileTypeActivity := make(map[string]int)
	folderActivity := make(map[string]int)

	for _, activity := range activities {
		// Count actions
		actionCounts[activity.Action]++

		// Count by hour
		hour := activity.CreatedAt.Hour()
		hourCounts[hour]++

		// Count active days
		dayKey := activity.CreatedAt.Format("2006-01-02")
		daySet[dayKey] = true

		// File type activity
		if activity.File != nil {
			ext := filepath.Ext(activity.File.Name)
			if ext != "" {
				fileTypeActivity[ext]++
			}

			// Folder activity
			if activity.File.FolderID != nil {
				folderActivity[*activity.File.FolderID]++
			} else {
				folderActivity["root"]++
			}
		}
	}

	// Get top actions
	var topActions []ActionStat
	for action, count := range actionCounts {
		topActions = append(topActions, ActionStat{
			Action: action,
			Count:  count,
		})
	}
	sort.Slice(topActions, func(i, j int) bool {
		return topActions[i].Count > topActions[j].Count
	})

	// Get peak hours
	var peakHours []int
	maxCount := 0
	for hour, count := range hourCounts {
		if count > maxCount {
			maxCount = count
			peakHours = []int{hour}
		} else if count == maxCount {
			peakHours = append(peakHours, hour)
		}
	}

	// Calculate trends
	trends := ds.calculateActivityTrends(activities, startDate)

	insight := &ActivityInsight{
		Period:           periodName,
		TotalActions:     int64(len(activities)),
		TopActions:       topActions,
		ActiveDays:       len(daySet),
		PeakHours:        peakHours,
		FileTypeActivity: fileTypeActivity,
		FolderActivity:   folderActivity,
		Trends:           trends,
	}

	return insight, nil
}

// calculateActivityTrends calculates activity trends over time
func (ds *DriveService) calculateActivityTrends(activities []models.FileActivity, startDate time.Time) map[string]interface{} {
	trends := make(map[string]interface{})

	// Group activities by day
	dailyActivity := make(map[string]int)
	for _, activity := range activities {
		dayKey := activity.CreatedAt.Format("2006-01-02")
		dailyActivity[dayKey]++
	}

	// Calculate trend direction
	days := make([]string, 0, len(dailyActivity))
	for day := range dailyActivity {
		days = append(days, day)
	}
	sort.Strings(days)

	if len(days) >= 2 {
		firstHalf := 0
		secondHalf := 0
		midPoint := len(days) / 2

		for i, day := range days {
			if i < midPoint {
				firstHalf += dailyActivity[day]
			} else {
				secondHalf += dailyActivity[day]
			}
		}

		trendDirection := "stable"
		if float64(secondHalf) > float64(firstHalf)*1.2 {
			trendDirection = "increasing"
		} else if float64(secondHalf) < float64(firstHalf)*0.8 {
			trendDirection = "decreasing"
		}

		trends["direction"] = trendDirection
		trends["change_percent"] = float64(secondHalf-firstHalf) / float64(firstHalf) * 100
	}

	trends["daily_activity"] = dailyActivity
	return trends
}

// GetSmartRecommendations generates smart recommendations for the user
func (ds *DriveService) GetSmartRecommendations(userID string) ([]SmartRecommendation, error) {
	var recommendations []SmartRecommendation

	// Get user's file statistics
	quota, err := ds.GetStorageQuota(context.Background(), userID)
	if err == nil {
		// Storage recommendations
		if quota.UsagePercent > 80 {
			recommendations = append(recommendations, SmartRecommendation{
				Type:        "storage_warning",
				Title:       "Storage Almost Full",
				Description: fmt.Sprintf("You're using %.1f%% of your storage. Consider cleaning up old files.", quota.UsagePercent),
				Priority:    "high",
				ActionURL:   "/api/v1/drive/cleanup",
				CreatedAt:   time.Now(),
			})
		}
	}

	// Duplicate file recommendations
	duplicateStats, err := ds.GetDuplicateStats(userID)
	if err == nil {
		if duplicateGroups, ok := duplicateStats["duplicate_groups"].(int); ok && duplicateGroups > 0 {
			potentialSave := duplicateStats["potential_save_mb"].(float64)
			recommendations = append(recommendations, SmartRecommendation{
				Type:        "duplicate_cleanup",
				Title:       "Duplicate Files Found",
				Description: fmt.Sprintf("Found %d groups of duplicate files. You could save %.1f MB by removing duplicates.", duplicateGroups, potentialSave),
				Priority:    "medium",
				ActionURL:   "/api/v1/drive/duplicates",
				Data:        duplicateStats,
				CreatedAt:   time.Now(),
			})
		}
	}

	// Untagged files recommendation
	var untaggedCount int64
	untaggedCount, err = facades.Orm().Query().
		Model(&models.File{}).
		Where("owner_id", userID).
		Where("is_trashed", false).
		Where("tags IS NULL OR tags = '' OR tags = '[]'").
		Count()

	if err == nil && untaggedCount > 10 {
		recommendations = append(recommendations, SmartRecommendation{
			Type:        "organization",
			Title:       "Organize Your Files",
			Description: fmt.Sprintf("You have %d untagged files. Adding tags will help you find files faster.", untaggedCount),
			Priority:    "low",
			ActionURL:   "/api/v1/drive/tags/suggest",
			Data: map[string]interface{}{
				"untagged_count": untaggedCount,
			},
			CreatedAt: time.Now(),
		})
	}

	// Recent activity recommendations
	activities, err := ds.GetUserActivityInsights(userID, "week")
	if err == nil {
		if activities.TotalActions == 0 {
			recommendations = append(recommendations, SmartRecommendation{
				Type:        "engagement",
				Title:       "Start Using Your Drive",
				Description: "Upload your first file to get started with organizing your documents.",
				Priority:    "low",
				ActionURL:   "/api/v1/drive/files",
				CreatedAt:   time.Now(),
			})
		} else if activities.TotalActions < 5 {
			recommendations = append(recommendations, SmartRecommendation{
				Type:        "engagement",
				Title:       "Explore More Features",
				Description: "Try using folders and tags to better organize your files.",
				Priority:    "low",
				CreatedAt:   time.Now(),
			})
		}
	}

	// Large files recommendation
	largestFiles, err := ds.GetLargestFiles(context.Background(), userID, 5)
	if err == nil && len(largestFiles) > 0 {
		totalLargeSize := int64(0)
		for _, file := range largestFiles {
			if file.Size > 50*1024*1024 { // Files larger than 50MB
				totalLargeSize += file.Size
			}
		}

		if totalLargeSize > 0 {
			recommendations = append(recommendations, SmartRecommendation{
				Type:        "optimization",
				Title:       "Large Files Detected",
				Description: fmt.Sprintf("You have large files taking up %.1f MB. Consider archiving or compressing them.", float64(totalLargeSize)/(1024*1024)),
				Priority:    "medium",
				Data: map[string]interface{}{
					"large_files": largestFiles,
					"total_size":  totalLargeSize,
				},
				CreatedAt: time.Now(),
			})
		}
	}

	// Sort recommendations by priority
	sort.Slice(recommendations, func(i, j int) bool {
		priorityOrder := map[string]int{"high": 3, "medium": 2, "low": 1}
		return priorityOrder[recommendations[i].Priority] > priorityOrder[recommendations[j].Priority]
	})

	return recommendations, nil
}

// GetFrequentlyAccessedFiles returns files that are accessed frequently
func (ds *DriveService) GetFrequentlyAccessedFiles(userID string, limit int) ([]models.File, error) {
	var files []models.File
	err := facades.Orm().Query().
		Where("owner_id", userID).
		Where("is_trashed", false).
		Where("download_count", ">", 0).
		With("Folder").
		OrderBy("download_count", "desc").
		OrderBy("last_accessed_at", "desc").
		Limit(limit).
		Find(&files)

	return files, err
}

// GetRecommendedFiles suggests files based on user activity patterns
func (ds *DriveService) GetRecommendedFiles(userID string, limit int) ([]models.File, error) {
	// Get user's recent activity to understand patterns
	weekAgo := time.Now().AddDate(0, 0, -7)
	var recentActivities []models.FileActivity
	err := facades.Orm().Query().
		Where("user_id", userID).
		Where("created_at", ">=", weekAgo).
		With("File").
		Find(&recentActivities)
	if err != nil {
		return nil, err
	}

	// Analyze patterns - files in similar folders, with similar tags, or similar types
	folderFreq := make(map[string]int)
	typeFreq := make(map[string]int)
	recentFileIDs := make(map[string]bool)

	for _, activity := range recentActivities {
		if activity.File != nil {
			recentFileIDs[activity.File.ID] = true

			if activity.File.FolderID != nil {
				folderFreq[*activity.File.FolderID]++
			}

			ext := filepath.Ext(activity.File.Name)
			if ext != "" {
				typeFreq[ext]++
			}
		}
	}

	// Find files in frequently accessed folders or with similar types
	query := facades.Orm().Query().
		Where("owner_id", userID).
		Where("is_trashed", false)

	// Exclude recently accessed files
	if len(recentFileIDs) > 0 {
		recentIDs := make([]interface{}, 0, len(recentFileIDs))
		for id := range recentFileIDs {
			recentIDs = append(recentIDs, id)
		}
		query = query.WhereNotIn("id", recentIDs)
	}

	var recommendedFiles []models.File
	err = query.With("Folder").
		OrderBy("created_at", "desc").
		Limit(limit * 2). // Get more to filter
		Find(&recommendedFiles)
	if err != nil {
		return nil, err
	}

	// Score and sort recommendations
	type scoredFile struct {
		File  models.File
		Score int
	}

	var scored []scoredFile
	for _, file := range recommendedFiles {
		score := 0

		// Boost score for files in frequently accessed folders
		if file.FolderID != nil {
			if freq, exists := folderFreq[*file.FolderID]; exists {
				score += freq * 2
			}
		}

		// Boost score for files with frequently accessed types
		ext := filepath.Ext(file.Name)
		if freq, exists := typeFreq[ext]; exists {
			score += freq
		}

		// Boost score for recently created files
		if file.CreatedAt.After(weekAgo) {
			score += 3
		}

		// Boost score for starred files
		if file.IsStarred {
			score += 5
		}

		if score > 0 {
			scored = append(scored, scoredFile{File: file, Score: score})
		}
	}

	// Sort by score and return top results
	sort.Slice(scored, func(i, j int) bool {
		return scored[i].Score > scored[j].Score
	})

	var result []models.File
	for i, sf := range scored {
		if i >= limit {
			break
		}
		result = append(result, sf.File)
	}

	return result, nil
}

// GetWorkspaceInsights provides insights about the user's workspace organization
func (ds *DriveService) GetWorkspaceInsights(userID string) (map[string]interface{}, error) {
	insights := make(map[string]interface{})

	// Get basic statistics
	quota, err := ds.GetStorageQuota(context.Background(), userID)
	if err != nil {
		return nil, err
	}

	// Get folder depth analysis
	var folders []models.Folder
	err = facades.Orm().Query().
		Where("owner_id", userID).
		Where("is_trashed", false).
		Find(&folders)
	if err != nil {
		return nil, err
	}

	maxDepth := 0
	avgDepth := 0
	for _, folder := range folders {
		if folder.Level > maxDepth {
			maxDepth = folder.Level
		}
		avgDepth += folder.Level
	}
	if len(folders) > 0 {
		avgDepth = avgDepth / len(folders)
	}

	// Get file distribution
	var files []models.File
	err = facades.Orm().Query().
		Where("owner_id", userID).
		Where("is_trashed", false).
		Select("folder_id", "mime_type").
		Find(&files)
	if err != nil {
		return nil, err
	}

	rootFiles := 0
	for _, file := range files {
		if file.FolderID == nil {
			rootFiles++
		}
	}

	// Organization score (0-100)
	organizationScore := 100
	if rootFiles > 10 {
		organizationScore -= 20 // Penalty for too many root files
	}
	if maxDepth > 5 {
		organizationScore -= 15 // Penalty for too deep folders
	}
	if quota.UsagePercent > 90 {
		organizationScore -= 25 // Penalty for high storage usage
	}

	taggedFileCount := int64(0)
	taggedFileCount, _ = facades.Orm().Query().
		Model(&models.File{}).
		Where("owner_id", userID).
		Where("is_trashed", false).
		WhereNotNull("tags").
		Where("tags", "!=", "").
		Where("tags", "!=", "[]").
		Count()

	taggedPercentage := 0.0
	if quota.FileCount > 0 {
		taggedPercentage = float64(taggedFileCount) / float64(quota.FileCount) * 100
	}

	if taggedPercentage < 30 {
		organizationScore -= 20 // Penalty for low tagging
	}

	if organizationScore < 0 {
		organizationScore = 0
	}

	insights["storage"] = map[string]interface{}{
		"usage_percent": quota.UsagePercent,
		"file_count":    quota.FileCount,
		"folder_count":  quota.FolderCount,
	}

	insights["organization"] = map[string]interface{}{
		"score":             organizationScore,
		"max_folder_depth":  maxDepth,
		"avg_folder_depth":  avgDepth,
		"root_files":        rootFiles,
		"tagged_percentage": taggedPercentage,
	}

	insights["recommendations"] = []string{}
	if rootFiles > 10 {
		insights["recommendations"] = append(insights["recommendations"].([]string), "Consider organizing root files into folders")
	}
	if taggedPercentage < 30 {
		insights["recommendations"] = append(insights["recommendations"].([]string), "Add tags to improve file discoverability")
	}

	return insights, nil
}

// sendFileCommentNotification sends a notification to the file owner about a new comment
func (ds *DriveService) sendFileCommentNotification(file *models.File, commenterID, commentContent string) error {
	// Get commenter information
	var commenter models.User
	if err := facades.Orm().Query().Find(&commenter, commenterID); err != nil {
		return fmt.Errorf("failed to get commenter information: %w", err)
	}

	// Get file owner information
	var owner models.User
	if err := facades.Orm().Query().Find(&owner, file.OwnerID); err != nil {
		return fmt.Errorf("failed to get file owner information: %w", err)
	}

	// Create notification data
	notificationData := map[string]interface{}{
		"file_name":       file.Name,
		"file_id":         file.ID,
		"commenter_name":  commenter.Name,
		"commenter_email": commenter.Email,
		"comment_content": commentContent,
		"file_path":       file.Path,
	}

	// Create notification
	notification := &models.Notification{
		NotifiableID:   owner.ID,
		NotifiableType: "user",
		Type:           "file_comment",
		Data:           notificationData,
		ReadAt:         nil,
	}

	// Save notification
	if err := facades.Orm().Query().Create(notification); err != nil {
		return fmt.Errorf("failed to create notification: %w", err)
	}

	// Log successful notification creation
	facades.Log().Info("File comment notification created", map[string]interface{}{
		"notification_id": notification.ID,
		"file_id":         file.ID,
		"owner_id":        owner.ID,
		"commenter_id":    commenterID,
	})

	return nil
}
