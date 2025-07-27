package v1

import (
	"context"
	"fmt"
	"goravel/app/http/requests"
	"goravel/app/http/responses"
	"goravel/app/models"
	"goravel/app/services"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/goravel/framework/contracts/http"
	"github.com/goravel/framework/facades"
)

type DriveController struct {
	driveService *services.DriveService
}

func NewDriveController() *DriveController {
	return &DriveController{
		driveService: services.NewDriveService(),
	}
}

// UploadFile handles file upload
// @Summary Upload a file
// @Description Upload a file to the drive
// @Tags Drive
// @Accept multipart/form-data
// @Produce json
// @Param file formData file true "File to upload"
// @Param folder_id formData string false "Folder ID to upload to"
// @Success 201 {object} responses.APIResponse{data=models.File}
// @Failure 400 {object} responses.APIResponse
// @Failure 401 {object} responses.APIResponse
// @Router /api/v1/drive/files [post]
func (dc *DriveController) UploadFile(ctx http.Context) http.Response {
	// Validate request
	var uploadRequest requests.FileUploadRequest
	if err := ctx.Request().Bind(&uploadRequest); err != nil {
		return responses.BadRequest(ctx, "Invalid request", err.Error())
	}

	// Get authenticated user
	userID := ctx.Value("user_id").(string)
	tenantID := ctx.Value("tenant_id").(*string)

	// Get uploaded file
	file, err := ctx.Request().File("file")
	if err != nil {
		return responses.BadRequest(ctx, "No file uploaded", err.Error())
	}

	// Get file size
	fileSize, err := file.Size()
	if err != nil {
		return responses.BadRequest(ctx, "Failed to get file size", err.Error())
	}

	// Get file path for reading
	filePath := file.File()

	// Open file for reading
	fileReader, err := os.Open(filePath)
	if err != nil {
		return responses.BadRequest(ctx, "Failed to read file", err.Error())
	}
	defer fileReader.Close()

	// Upload file
	uploadedFile, err := dc.driveService.UploadFile(
		context.Background(),
		userID,
		uploadRequest.FolderID,
		file.GetClientOriginalName(),
		fileReader,
		fileSize,
		tenantID,
	)
	if err != nil {
		return responses.InternalServerError(ctx, "Failed to upload file", err.Error())
	}

	return responses.Created(ctx, "File uploaded successfully", uploadedFile)
}

// GetFiles retrieves files in a folder
// @Summary Get files
// @Description Get files in a folder
// @Tags Drive
// @Produce json
// @Param folder_id query string false "Folder ID"
// @Param page query int false "Page number" default(1)
// @Param limit query int false "Items per page" default(20)
// @Param search query string false "Search term"
// @Success 200 {object} responses.PaginatedResponse{data=[]models.File}
// @Failure 401 {object} responses.APIResponse
// @Router /api/v1/drive/files [get]
func (dc *DriveController) GetFiles(ctx http.Context) http.Response {
	// Get authenticated user
	userID := ctx.Value("user_id").(string)

	// Parse query parameters
	folderID := ctx.Request().Query("folder_id", "")
	var folderIDPtr *string
	if folderID != "" {
		folderIDPtr = &folderID
	}

	page, _ := strconv.Atoi(ctx.Request().Query("page", "1"))
	limit, _ := strconv.Atoi(ctx.Request().Query("limit", "20"))
	search := ctx.Request().Query("search", "")

	// Get files
	files, total, err := dc.driveService.GetFiles(userID, folderIDPtr, page, limit, search)
	if err != nil {
		return responses.InternalServerError(ctx, "Failed to get files", err.Error())
	}

	return responses.PaginatedSuccess(ctx, "Files retrieved successfully", files, total, page, limit)
}

// CreateFolder creates a new folder
// @Summary Create folder
// @Description Create a new folder
// @Tags Drive
// @Accept json
// @Produce json
// @Param request body requests.CreateFolderRequest true "Folder data"
// @Success 201 {object} responses.APIResponse{data=models.Folder}
// @Failure 400 {object} responses.APIResponse
// @Failure 401 {object} responses.APIResponse
// @Router /api/v1/drive/folders [post]
func (dc *DriveController) CreateFolder(ctx http.Context) http.Response {
	// Validate request
	var folderRequest requests.CreateFolderRequest
	if err := ctx.Request().Bind(&folderRequest); err != nil {
		return responses.BadRequest(ctx, "Invalid request", err.Error())
	}

	// Get authenticated user
	userID := ctx.Value("user_id").(string)
	tenantID := ctx.Value("tenant_id").(*string)

	// Create folder
	folder, err := dc.driveService.CreateFolder(
		context.Background(),
		userID,
		folderRequest.ParentID,
		folderRequest.Name,
		tenantID,
	)
	if err != nil {
		return responses.BadRequest(ctx, "Failed to create folder", err.Error())
	}

	return responses.Created(ctx, "Folder created successfully", folder)
}

// GetFolders retrieves folders
// @Summary Get folders
// @Description Get folders in a parent folder
// @Tags Drive
// @Produce json
// @Param parent_id query string false "Parent folder ID"
// @Param page query int false "Page number" default(1)
// @Param limit query int false "Items per page" default(20)
// @Param search query string false "Search term"
// @Success 200 {object} responses.PaginatedResponse{data=[]models.Folder}
// @Failure 401 {object} responses.APIResponse
// @Router /api/v1/drive/folders [get]
func (dc *DriveController) GetFolders(ctx http.Context) http.Response {
	// Get authenticated user
	userID := ctx.Value("user_id").(string)

	// Parse query parameters
	parentID := ctx.Request().Query("parent_id", "")
	var parentIDPtr *string
	if parentID != "" {
		parentIDPtr = &parentID
	}

	page, _ := strconv.Atoi(ctx.Request().Query("page", "1"))
	limit, _ := strconv.Atoi(ctx.Request().Query("limit", "20"))
	search := ctx.Request().Query("search", "")

	// Get folders
	folders, total, err := dc.driveService.GetFolders(userID, parentIDPtr, page, limit, search)
	if err != nil {
		return responses.InternalServerError(ctx, "Failed to get folders", err.Error())
	}

	return responses.PaginatedSuccess(ctx, "Folders retrieved successfully", folders, total, page, limit)
}

// DownloadFile handles file download
// @Summary Download file
// @Description Download a file
// @Tags Drive
// @Produce application/octet-stream
// @Param id path string true "File ID"
// @Success 200 {file} binary "File content"
// @Failure 404 {object} responses.APIResponse
// @Failure 403 {object} responses.APIResponse
// @Router /api/v1/drive/files/{id}/download [get]
func (dc *DriveController) DownloadFile(ctx http.Context) http.Response {
	// Get file ID
	fileID := ctx.Request().Route("id")

	// Get authenticated user (optional for public files)
	var userID *string
	if uid := ctx.Value("user_id"); uid != nil {
		if uidStr, ok := uid.(string); ok {
			userID = &uidStr
		}
	}

	// Download file
	file, content, err := dc.driveService.DownloadFile(context.Background(), fileID, userID)
	if err != nil {
		if err.Error() == "access denied" {
			return responses.Forbidden(ctx, "Access denied", "You don't have permission to download this file")
		}
		return responses.NotFound(ctx, "File not found", err.Error())
	}
	defer content.Close()

	// Set headers for file download
	ctx.Response().Header("Content-Disposition", "attachment; filename=\""+file.OriginalName+"\"")
	ctx.Response().Header("Content-Type", file.MimeType)
	ctx.Response().Header("Content-Length", strconv.FormatInt(file.Size, 10))

	// Stream file content
	return ctx.Response().Stream(200, func(w http.StreamWriter) error {
		_, err := io.Copy(w, content)
		return err
	})
}

// ShareFile creates a file share
// @Summary Share file
// @Description Share a file with others
// @Tags Drive
// @Accept json
// @Produce json
// @Param id path string true "File ID"
// @Param request body requests.ShareFileRequest true "Share data"
// @Success 201 {object} responses.APIResponse{data=models.FileShare}
// @Failure 400 {object} responses.APIResponse
// @Failure 401 {object} responses.APIResponse
// @Router /api/v1/drive/files/{id}/share [post]
func (dc *DriveController) ShareFile(ctx http.Context) http.Response {
	// Get file ID
	fileID := ctx.Request().Route("id")

	// Validate request
	var shareRequest requests.ShareFileRequest
	if err := ctx.Request().Bind(&shareRequest); err != nil {
		return responses.BadRequest(ctx, "Invalid request", err.Error())
	}

	// Get authenticated user
	userID := ctx.Value("user_id").(string)

	// Prepare options
	options := make(map[string]interface{})
	if shareRequest.Email != "" {
		options["email"] = shareRequest.Email
	}
	if shareRequest.Message != "" {
		options["message"] = shareRequest.Message
	}
	if shareRequest.ExpiresAt != nil {
		options["expires_at"] = shareRequest.ExpiresAt
	}
	if shareRequest.RequirePassword {
		options["require_password"] = true
		options["password"] = shareRequest.Password
	}

	// Create share
	share, err := dc.driveService.ShareFile(
		context.Background(),
		fileID,
		userID,
		shareRequest.ShareType,
		shareRequest.Permission,
		options,
	)
	if err != nil {
		return responses.BadRequest(ctx, "Failed to share file", err.Error())
	}

	return responses.Created(ctx, "File shared successfully", share)
}

// MoveFile moves a file to a different folder
// @Summary Move file
// @Description Move a file to a different folder
// @Tags Drive
// @Accept json
// @Produce json
// @Param id path string true "File ID"
// @Param request body requests.MoveFileRequest true "Move data"
// @Success 200 {object} responses.APIResponse
// @Failure 400 {object} responses.APIResponse
// @Failure 401 {object} responses.APIResponse
// @Router /api/v1/drive/files/{id}/move [post]
func (dc *DriveController) MoveFile(ctx http.Context) http.Response {
	// Get file ID
	fileID := ctx.Request().Route("id")

	// Validate request
	var moveRequest requests.MoveFileRequest
	if err := ctx.Request().Bind(&moveRequest); err != nil {
		return responses.BadRequest(ctx, "Invalid request", err.Error())
	}

	// Get authenticated user
	userID := ctx.Value("user_id").(string)

	// Move file
	err := dc.driveService.MoveFile(context.Background(), fileID, userID, moveRequest.FolderID)
	if err != nil {
		return responses.BadRequest(ctx, "Failed to move file", err.Error())
	}

	return responses.Success(ctx, "File moved successfully", nil)
}

// TrashFile moves a file to trash
// @Summary Trash file
// @Description Move a file to trash
// @Tags Drive
// @Produce json
// @Param id path string true "File ID"
// @Success 200 {object} responses.APIResponse
// @Failure 400 {object} responses.APIResponse
// @Failure 401 {object} responses.APIResponse
// @Router /api/v1/drive/files/{id}/trash [post]
func (dc *DriveController) TrashFile(ctx http.Context) http.Response {
	// Get file ID
	fileID := ctx.Request().Route("id")

	// Get authenticated user
	userID := ctx.Value("user_id").(string)

	// Trash file
	err := dc.driveService.TrashFile(context.Background(), fileID, userID)
	if err != nil {
		return responses.BadRequest(ctx, "Failed to trash file", err.Error())
	}

	return responses.Success(ctx, "File moved to trash successfully", nil)
}

// RestoreFile restores a file from trash
// @Summary Restore file
// @Description Restore a file from trash
// @Tags Drive
// @Produce json
// @Param id path string true "File ID"
// @Success 200 {object} responses.APIResponse
// @Failure 400 {object} responses.APIResponse
// @Failure 401 {object} responses.APIResponse
// @Router /api/v1/drive/files/{id}/restore [post]
func (dc *DriveController) RestoreFile(ctx http.Context) http.Response {
	// Get file ID
	fileID := ctx.Request().Route("id")

	// Get authenticated user
	userID := ctx.Value("user_id").(string)

	// Restore file
	err := dc.driveService.RestoreFile(context.Background(), fileID, userID)
	if err != nil {
		return responses.BadRequest(ctx, "Failed to restore file", err.Error())
	}

	return responses.Success(ctx, "File restored successfully", nil)
}

// CreateFileVersion creates a new version of a file
// @Summary Create file version
// @Description Create a new version of a file
// @Tags Drive
// @Accept multipart/form-data
// @Produce json
// @Param id path string true "File ID"
// @Param file formData file true "New file version"
// @Param comment formData string false "Version comment"
// @Success 201 {object} responses.APIResponse{data=models.File}
// @Failure 400 {object} responses.APIResponse
// @Failure 401 {object} responses.APIResponse
// @Router /api/v1/drive/files/{id}/versions [post]
func (dc *DriveController) CreateFileVersion(ctx http.Context) http.Response {
	// Get file ID
	fileID := ctx.Request().Route("id")

	// Get authenticated user
	userID := ctx.Value("user_id").(string)

	// Get uploaded file
	file, err := ctx.Request().File("file")
	if err != nil {
		return responses.BadRequest(ctx, "No file uploaded", err.Error())
	}

	// Get version comment
	comment := ctx.Request().Input("comment", "")

	// Get file size
	fileSize, err := file.Size()
	if err != nil {
		return responses.BadRequest(ctx, "Failed to get file size", err.Error())
	}

	// Get file path for reading
	filePath := file.File()

	// Open file for reading
	fileReader, err := os.Open(filePath)
	if err != nil {
		return responses.BadRequest(ctx, "Failed to read file", err.Error())
	}
	defer fileReader.Close()

	// Create file version
	updatedFile, err := dc.driveService.CreateFileVersion(
		context.Background(),
		fileID,
		userID,
		fileReader,
		fileSize,
		comment,
	)
	if err != nil {
		return responses.BadRequest(ctx, "Failed to create file version", err.Error())
	}

	return responses.Created(ctx, "File version created successfully", updatedFile)
}

// GetFilePreview handles file preview requests
// @Summary Get file preview
// @Description Get a preview of a file (resized for images)
// @Tags Drive
// @Produce application/octet-stream
// @Param id path string true "File ID"
// @Success 200 {file} binary "Preview content"
// @Failure 404 {object} responses.APIResponse
// @Failure 403 {object} responses.APIResponse
// @Router /api/v1/drive/files/{id}/preview [get]
func (dc *DriveController) GetFilePreview(ctx http.Context) http.Response {
	// Get file ID
	fileID := ctx.Request().Route("id")

	// Get authenticated user (optional for public files)
	var userID *string
	if uid := ctx.Value("user_id"); uid != nil {
		if uidStr, ok := uid.(string); ok {
			userID = &uidStr
		}
	}

	// Get file preview
	_, content, err := dc.driveService.GetFilePreview(context.Background(), fileID, userID)
	if err != nil {
		if err.Error() == "access denied" {
			return responses.Forbidden(ctx, "Access denied", "You don't have permission to preview this file")
		}
		return responses.NotFound(ctx, "File not found", err.Error())
	}
	defer content.Close()

	// Set headers for preview
	ctx.Response().Header("Content-Type", "image/jpeg")
	ctx.Response().Header("Cache-Control", "public, max-age=3600")

	// Stream preview content
	return ctx.Response().Stream(200, func(w http.StreamWriter) error {
		_, err := io.Copy(w, content)
		return err
	})
}

// GetFileThumbnail handles file thumbnail requests
// @Summary Get file thumbnail
// @Description Get a thumbnail of a file
// @Tags Drive
// @Produce image/jpeg
// @Param id path string true "File ID"
// @Success 200 {file} binary "Thumbnail content"
// @Failure 404 {object} responses.APIResponse
// @Failure 403 {object} responses.APIResponse
// @Router /api/v1/drive/files/{id}/thumbnail [get]
func (dc *DriveController) GetFileThumbnail(ctx http.Context) http.Response {
	// Get file ID
	fileID := ctx.Request().Route("id")

	// Get authenticated user (optional for public files)
	var userID *string
	if uid := ctx.Value("user_id"); uid != nil {
		if uidStr, ok := uid.(string); ok {
			userID = &uidStr
		}
	}

	// Get file record
	var file models.File
	if err := facades.Orm().Query().Find(&file, fileID); err != nil {
		return responses.NotFound(ctx, "File not found", err.Error())
	}

	// Check access permissions
	if !dc.driveService.CanAccessFile(&file, userID) {
		return responses.Forbidden(ctx, "Access denied", "You don't have permission to view this file")
	}

	// Try to get thumbnail
	thumbnailPath := fmt.Sprintf("thumbnails/%s_thumb.jpg", file.ID)
	storageService := services.NewStorageService()
	_, thumbnailContent, err := storageService.Get(context.Background(), thumbnailPath)

	if err != nil {
		// Generate thumbnail if it doesn't exist
		if err := dc.driveService.GenerateThumbnail(context.Background(), &file); err != nil {
			return responses.InternalServerError(ctx, "Failed to generate thumbnail", err.Error())
		}

		// Try again
		_, thumbnailContent, err = storageService.Get(context.Background(), thumbnailPath)
		if err != nil {
			return responses.NotFound(ctx, "Thumbnail not available", err.Error())
		}
	}
	defer thumbnailContent.Close()

	// Set headers for thumbnail
	ctx.Response().Header("Content-Type", "image/jpeg")
	ctx.Response().Header("Cache-Control", "public, max-age=86400") // 24 hours

	// Stream thumbnail content
	return ctx.Response().Stream(200, func(w http.StreamWriter) error {
		_, err := io.Copy(w, thumbnailContent)
		return err
	})
}

// SearchFiles handles advanced file search
// @Summary Advanced file search
// @Description Search files with advanced filters
// @Tags Drive
// @Produce json
// @Param query query string false "Search query"
// @Param file_types query []string false "File types (extensions)"
// @Param min_size query int false "Minimum file size in bytes"
// @Param max_size query int false "Maximum file size in bytes"
// @Param date_from query string false "Date from (YYYY-MM-DD)"
// @Param date_to query string false "Date to (YYYY-MM-DD)"
// @Param tags query []string false "Tags"
// @Param is_starred query boolean false "Filter by starred status"
// @Param sort_by query string false "Sort by field" Enums(name, size, created_at, updated_at)
// @Param sort_order query string false "Sort order" Enums(asc, desc)
// @Param page query int false "Page number" default(1)
// @Param limit query int false "Items per page" default(20)
// @Success 200 {object} responses.PaginatedResponse{data=[]models.File}
// @Failure 401 {object} responses.APIResponse
// @Router /api/v1/drive/search [get]
func (dc *DriveController) SearchFiles(ctx http.Context) http.Response {
	// Get authenticated user
	userID := ctx.Value("user_id").(string)

	// Parse query parameters
	filters := &services.SearchFilters{
		Query:     ctx.Request().Query("query", ""),
		SortBy:    ctx.Request().Query("sort_by", "created_at"),
		SortOrder: ctx.Request().Query("sort_order", "desc"),
	}

	// Parse file types
	if fileTypesStr := ctx.Request().Query("file_types", ""); fileTypesStr != "" {
		filters.FileTypes = strings.Split(fileTypesStr, ",")
	}

	// Parse size filters
	if minSizeStr := ctx.Request().Query("min_size", ""); minSizeStr != "" {
		if minSize, err := strconv.ParseInt(minSizeStr, 10, 64); err == nil {
			filters.MinSize = &minSize
		}
	}
	if maxSizeStr := ctx.Request().Query("max_size", ""); maxSizeStr != "" {
		if maxSize, err := strconv.ParseInt(maxSizeStr, 10, 64); err == nil {
			filters.MaxSize = &maxSize
		}
	}

	// Parse date filters
	if dateFromStr := ctx.Request().Query("date_from", ""); dateFromStr != "" {
		if dateFrom, err := time.Parse("2006-01-02", dateFromStr); err == nil {
			filters.DateFrom = &dateFrom
		}
	}
	if dateToStr := ctx.Request().Query("date_to", ""); dateToStr != "" {
		if dateTo, err := time.Parse("2006-01-02", dateToStr); err == nil {
			filters.DateTo = &dateTo
		}
	}

	// Parse tags
	if tagsStr := ctx.Request().Query("tags", ""); tagsStr != "" {
		filters.Tags = strings.Split(tagsStr, ",")
	}

	// Parse starred filter
	if isStarredStr := ctx.Request().Query("is_starred", ""); isStarredStr != "" {
		if isStarred, err := strconv.ParseBool(isStarredStr); err == nil {
			filters.IsStarred = &isStarred
		}
	}

	// Parse pagination
	page, _ := strconv.Atoi(ctx.Request().Query("page", "1"))
	limit, _ := strconv.Atoi(ctx.Request().Query("limit", "20"))

	// Search files
	files, total, err := dc.driveService.GetFilesAdvanced(userID, filters, page, limit)
	if err != nil {
		return responses.InternalServerError(ctx, "Failed to search files", err.Error())
	}

	return responses.PaginatedSuccess(ctx, "Files found", files, total, page, limit)
}

// GetRecentFiles handles recent files request
// @Summary Get recent files
// @Description Get recently accessed files
// @Tags Drive
// @Produce json
// @Param limit query int false "Number of files to return" default(10)
// @Success 200 {object} responses.APIResponse{data=[]models.File}
// @Failure 401 {object} responses.APIResponse
// @Router /api/v1/drive/recent [get]
func (dc *DriveController) GetRecentFiles(ctx http.Context) http.Response {
	// Get authenticated user
	userID := ctx.Value("user_id").(string)

	// Parse limit
	limit, _ := strconv.Atoi(ctx.Request().Query("limit", "10"))
	if limit > 50 {
		limit = 50 // Cap at 50
	}

	// Get recent files
	files, err := dc.driveService.GetRecentFiles(userID, limit)
	if err != nil {
		return responses.InternalServerError(ctx, "Failed to get recent files", err.Error())
	}

	return responses.Success(ctx, "Recent files retrieved", files)
}

// GetStarredFiles handles starred files request
// @Summary Get starred files
// @Description Get starred/favorited files
// @Tags Drive
// @Produce json
// @Param page query int false "Page number" default(1)
// @Param limit query int false "Items per page" default(20)
// @Success 200 {object} responses.PaginatedResponse{data=[]models.File}
// @Failure 401 {object} responses.APIResponse
// @Router /api/v1/drive/starred [get]
func (dc *DriveController) GetStarredFiles(ctx http.Context) http.Response {
	// Get authenticated user
	userID := ctx.Value("user_id").(string)

	// Parse pagination
	page, _ := strconv.Atoi(ctx.Request().Query("page", "1"))
	limit, _ := strconv.Atoi(ctx.Request().Query("limit", "20"))

	// Get starred files
	files, total, err := dc.driveService.GetStarredFiles(userID, page, limit)
	if err != nil {
		return responses.InternalServerError(ctx, "Failed to get starred files", err.Error())
	}

	return responses.PaginatedSuccess(ctx, "Starred files retrieved", files, total, page, limit)
}

// ToggleFileStar handles file star toggle
// @Summary Toggle file star
// @Description Star or unstar a file
// @Tags Drive
// @Produce json
// @Param id path string true "File ID"
// @Success 200 {object} responses.APIResponse{data=models.File}
// @Failure 400 {object} responses.APIResponse
// @Failure 401 {object} responses.APIResponse
// @Router /api/v1/drive/files/{id}/star [post]
func (dc *DriveController) ToggleFileStar(ctx http.Context) http.Response {
	// Get file ID
	fileID := ctx.Request().Route("id")

	// Get authenticated user
	userID := ctx.Value("user_id").(string)

	// Toggle star
	file, err := dc.driveService.ToggleFileStar(context.Background(), fileID, userID)
	if err != nil {
		return responses.BadRequest(ctx, "Failed to toggle star", err.Error())
	}

	return responses.Success(ctx, "File star toggled", file)
}

// GetFilesByType handles files by type request
// @Summary Get files by type
// @Description Get files filtered by type category
// @Tags Drive
// @Produce json
// @Param type path string true "File type" Enums(images, videos, audio, documents, archives)
// @Param page query int false "Page number" default(1)
// @Param limit query int false "Items per page" default(20)
// @Success 200 {object} responses.PaginatedResponse{data=[]models.File}
// @Failure 400 {object} responses.APIResponse
// @Failure 401 {object} responses.APIResponse
// @Router /api/v1/drive/types/{type} [get]
func (dc *DriveController) GetFilesByType(ctx http.Context) http.Response {
	// Get authenticated user
	userID := ctx.Value("user_id").(string)

	// Get file type
	fileType := ctx.Request().Route("type")

	// Parse pagination
	page, _ := strconv.Atoi(ctx.Request().Query("page", "1"))
	limit, _ := strconv.Atoi(ctx.Request().Query("limit", "20"))

	// Get files by type
	files, total, err := dc.driveService.GetFilesByType(userID, fileType, page, limit)
	if err != nil {
		return responses.BadRequest(ctx, "Failed to get files by type", err.Error())
	}

	return responses.PaginatedSuccess(ctx, fmt.Sprintf("%s files retrieved", fileType), files, total, page, limit)
}

// BulkOperation handles bulk file operations
// @Summary Bulk file operations
// @Description Perform bulk operations on multiple files
// @Tags Drive
// @Accept json
// @Produce json
// @Param request body services.BulkOperationRequest true "Bulk operation data"
// @Success 200 {object} responses.APIResponse{data=services.BulkOperationResult}
// @Failure 400 {object} responses.APIResponse
// @Failure 401 {object} responses.APIResponse
// @Router /api/v1/drive/bulk [post]
func (dc *DriveController) BulkOperation(ctx http.Context) http.Response {
	// Get authenticated user
	userID := ctx.Value("user_id").(string)

	// Parse request
	var request services.BulkOperationRequest
	if err := ctx.Request().Bind(&request); err != nil {
		return responses.BadRequest(ctx, "Invalid request", err.Error())
	}

	// Validate request
	if len(request.FileIDs) == 0 {
		return responses.BadRequest(ctx, "No files selected", "File IDs are required")
	}

	if len(request.FileIDs) > 100 {
		return responses.BadRequest(ctx, "Too many files", "Maximum 100 files can be processed at once")
	}

	allowedOperations := map[string]bool{
		"move": true, "trash": true, "restore": true,
		"star": true, "unstar": true, "delete": true,
	}
	if !allowedOperations[request.Operation] {
		return responses.BadRequest(ctx, "Invalid operation",
			"Operation must be one of: move, trash, restore, star, unstar, delete")
	}

	// Process bulk operation
	result, err := dc.driveService.ProcessBulkOperation(context.Background(), userID, &request)
	if err != nil {
		return responses.BadRequest(ctx, "Failed to process bulk operation", err.Error())
	}

	return responses.Success(ctx, "Bulk operation completed", result)
}

// AddFileComment handles adding a comment to a file
// @Summary Add file comment
// @Description Add a comment to a file
// @Tags Drive
// @Accept json
// @Produce json
// @Param id path string true "File ID"
// @Param request body map[string]string true "Comment data"
// @Success 201 {object} responses.APIResponse{data=models.FileComment}
// @Failure 400 {object} responses.APIResponse
// @Failure 401 {object} responses.APIResponse
// @Router /api/v1/drive/files/{id}/comments [post]
func (dc *DriveController) AddFileComment(ctx http.Context) http.Response {
	// Get file ID
	fileID := ctx.Request().Route("id")

	// Get authenticated user
	userID := ctx.Value("user_id").(string)

	// Parse request
	var request map[string]string
	if err := ctx.Request().Bind(&request); err != nil {
		return responses.BadRequest(ctx, "Invalid request", err.Error())
	}

	content, exists := request["content"]
	if !exists || content == "" {
		return responses.BadRequest(ctx, "Content is required", "Comment content cannot be empty")
	}

	// Add comment
	comment, err := dc.driveService.AddFileComment(context.Background(), fileID, userID, content)
	if err != nil {
		return responses.BadRequest(ctx, "Failed to add comment", err.Error())
	}

	return responses.Created(ctx, "Comment added successfully", comment)
}

// GetFileComments handles getting comments for a file
// @Summary Get file comments
// @Description Get comments for a file
// @Tags Drive
// @Produce json
// @Param id path string true "File ID"
// @Param page query int false "Page number" default(1)
// @Param limit query int false "Items per page" default(20)
// @Success 200 {object} responses.PaginatedResponse{data=[]models.FileComment}
// @Failure 401 {object} responses.APIResponse
// @Router /api/v1/drive/files/{id}/comments [get]
func (dc *DriveController) GetFileComments(ctx http.Context) http.Response {
	// Get file ID
	fileID := ctx.Request().Route("id")

	// Get authenticated user
	userID := ctx.Value("user_id").(string)

	// Parse pagination
	page, _ := strconv.Atoi(ctx.Request().Query("page", "1"))
	limit, _ := strconv.Atoi(ctx.Request().Query("limit", "20"))

	// Get comments
	comments, total, err := dc.driveService.GetFileComments(context.Background(), fileID, userID, page, limit)
	if err != nil {
		return responses.BadRequest(ctx, "Failed to get comments", err.Error())
	}

	return responses.PaginatedSuccess(ctx, "Comments retrieved successfully", comments, total, page, limit)
}

// UpdateFileComment handles updating a comment
// @Summary Update file comment
// @Description Update a file comment
// @Tags Drive
// @Accept json
// @Produce json
// @Param id path string true "Comment ID"
// @Param request body map[string]string true "Comment data"
// @Success 200 {object} responses.APIResponse{data=models.FileComment}
// @Failure 400 {object} responses.APIResponse
// @Failure 401 {object} responses.APIResponse
// @Router /api/v1/drive/comments/{id} [put]
func (dc *DriveController) UpdateFileComment(ctx http.Context) http.Response {
	// Get comment ID
	commentID := ctx.Request().Route("id")

	// Get authenticated user
	userID := ctx.Value("user_id").(string)

	// Parse request
	var request map[string]string
	if err := ctx.Request().Bind(&request); err != nil {
		return responses.BadRequest(ctx, "Invalid request", err.Error())
	}

	content, exists := request["content"]
	if !exists || content == "" {
		return responses.BadRequest(ctx, "Content is required", "Comment content cannot be empty")
	}

	// Update comment
	comment, err := dc.driveService.UpdateFileComment(context.Background(), commentID, userID, content)
	if err != nil {
		return responses.BadRequest(ctx, "Failed to update comment", err.Error())
	}

	return responses.Success(ctx, "Comment updated successfully", comment)
}

// DeleteFileComment handles deleting a comment
// @Summary Delete file comment
// @Description Delete a file comment
// @Tags Drive
// @Produce json
// @Param id path string true "Comment ID"
// @Success 200 {object} responses.APIResponse
// @Failure 400 {object} responses.APIResponse
// @Failure 401 {object} responses.APIResponse
// @Router /api/v1/drive/comments/{id} [delete]
func (dc *DriveController) DeleteFileComment(ctx http.Context) http.Response {
	// Get comment ID
	commentID := ctx.Request().Route("id")

	// Get authenticated user
	userID := ctx.Value("user_id").(string)

	// Delete comment
	err := dc.driveService.DeleteFileComment(context.Background(), commentID, userID)
	if err != nil {
		return responses.BadRequest(ctx, "Failed to delete comment", err.Error())
	}

	return responses.Success(ctx, "Comment deleted successfully", nil)
}

// GetFileActivity handles getting file activity history
// @Summary Get file activity
// @Description Get activity history for a file
// @Tags Drive
// @Produce json
// @Param id path string true "File ID"
// @Param page query int false "Page number" default(1)
// @Param limit query int false "Items per page" default(20)
// @Success 200 {object} responses.PaginatedResponse{data=[]models.FileActivity}
// @Failure 401 {object} responses.APIResponse
// @Router /api/v1/drive/files/{id}/activity [get]
func (dc *DriveController) GetFileActivity(ctx http.Context) http.Response {
	// Get file ID
	fileID := ctx.Request().Route("id")

	// Get authenticated user
	userID := ctx.Value("user_id").(string)

	// Parse pagination
	page, _ := strconv.Atoi(ctx.Request().Query("page", "1"))
	limit, _ := strconv.Atoi(ctx.Request().Query("limit", "20"))

	// Get activity
	activities, total, err := dc.driveService.GetFileActivity(context.Background(), fileID, userID, page, limit)
	if err != nil {
		return responses.BadRequest(ctx, "Failed to get file activity", err.Error())
	}

	return responses.PaginatedSuccess(ctx, "File activity retrieved successfully", activities, total, page, limit)
}

// ShareFolder handles folder sharing
// @Summary Share folder
// @Description Share a folder with others
// @Tags Drive
// @Accept json
// @Produce json
// @Param id path string true "Folder ID"
// @Param request body requests.ShareFileRequest true "Share data"
// @Success 201 {object} responses.APIResponse{data=models.FolderShare}
// @Failure 400 {object} responses.APIResponse
// @Failure 401 {object} responses.APIResponse
// @Router /api/v1/drive/folders/{id}/share [post]
func (dc *DriveController) ShareFolder(ctx http.Context) http.Response {
	// Get folder ID
	folderID := ctx.Request().Route("id")

	// Validate request
	var shareRequest requests.ShareFileRequest
	if err := ctx.Request().Bind(&shareRequest); err != nil {
		return responses.BadRequest(ctx, "Invalid request", err.Error())
	}

	// Get authenticated user
	userID := ctx.Value("user_id").(string)

	// Prepare options
	options := make(map[string]interface{})
	if shareRequest.Email != "" {
		options["email"] = shareRequest.Email
	}
	if shareRequest.Message != "" {
		options["message"] = shareRequest.Message
	}
	if shareRequest.ExpiresAt != nil {
		options["expires_at"] = shareRequest.ExpiresAt
	}
	if shareRequest.RequirePassword {
		options["require_password"] = true
		options["password"] = shareRequest.Password
	}

	// Create share
	share, err := dc.driveService.ShareFolder(
		context.Background(),
		folderID,
		userID,
		shareRequest.ShareType,
		shareRequest.Permission,
		options,
	)
	if err != nil {
		return responses.BadRequest(ctx, "Failed to share folder", err.Error())
	}

	return responses.Created(ctx, "Folder shared successfully", share)
}

// GetSharedFolders handles getting folders shared with user
// @Summary Get shared folders
// @Description Get folders shared with the current user
// @Tags Drive
// @Produce json
// @Param page query int false "Page number" default(1)
// @Param limit query int false "Items per page" default(20)
// @Success 200 {object} responses.PaginatedResponse{data=[]models.Folder}
// @Failure 401 {object} responses.APIResponse
// @Router /api/v1/drive/shared/folders [get]
func (dc *DriveController) GetSharedFolders(ctx http.Context) http.Response {
	// Get authenticated user
	userID := ctx.Value("user_id").(string)

	// Parse pagination
	page, _ := strconv.Atoi(ctx.Request().Query("page", "1"))
	limit, _ := strconv.Atoi(ctx.Request().Query("limit", "20"))

	// Get shared folders
	folders, total, err := dc.driveService.GetSharedFolders(userID, page, limit)
	if err != nil {
		return responses.InternalServerError(ctx, "Failed to get shared folders", err.Error())
	}

	return responses.PaginatedSuccess(ctx, "Shared folders retrieved successfully", folders, total, page, limit)
}

// GetFolderContents handles getting folder contents
// @Summary Get folder contents
// @Description Get files and subfolders in a folder
// @Tags Drive
// @Produce json
// @Param id path string false "Folder ID (empty for root)"
// @Param page query int false "Page number" default(1)
// @Param limit query int false "Items per page" default(20)
// @Success 200 {object} responses.APIResponse{data=map[string]interface{}}
// @Failure 401 {object} responses.APIResponse
// @Router /api/v1/drive/folders/{id}/contents [get]
func (dc *DriveController) GetFolderContents(ctx http.Context) http.Response {
	// Get authenticated user
	userID := ctx.Value("user_id").(string)

	// Get folder ID (can be empty for root)
	folderIDStr := ctx.Request().Route("id")
	var folderID *string
	if folderIDStr != "" && folderIDStr != "root" {
		folderID = &folderIDStr
	}

	// Parse pagination
	page, _ := strconv.Atoi(ctx.Request().Query("page", "1"))
	limit, _ := strconv.Atoi(ctx.Request().Query("limit", "20"))

	// Get folder contents
	contents, err := dc.driveService.GetFolderContents(userID, folderID, page, limit)
	if err != nil {
		return responses.BadRequest(ctx, "Failed to get folder contents", err.Error())
	}

	return responses.Success(ctx, "Folder contents retrieved successfully", contents)
}

// MoveFolderToTrash handles moving folder to trash
// @Summary Move folder to trash
// @Description Move a folder and its contents to trash
// @Tags Drive
// @Produce json
// @Param id path string true "Folder ID"
// @Success 200 {object} responses.APIResponse
// @Failure 400 {object} responses.APIResponse
// @Failure 401 {object} responses.APIResponse
// @Router /api/v1/drive/folders/{id}/trash [post]
func (dc *DriveController) MoveFolderToTrash(ctx http.Context) http.Response {
	// Get folder ID
	folderID := ctx.Request().Route("id")

	// Get authenticated user
	userID := ctx.Value("user_id").(string)

	// Move folder to trash
	err := dc.driveService.MoveFolderToTrash(context.Background(), folderID, userID)
	if err != nil {
		return responses.BadRequest(ctx, "Failed to move folder to trash", err.Error())
	}

	return responses.Success(ctx, "Folder moved to trash successfully", nil)
}

// RestoreFolderFromTrash handles restoring folder from trash
// @Summary Restore folder from trash
// @Description Restore a folder and its contents from trash
// @Tags Drive
// @Produce json
// @Param id path string true "Folder ID"
// @Success 200 {object} responses.APIResponse
// @Failure 400 {object} responses.APIResponse
// @Failure 401 {object} responses.APIResponse
// @Router /api/v1/drive/folders/{id}/restore [post]
func (dc *DriveController) RestoreFolderFromTrash(ctx http.Context) http.Response {
	// Get folder ID
	folderID := ctx.Request().Route("id")

	// Get authenticated user
	userID := ctx.Value("user_id").(string)

	// Restore folder from trash
	err := dc.driveService.RestoreFolderFromTrash(context.Background(), folderID, userID)
	if err != nil {
		return responses.BadRequest(ctx, "Failed to restore folder from trash", err.Error())
	}

	return responses.Success(ctx, "Folder restored from trash successfully", nil)
}

// GetTrashedItems handles getting items in trash
// @Summary Get trashed items
// @Description Get files and folders in trash
// @Tags Drive
// @Produce json
// @Param page query int false "Page number" default(1)
// @Param limit query int false "Items per page" default(20)
// @Success 200 {object} responses.APIResponse{data=map[string]interface{}}
// @Failure 401 {object} responses.APIResponse
// @Router /api/v1/drive/trash [get]
func (dc *DriveController) GetTrashedItems(ctx http.Context) http.Response {
	// Get authenticated user
	userID := ctx.Value("user_id").(string)

	// Parse pagination
	page, _ := strconv.Atoi(ctx.Request().Query("page", "1"))
	limit, _ := strconv.Atoi(ctx.Request().Query("limit", "20"))

	// Get trashed items
	items, err := dc.driveService.GetTrashedItems(userID, page, limit)
	if err != nil {
		return responses.InternalServerError(ctx, "Failed to get trashed items", err.Error())
	}

	return responses.Success(ctx, "Trashed items retrieved successfully", items)
}

// GetStorageQuota handles getting storage quota information
// @Summary Get storage quota
// @Description Get storage quota and usage information
// @Tags Drive
// @Produce json
// @Success 200 {object} responses.APIResponse{data=services.StorageQuota}
// @Failure 401 {object} responses.APIResponse
// @Router /api/v1/drive/quota [get]
func (dc *DriveController) GetStorageQuota(ctx http.Context) http.Response {
	// Get authenticated user
	userID := ctx.Value("user_id").(string)

	// Get storage quota
	quota, err := dc.driveService.GetStorageQuota(context.Background(), userID)
	if err != nil {
		return responses.InternalServerError(ctx, "Failed to get storage quota", err.Error())
	}

	return responses.Success(ctx, "Storage quota retrieved successfully", quota)
}

// GetStorageAnalytics handles getting storage analytics
// @Summary Get storage analytics
// @Description Get detailed storage usage analytics
// @Tags Drive
// @Produce json
// @Success 200 {object} responses.APIResponse{data=map[string]interface{}}
// @Failure 401 {object} responses.APIResponse
// @Router /api/v1/drive/analytics [get]
func (dc *DriveController) GetStorageAnalytics(ctx http.Context) http.Response {
	// Get authenticated user
	userID := ctx.Value("user_id").(string)

	// Get storage analytics
	analytics, err := dc.driveService.GetStorageAnalytics(context.Background(), userID)
	if err != nil {
		return responses.InternalServerError(ctx, "Failed to get storage analytics", err.Error())
	}

	return responses.Success(ctx, "Storage analytics retrieved successfully", analytics)
}

// CleanupTrash handles cleaning up old trashed files
// @Summary Cleanup trash
// @Description Permanently delete old trashed files
// @Tags Drive
// @Produce json
// @Param days query int false "Delete files older than X days" default(30)
// @Success 200 {object} responses.APIResponse{data=map[string]interface{}}
// @Failure 401 {object} responses.APIResponse
// @Router /api/v1/drive/cleanup [post]
func (dc *DriveController) CleanupTrash(ctx http.Context) http.Response {
	// Get authenticated user
	userID := ctx.Value("user_id").(string)

	// Parse days parameter
	days, _ := strconv.Atoi(ctx.Request().Query("days", "30"))
	if days < 1 {
		days = 30
	}

	// Cleanup trashed files
	deletedCount, err := dc.driveService.CleanupTrashedFiles(context.Background(), userID, days)
	if err != nil {
		return responses.InternalServerError(ctx, "Failed to cleanup trash", err.Error())
	}

	result := map[string]interface{}{
		"deleted_count": deletedCount,
		"days":          days,
	}

	return responses.Success(ctx, "Trash cleanup completed successfully", result)
}

// TagFile handles adding tags to a file
// @Summary Tag file
// @Description Add tags to a file
// @Tags Drive
// @Accept json
// @Produce json
// @Param id path string true "File ID"
// @Param request body map[string][]string true "Tags data"
// @Success 200 {object} responses.APIResponse{data=models.File}
// @Failure 400 {object} responses.APIResponse
// @Failure 401 {object} responses.APIResponse
// @Router /api/v1/drive/files/{id}/tags [post]
func (dc *DriveController) TagFile(ctx http.Context) http.Response {
	// Get file ID
	fileID := ctx.Request().Route("id")

	// Get authenticated user
	userID := ctx.Value("user_id").(string)

	// Parse request
	var request map[string][]string
	if err := ctx.Request().Bind(&request); err != nil {
		return responses.BadRequest(ctx, "Invalid request", err.Error())
	}

	tags, exists := request["tags"]
	if !exists || len(tags) == 0 {
		return responses.BadRequest(ctx, "Tags are required", "At least one tag must be provided")
	}

	// Tag file
	file, err := dc.driveService.TagFile(context.Background(), fileID, userID, tags)
	if err != nil {
		return responses.BadRequest(ctx, "Failed to tag file", err.Error())
	}

	return responses.Success(ctx, "File tagged successfully", file)
}

// RemoveTagsFromFile handles removing tags from a file
// @Summary Remove tags from file
// @Description Remove specific tags from a file
// @Tags Drive
// @Accept json
// @Produce json
// @Param id path string true "File ID"
// @Param request body map[string][]string true "Tags to remove"
// @Success 200 {object} responses.APIResponse{data=models.File}
// @Failure 400 {object} responses.APIResponse
// @Failure 401 {object} responses.APIResponse
// @Router /api/v1/drive/files/{id}/tags [delete]
func (dc *DriveController) RemoveTagsFromFile(ctx http.Context) http.Response {
	// Get file ID
	fileID := ctx.Request().Route("id")

	// Get authenticated user
	userID := ctx.Value("user_id").(string)

	// Parse request
	var request map[string][]string
	if err := ctx.Request().Bind(&request); err != nil {
		return responses.BadRequest(ctx, "Invalid request", err.Error())
	}

	tags, exists := request["tags"]
	if !exists || len(tags) == 0 {
		return responses.BadRequest(ctx, "Tags are required", "At least one tag must be provided")
	}

	// Remove tags from file
	file, err := dc.driveService.RemoveTagsFromFile(context.Background(), fileID, userID, tags)
	if err != nil {
		return responses.BadRequest(ctx, "Failed to remove tags from file", err.Error())
	}

	return responses.Success(ctx, "Tags removed successfully", file)
}

// GetAllUserTags handles getting all user tags
// @Summary Get all user tags
// @Description Get all unique tags used by the current user
// @Tags Drive
// @Produce json
// @Success 200 {object} responses.APIResponse{data=[]string}
// @Failure 401 {object} responses.APIResponse
// @Router /api/v1/drive/tags [get]
func (dc *DriveController) GetAllUserTags(ctx http.Context) http.Response {
	// Get authenticated user
	userID := ctx.Value("user_id").(string)

	// Get all user tags
	tags, err := dc.driveService.GetAllUserTags(userID)
	if err != nil {
		return responses.InternalServerError(ctx, "Failed to get user tags", err.Error())
	}

	return responses.Success(ctx, "User tags retrieved successfully", tags)
}

// GetTagUsageStats handles getting tag usage statistics
// @Summary Get tag usage statistics
// @Description Get detailed statistics about tag usage
// @Tags Drive
// @Produce json
// @Success 200 {object} responses.APIResponse{data=map[string]interface{}}
// @Failure 401 {object} responses.APIResponse
// @Router /api/v1/drive/tags/stats [get]
func (dc *DriveController) GetTagUsageStats(ctx http.Context) http.Response {
	// Get authenticated user
	userID := ctx.Value("user_id").(string)

	// Get tag usage stats
	stats, err := dc.driveService.GetTagUsageStats(userID)
	if err != nil {
		return responses.InternalServerError(ctx, "Failed to get tag usage stats", err.Error())
	}

	return responses.Success(ctx, "Tag usage statistics retrieved successfully", stats)
}

// GetFilesByTags handles getting files by tags
// @Summary Get files by tags
// @Description Get files that have specific tags
// @Tags Drive
// @Produce json
// @Param tags query string true "Comma-separated tags"
// @Param match_all query boolean false "Whether to match all tags or any tag" default(false)
// @Param page query int false "Page number" default(1)
// @Param limit query int false "Items per page" default(20)
// @Success 200 {object} responses.PaginatedResponse{data=[]models.File}
// @Failure 400 {object} responses.APIResponse
// @Failure 401 {object} responses.APIResponse
// @Router /api/v1/drive/tags/files [get]
func (dc *DriveController) GetFilesByTags(ctx http.Context) http.Response {
	// Get authenticated user
	userID := ctx.Value("user_id").(string)

	// Parse tags
	tagsStr := ctx.Request().Query("tags", "")
	if tagsStr == "" {
		return responses.BadRequest(ctx, "Tags are required", "At least one tag must be provided")
	}

	tags := strings.Split(tagsStr, ",")
	for i, tag := range tags {
		tags[i] = strings.TrimSpace(tag)
	}

	// Parse match_all parameter
	matchAll, _ := strconv.ParseBool(ctx.Request().Query("match_all", "false"))

	// Parse pagination
	page, _ := strconv.Atoi(ctx.Request().Query("page", "1"))
	limit, _ := strconv.Atoi(ctx.Request().Query("limit", "20"))

	// Get files by tags
	files, total, err := dc.driveService.GetFilesByTags(userID, tags, matchAll, page, limit)
	if err != nil {
		return responses.InternalServerError(ctx, "Failed to get files by tags", err.Error())
	}

	return responses.PaginatedSuccess(ctx, "Files retrieved successfully", files, total, page, limit)
}

// SuggestTags handles tag suggestions
// @Summary Suggest tags
// @Description Get tag suggestions based on filename and existing tags
// @Tags Drive
// @Produce json
// @Param filename query string true "Filename to suggest tags for"
// @Success 200 {object} responses.APIResponse{data=[]string}
// @Failure 400 {object} responses.APIResponse
// @Failure 401 {object} responses.APIResponse
// @Router /api/v1/drive/tags/suggest [get]
func (dc *DriveController) SuggestTags(ctx http.Context) http.Response {
	// Get authenticated user
	userID := ctx.Value("user_id").(string)

	// Get filename
	filename := ctx.Request().Query("filename", "")
	if filename == "" {
		return responses.BadRequest(ctx, "Filename is required", "Filename parameter must be provided")
	}

	// Get tag suggestions
	suggestions, err := dc.driveService.SuggestTags(userID, filename)
	if err != nil {
		return responses.InternalServerError(ctx, "Failed to get tag suggestions", err.Error())
	}

	return responses.Success(ctx, "Tag suggestions retrieved successfully", suggestions)
}

// OrganizeFilesByTags handles file organization by tags
// @Summary Organize files by tags
// @Description Get files organized hierarchically by tags
// @Tags Drive
// @Produce json
// @Success 200 {object} responses.APIResponse{data=map[string]interface{}}
// @Failure 401 {object} responses.APIResponse
// @Router /api/v1/drive/organize/tags [get]
func (dc *DriveController) OrganizeFilesByTags(ctx http.Context) http.Response {
	// Get authenticated user
	userID := ctx.Value("user_id").(string)

	// Get organized files
	organization, err := dc.driveService.OrganizeFilesByTags(userID)
	if err != nil {
		return responses.InternalServerError(ctx, "Failed to organize files by tags", err.Error())
	}

	return responses.Success(ctx, "Files organized by tags successfully", organization)
}

// FindDuplicateFiles handles finding duplicate files
// @Summary Find duplicate files
// @Description Find duplicate files based on content hash
// @Tags Drive
// @Produce json
// @Success 200 {object} responses.APIResponse{data=[]services.DuplicateFile}
// @Failure 401 {object} responses.APIResponse
// @Router /api/v1/drive/duplicates [get]
func (dc *DriveController) FindDuplicateFiles(ctx http.Context) http.Response {
	// Get authenticated user
	userID := ctx.Value("user_id").(string)

	// Find duplicate files
	duplicates, err := dc.driveService.FindDuplicateFiles(userID)
	if err != nil {
		return responses.InternalServerError(ctx, "Failed to find duplicate files", err.Error())
	}

	return responses.Success(ctx, "Duplicate files found successfully", duplicates)
}

// GetDuplicateStats handles getting duplicate file statistics
// @Summary Get duplicate statistics
// @Description Get statistics about duplicate files
// @Tags Drive
// @Produce json
// @Success 200 {object} responses.APIResponse{data=map[string]interface{}}
// @Failure 401 {object} responses.APIResponse
// @Router /api/v1/drive/duplicates/stats [get]
func (dc *DriveController) GetDuplicateStats(ctx http.Context) http.Response {
	// Get authenticated user
	userID := ctx.Value("user_id").(string)

	// Get duplicate stats
	stats, err := dc.driveService.GetDuplicateStats(userID)
	if err != nil {
		return responses.InternalServerError(ctx, "Failed to get duplicate stats", err.Error())
	}

	return responses.Success(ctx, "Duplicate statistics retrieved successfully", stats)
}

// ResolveDuplicates handles resolving duplicate files
// @Summary Resolve duplicates
// @Description Resolve duplicate files by keeping one and removing others
// @Tags Drive
// @Accept json
// @Produce json
// @Param request body map[string]string true "Resolution data"
// @Success 200 {object} responses.APIResponse{data=services.BulkOperationResult}
// @Failure 400 {object} responses.APIResponse
// @Failure 401 {object} responses.APIResponse
// @Router /api/v1/drive/duplicates/resolve [post]
func (dc *DriveController) ResolveDuplicates(ctx http.Context) http.Response {
	// Get authenticated user
	userID := ctx.Value("user_id").(string)

	// Parse request
	var request map[string]string
	if err := ctx.Request().Bind(&request); err != nil {
		return responses.BadRequest(ctx, "Invalid request", err.Error())
	}

	hash, hashExists := request["hash"]
	keepFileID, keepExists := request["keep_file_id"]

	if !hashExists || !keepExists || hash == "" || keepFileID == "" {
		return responses.BadRequest(ctx, "Missing required fields", "hash and keep_file_id are required")
	}

	// Resolve duplicates
	result, err := dc.driveService.ResolveDuplicates(context.Background(), userID, hash, keepFileID)
	if err != nil {
		return responses.BadRequest(ctx, "Failed to resolve duplicates", err.Error())
	}

	return responses.Success(ctx, "Duplicates resolved successfully", result)
}

// FindSimilarFiles handles finding similar files
// @Summary Find similar files
// @Description Find files with similar names or content
// @Tags Drive
// @Produce json
// @Param threshold query float64 false "Similarity threshold (0.0-1.0)" default(0.8)
// @Success 200 {object} responses.APIResponse{data=[]map[string]interface{}}
// @Failure 401 {object} responses.APIResponse
// @Router /api/v1/drive/similar [get]
func (dc *DriveController) FindSimilarFiles(ctx http.Context) http.Response {
	// Get authenticated user
	userID := ctx.Value("user_id").(string)

	// Parse threshold
	thresholdStr := ctx.Request().Query("threshold", "0.8")
	threshold, err := strconv.ParseFloat(thresholdStr, 64)
	if err != nil || threshold <= 0 || threshold > 1 {
		threshold = 0.8
	}

	// Find similar files
	similar, err := dc.driveService.FindSimilarFiles(userID, threshold)
	if err != nil {
		return responses.InternalServerError(ctx, "Failed to find similar files", err.Error())
	}

	return responses.Success(ctx, "Similar files found successfully", similar)
}

// GetDuplicateManagementSuggestions handles getting duplicate management suggestions
// @Summary Get duplicate management suggestions
// @Description Get suggestions for managing duplicate and similar files
// @Tags Drive
// @Produce json
// @Success 200 {object} responses.APIResponse{data=map[string]interface{}}
// @Failure 401 {object} responses.APIResponse
// @Router /api/v1/drive/duplicates/suggestions [get]
func (dc *DriveController) GetDuplicateManagementSuggestions(ctx http.Context) http.Response {
	// Get authenticated user
	userID := ctx.Value("user_id").(string)

	// Get suggestions
	suggestions, err := dc.driveService.GetDuplicateManagementSuggestions(userID)
	if err != nil {
		return responses.InternalServerError(ctx, "Failed to get duplicate management suggestions", err.Error())
	}

	return responses.Success(ctx, "Duplicate management suggestions retrieved successfully", suggestions)
}

// GetUserActivityInsights handles getting user activity insights
// @Summary Get user activity insights
// @Description Get detailed insights about user activity patterns
// @Tags Drive
// @Produce json
// @Param period query string false "Time period" Enums(week, month, quarter) default(week)
// @Success 200 {object} responses.APIResponse{data=services.ActivityInsight}
// @Failure 401 {object} responses.APIResponse
// @Router /api/v1/drive/insights/activity [get]
func (dc *DriveController) GetUserActivityInsights(ctx http.Context) http.Response {
	// Get authenticated user
	userID := ctx.Value("user_id").(string)

	// Parse period
	period := ctx.Request().Query("period", "week")
	if period != "week" && period != "month" && period != "quarter" {
		period = "week"
	}

	// Get activity insights
	insights, err := dc.driveService.GetUserActivityInsights(userID, period)
	if err != nil {
		return responses.InternalServerError(ctx, "Failed to get activity insights", err.Error())
	}

	return responses.Success(ctx, "Activity insights retrieved successfully", insights)
}

// GetSmartRecommendations handles getting smart recommendations
// @Summary Get smart recommendations
// @Description Get AI-powered recommendations for file management
// @Tags Drive
// @Produce json
// @Success 200 {object} responses.APIResponse{data=[]services.SmartRecommendation}
// @Failure 401 {object} responses.APIResponse
// @Router /api/v1/drive/recommendations [get]
func (dc *DriveController) GetSmartRecommendations(ctx http.Context) http.Response {
	// Get authenticated user
	userID := ctx.Value("user_id").(string)

	// Get smart recommendations
	recommendations, err := dc.driveService.GetSmartRecommendations(userID)
	if err != nil {
		return responses.InternalServerError(ctx, "Failed to get smart recommendations", err.Error())
	}

	return responses.Success(ctx, "Smart recommendations retrieved successfully", recommendations)
}

// GetFrequentlyAccessedFiles handles getting frequently accessed files
// @Summary Get frequently accessed files
// @Description Get files that are accessed frequently by the user
// @Tags Drive
// @Produce json
// @Param limit query int false "Number of files to return" default(10)
// @Success 200 {object} responses.APIResponse{data=[]models.File}
// @Failure 401 {object} responses.APIResponse
// @Router /api/v1/drive/frequent [get]
func (dc *DriveController) GetFrequentlyAccessedFiles(ctx http.Context) http.Response {
	// Get authenticated user
	userID := ctx.Value("user_id").(string)

	// Parse limit
	limit, _ := strconv.Atoi(ctx.Request().Query("limit", "10"))
	if limit > 50 {
		limit = 50 // Cap at 50
	}

	// Get frequently accessed files
	files, err := dc.driveService.GetFrequentlyAccessedFiles(userID, limit)
	if err != nil {
		return responses.InternalServerError(ctx, "Failed to get frequently accessed files", err.Error())
	}

	return responses.Success(ctx, "Frequently accessed files retrieved successfully", files)
}

// GetRecommendedFiles handles getting recommended files
// @Summary Get recommended files
// @Description Get AI-recommended files based on user activity patterns
// @Tags Drive
// @Produce json
// @Param limit query int false "Number of files to return" default(10)
// @Success 200 {object} responses.APIResponse{data=[]models.File}
// @Failure 401 {object} responses.APIResponse
// @Router /api/v1/drive/recommended [get]
func (dc *DriveController) GetRecommendedFiles(ctx http.Context) http.Response {
	// Get authenticated user
	userID := ctx.Value("user_id").(string)

	// Parse limit
	limit, _ := strconv.Atoi(ctx.Request().Query("limit", "10"))
	if limit > 50 {
		limit = 50 // Cap at 50
	}

	// Get recommended files
	files, err := dc.driveService.GetRecommendedFiles(userID, limit)
	if err != nil {
		return responses.InternalServerError(ctx, "Failed to get recommended files", err.Error())
	}

	return responses.Success(ctx, "Recommended files retrieved successfully", files)
}

// GetWorkspaceInsights handles getting workspace insights
// @Summary Get workspace insights
// @Description Get insights about workspace organization and usage
// @Tags Drive
// @Produce json
// @Success 200 {object} responses.APIResponse{data=map[string]interface{}}
// @Failure 401 {object} responses.APIResponse
// @Router /api/v1/drive/insights/workspace [get]
func (dc *DriveController) GetWorkspaceInsights(ctx http.Context) http.Response {
	// Get authenticated user
	userID := ctx.Value("user_id").(string)

	// Get workspace insights
	insights, err := dc.driveService.GetWorkspaceInsights(userID)
	if err != nil {
		return responses.InternalServerError(ctx, "Failed to get workspace insights", err.Error())
	}

	return responses.Success(ctx, "Workspace insights retrieved successfully", insights)
}
