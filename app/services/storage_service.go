package services

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/goravel/framework/facades"
)

// StorageService handles file storage operations for meetings
type StorageService struct {
	provider     string // local, s3, gcs, azure
	basePath     string
	maxFileSize  int64
	allowedTypes []string
}

// StorageConfig represents storage configuration
type StorageConfig struct {
	Provider     string            `json:"provider"`
	BasePath     string            `json:"base_path"`
	MaxFileSize  int64             `json:"max_file_size"`
	AllowedTypes []string          `json:"allowed_types"`
	Credentials  map[string]string `json:"credentials"`
}

// FileInfo represents stored file information
type FileInfo struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Path        string                 `json:"path"`
	Size        int64                  `json:"size"`
	ContentType string                 `json:"content_type"`
	StoredAt    time.Time              `json:"stored_at"`
	URL         string                 `json:"url"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// NewStorageService creates a new storage service
func NewStorageService() *StorageService {
	return &StorageService{
		provider:    facades.Config().GetString("storage.provider", "local"),
		basePath:    facades.Config().GetString("storage.base_path", "storage"),
		maxFileSize: int64(facades.Config().GetInt("storage.max_file_size", 100*1024*1024)), // 100MB
		allowedTypes: facades.Config().Get("storage.allowed_types", []string{
			"video/mp4", "video/webm", "audio/mp3", "audio/wav", "image/jpeg", "image/png",
		}).([]string),
	}
}

// Store stores a file and returns file information
func (ss *StorageService) Store(ctx context.Context, filename string, content io.Reader, metadata map[string]interface{}) (*FileInfo, error) {
	switch ss.provider {
	case "local":
		return ss.storeLocal(filename, content, metadata)
	case "s3":
		return ss.storeS3(ctx, filename, content, metadata)
	case "gcs":
		return ss.storeGCS(ctx, filename, content, metadata)
	case "azure":
		return ss.storeAzure(ctx, filename, content, metadata)
	default:
		return nil, fmt.Errorf("unsupported storage provider: %s", ss.provider)
	}
}

// Get retrieves a file by ID
func (ss *StorageService) Get(ctx context.Context, fileID string) (*FileInfo, io.ReadCloser, error) {
	switch ss.provider {
	case "local":
		return ss.getLocal(fileID)
	case "s3":
		return ss.getS3(ctx, fileID)
	case "gcs":
		return ss.getGCS(ctx, fileID)
	case "azure":
		return ss.getAzure(ctx, fileID)
	default:
		return nil, nil, fmt.Errorf("unsupported storage provider: %s", ss.provider)
	}
}

// Delete removes a file by ID
func (ss *StorageService) Delete(ctx context.Context, fileID string) error {
	switch ss.provider {
	case "local":
		return ss.deleteLocal(fileID)
	case "s3":
		return ss.deleteS3(ctx, fileID)
	case "gcs":
		return ss.deleteGCS(ctx, fileID)
	case "azure":
		return ss.deleteAzure(ctx, fileID)
	default:
		return fmt.Errorf("unsupported storage provider: %s", ss.provider)
	}
}

// GetURL returns a public URL for a file
func (ss *StorageService) GetURL(fileID string, expiry time.Duration) (string, error) {
	switch ss.provider {
	case "local":
		return ss.getLocalURL(fileID), nil
	case "s3":
		return ss.getS3URL(fileID, expiry)
	case "gcs":
		return ss.getGCSURL(fileID, expiry)
	case "azure":
		return ss.getAzureURL(fileID, expiry)
	default:
		return "", fmt.Errorf("unsupported storage provider: %s", ss.provider)
	}
}

// Local storage implementation
func (ss *StorageService) storeLocal(filename string, content io.Reader, metadata map[string]interface{}) (*FileInfo, error) {
	// Ensure directory exists
	dir := filepath.Join(ss.basePath, "meetings")
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create directory: %v", err)
	}

	// Generate unique filename
	fileID := ss.generateFileID()
	ext := filepath.Ext(filename)
	storedFilename := fileID + ext
	filePath := filepath.Join(dir, storedFilename)

	// Create file
	file, err := os.Create(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to create file: %v", err)
	}
	defer file.Close()

	// Copy content
	size, err := io.Copy(file, content)
	if err != nil {
		os.Remove(filePath)
		return nil, fmt.Errorf("failed to write file: %v", err)
	}

	// Check file size
	if size > ss.maxFileSize {
		os.Remove(filePath)
		return nil, fmt.Errorf("file size exceeds limit: %d > %d", size, ss.maxFileSize)
	}

	return &FileInfo{
		ID:          fileID,
		Name:        filename,
		Path:        filePath,
		Size:        size,
		ContentType: ss.detectContentType(filename),
		StoredAt:    time.Now(),
		URL:         ss.getLocalURL(fileID),
		Metadata:    metadata,
	}, nil
}

func (ss *StorageService) getLocal(fileID string) (*FileInfo, io.ReadCloser, error) {
	// Find file by ID
	pattern := filepath.Join(ss.basePath, "meetings", fileID+".*")
	matches, err := filepath.Glob(pattern)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to search file: %v", err)
	}

	if len(matches) == 0 {
		return nil, nil, fmt.Errorf("file not found: %s", fileID)
	}

	filePath := matches[0]
	file, err := os.Open(filePath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to open file: %v", err)
	}

	stat, err := file.Stat()
	if err != nil {
		file.Close()
		return nil, nil, fmt.Errorf("failed to get file info: %v", err)
	}

	fileInfo := &FileInfo{
		ID:          fileID,
		Name:        filepath.Base(filePath),
		Path:        filePath,
		Size:        stat.Size(),
		ContentType: ss.detectContentType(filePath),
		StoredAt:    stat.ModTime(),
		URL:         ss.getLocalURL(fileID),
	}

	return fileInfo, file, nil
}

func (ss *StorageService) deleteLocal(fileID string) error {
	pattern := filepath.Join(ss.basePath, "meetings", fileID+".*")
	matches, err := filepath.Glob(pattern)
	if err != nil {
		return fmt.Errorf("failed to search file: %v", err)
	}

	if len(matches) == 0 {
		return fmt.Errorf("file not found: %s", fileID)
	}

	return os.Remove(matches[0])
}

func (ss *StorageService) getLocalURL(fileID string) string {
	baseURL := facades.Config().GetString("app.url", "http://localhost:8080")
	return fmt.Sprintf("%s/storage/meetings/%s", baseURL, fileID)
}

// S3 storage implementation (placeholder)
func (ss *StorageService) storeS3(ctx context.Context, filename string, content io.Reader, metadata map[string]interface{}) (*FileInfo, error) {
	// Implementation would use AWS S3 SDK
	return nil, fmt.Errorf("S3 storage not implemented")
}

func (ss *StorageService) getS3(ctx context.Context, fileID string) (*FileInfo, io.ReadCloser, error) {
	return nil, nil, fmt.Errorf("S3 storage not implemented")
}

func (ss *StorageService) deleteS3(ctx context.Context, fileID string) error {
	return fmt.Errorf("S3 storage not implemented")
}

func (ss *StorageService) getS3URL(fileID string, expiry time.Duration) (string, error) {
	return "", fmt.Errorf("S3 storage not implemented")
}

// Google Cloud Storage implementation (placeholder)
func (ss *StorageService) storeGCS(ctx context.Context, filename string, content io.Reader, metadata map[string]interface{}) (*FileInfo, error) {
	return nil, fmt.Errorf("GCS storage not implemented")
}

func (ss *StorageService) getGCS(ctx context.Context, fileID string) (*FileInfo, io.ReadCloser, error) {
	return nil, nil, fmt.Errorf("GCS storage not implemented")
}

func (ss *StorageService) deleteGCS(ctx context.Context, fileID string) error {
	return fmt.Errorf("GCS storage not implemented")
}

func (ss *StorageService) getGCSURL(fileID string, expiry time.Duration) (string, error) {
	return "", fmt.Errorf("GCS storage not implemented")
}

// Azure Blob Storage implementation (placeholder)
func (ss *StorageService) storeAzure(ctx context.Context, filename string, content io.Reader, metadata map[string]interface{}) (*FileInfo, error) {
	return nil, fmt.Errorf("Azure storage not implemented")
}

func (ss *StorageService) getAzure(ctx context.Context, fileID string) (*FileInfo, io.ReadCloser, error) {
	return nil, nil, fmt.Errorf("Azure storage not implemented")
}

func (ss *StorageService) deleteAzure(ctx context.Context, fileID string) error {
	return fmt.Errorf("Azure storage not implemented")
}

func (ss *StorageService) getAzureURL(fileID string, expiry time.Duration) (string, error) {
	return "", fmt.Errorf("Azure storage not implemented")
}

// Helper methods
func (ss *StorageService) generateFileID() string {
	return fmt.Sprintf("%d", time.Now().UnixNano())
}

func (ss *StorageService) detectContentType(filename string) string {
	ext := filepath.Ext(filename)
	switch ext {
	case ".mp4":
		return "video/mp4"
	case ".webm":
		return "video/webm"
	case ".mp3":
		return "audio/mp3"
	case ".wav":
		return "audio/wav"
	case ".jpg", ".jpeg":
		return "image/jpeg"
	case ".png":
		return "image/png"
	case ".pdf":
		return "application/pdf"
	default:
		return "application/octet-stream"
	}
}

// Cleanup removes old files based on retention policy
func (ss *StorageService) Cleanup(ctx context.Context, retentionDays int) error {
	cutoffTime := time.Now().AddDate(0, 0, -retentionDays)

	switch ss.provider {
	case "local":
		return ss.cleanupLocal(cutoffTime)
	case "s3":
		return ss.cleanupS3(ctx, cutoffTime)
	case "gcs":
		return ss.cleanupGCS(ctx, cutoffTime)
	case "azure":
		return ss.cleanupAzure(ctx, cutoffTime)
	default:
		return fmt.Errorf("unsupported storage provider: %s", ss.provider)
	}
}

func (ss *StorageService) cleanupLocal(cutoffTime time.Time) error {
	dir := filepath.Join(ss.basePath, "meetings")
	return filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if !info.IsDir() && info.ModTime().Before(cutoffTime) {
			facades.Log().Info("Cleaning up old file", map[string]interface{}{
				"file": path,
				"age":  time.Since(info.ModTime()),
			})
			return os.Remove(path)
		}

		return nil
	})
}

func (ss *StorageService) cleanupS3(ctx context.Context, cutoffTime time.Time) error {
	// Implementation would cleanup S3 objects
	return fmt.Errorf("S3 cleanup not implemented")
}

func (ss *StorageService) cleanupGCS(ctx context.Context, cutoffTime time.Time) error {
	// Implementation would cleanup GCS objects
	return fmt.Errorf("GCS cleanup not implemented")
}

func (ss *StorageService) cleanupAzure(ctx context.Context, cutoffTime time.Time) error {
	// Implementation would cleanup Azure blobs
	return fmt.Errorf("Azure cleanup not implemented")
}
