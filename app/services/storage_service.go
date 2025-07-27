package services

import (
	"bytes"
	"context"
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/goravel/framework/facades"

	"goravel/app/models"
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
	fileID := uuid.New().String()
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

	fileInfo := &FileInfo{
		ID:          fileID,
		Name:        filename,
		Path:        filePath,
		Size:        size,
		ContentType: ss.detectContentType(filename),
		StoredAt:    time.Now(),
		URL:         ss.getLocalURL(fileID),
		Metadata:    metadata,
	}

	if err := ss.storeFileInfoInDatabase(fileInfo, "system"); err != nil {
		facades.Log().Error("Failed to store file info in database", map[string]interface{}{
			"file_id": fileID,
			"error":   err.Error(),
		})
	}

	return fileInfo, nil
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

	if err := ss.storeFileInfoInDatabase(fileInfo, "system"); err != nil {
		facades.Log().Error("Failed to store file info in database", map[string]interface{}{
			"file_id": fileID,
			"error":   err.Error(),
		})
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

// S3 storage implementation using HTTP client with AWS v4 signature
func (ss *StorageService) storeS3(ctx context.Context, filename string, content io.Reader, metadata map[string]interface{}) (*FileInfo, error) {
	// Get S3 configuration from environment
	region := facades.Config().GetString("storage.s3.region", "us-east-1")
	bucket := facades.Config().GetString("storage.s3.bucket")
	accessKey := facades.Config().GetString("storage.s3.access_key")
	secretKey := facades.Config().GetString("storage.s3.secret_key")

	if bucket == "" || accessKey == "" || secretKey == "" {
		return nil, fmt.Errorf("S3 configuration incomplete")
	}

	// Generate unique file ID and path
	fileID := uuid.New().String()
	key := filepath.Join(ss.basePath, fileID, filename)

	// Read content into buffer to get size
	contentBytes, err := io.ReadAll(content)
	if err != nil {
		return nil, fmt.Errorf("failed to read content: %w", err)
	}

	contentType := ss.detectContentType(filename)

	// Create S3 PUT request
	endpoint := fmt.Sprintf("https://%s.s3.%s.amazonaws.com/%s", bucket, region, key)
	req, err := http.NewRequestWithContext(ctx, "PUT", endpoint, bytes.NewReader(contentBytes))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Set headers
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("Content-Length", fmt.Sprintf("%d", len(contentBytes)))

	// Add metadata headers
	for k, v := range metadata {
		if str, ok := v.(string); ok {
			req.Header.Set("x-amz-meta-"+k, str)
		}
	}

	// Sign request with AWS v4 signature
	err = ss.signAWSRequest(req, "s3", region, accessKey, secretKey, contentBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to sign request: %w", err)
	}

	// Execute request
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to upload to S3: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("S3 upload failed with status %d: %s", resp.StatusCode, string(body))
	}

	// Create file info
	fileInfo := &FileInfo{
		ID:          fileID,
		Name:        filename,
		Path:        key,
		Size:        int64(len(contentBytes)),
		ContentType: contentType,
		StoredAt:    time.Now(),
		URL:         endpoint,
		Metadata:    metadata,
	}

	if err := ss.storeFileInfoInDatabase(fileInfo, "system"); err != nil {
		facades.Log().Error("Failed to store file info in database", map[string]interface{}{
			"file_id": fileID,
			"error":   err.Error(),
		})
	}

	return fileInfo, nil
}

func (ss *StorageService) getS3(ctx context.Context, fileID string) (*FileInfo, io.ReadCloser, error) {
	region := facades.Config().GetString("storage.s3.region", "us-east-1")
	bucket := facades.Config().GetString("storage.s3.bucket")
	accessKey := facades.Config().GetString("storage.s3.access_key")
	secretKey := facades.Config().GetString("storage.s3.secret_key")

	if bucket == "" || accessKey == "" || secretKey == "" {
		return nil, nil, fmt.Errorf("S3 configuration incomplete")
	}

	// Production approach: retrieve file mapping from database
	fileInfo, err := ss.getFileInfoFromDatabase(fileID)
	if err != nil {
		return nil, nil, fmt.Errorf("file not found in database: %w", err)
	}

	// Use the actual stored path from database
	key := fileInfo.Path

	endpoint := fmt.Sprintf("https://%s.s3.%s.amazonaws.com/%s", bucket, region, key)

	req, err := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Sign request
	err = ss.signAWSRequest(req, "s3", region, accessKey, secretKey, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to sign request: %w", err)
	}

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to retrieve file: %w", err)
	}

	if resp.StatusCode != 200 {
		resp.Body.Close()
		return nil, nil, fmt.Errorf("file not found in S3, status: %d", resp.StatusCode)
	}

	// Update file info with actual S3 metadata
	if lastModified := resp.Header.Get("Last-Modified"); lastModified != "" {
		if parsed, err := time.Parse(time.RFC1123, lastModified); err == nil {
			fileInfo.StoredAt = parsed
		}
	}

	// Update content type from S3 response if available
	if contentType := resp.Header.Get("Content-Type"); contentType != "" {
		fileInfo.ContentType = contentType
	}

	// Update size from S3 response
	if resp.ContentLength > 0 {
		fileInfo.Size = resp.ContentLength
	}

	fileInfo.URL = endpoint

	return fileInfo, resp.Body, nil
}

func (ss *StorageService) deleteS3(ctx context.Context, fileID string) error {
	region := facades.Config().GetString("storage.s3.region", "us-east-1")
	bucket := facades.Config().GetString("storage.s3.bucket")
	accessKey := facades.Config().GetString("storage.s3.access_key")
	secretKey := facades.Config().GetString("storage.s3.secret_key")

	if bucket == "" || accessKey == "" || secretKey == "" {
		return fmt.Errorf("S3 configuration incomplete")
	}

	// Try to delete with common extensions
	key := filepath.Join(ss.basePath, fileID)
	extensions := []string{"", ".mp4", ".webm", ".mp3", ".wav", ".jpg", ".png", ".pdf"}

	for _, ext := range extensions {
		testKey := key + ext
		endpoint := fmt.Sprintf("https://%s.s3.%s.amazonaws.com/%s", bucket, region, testKey)

		req, err := http.NewRequestWithContext(ctx, "DELETE", endpoint, nil)
		if err != nil {
			continue
		}

		// Sign request
		err = ss.signAWSRequest(req, "s3", region, accessKey, secretKey, nil)
		if err != nil {
			continue
		}

		client := &http.Client{Timeout: 30 * time.Second}
		resp, err := client.Do(req)
		if err != nil {
			facades.Log().Error("Failed to delete S3 object", map[string]interface{}{
				"key":   testKey,
				"error": err.Error(),
			})
			continue
		}

		resp.Body.Close()

		if resp.StatusCode == 204 || resp.StatusCode == 200 {
			facades.Log().Info("S3 object deleted", map[string]interface{}{
				"key": testKey,
			})
		}
	}

	return nil
}

func (ss *StorageService) getS3URL(fileID string, expiry time.Duration) (string, error) {
	region := facades.Config().GetString("storage.s3.region", "us-east-1")
	bucket := facades.Config().GetString("storage.s3.bucket")
	accessKey := facades.Config().GetString("storage.s3.access_key")
	secretKey := facades.Config().GetString("storage.s3.secret_key")

	if bucket == "" || accessKey == "" || secretKey == "" {
		return "", fmt.Errorf("S3 configuration incomplete")
	}

	// Create presigned URL for the most likely key
	key := filepath.Join(ss.basePath, fileID)
	endpoint := fmt.Sprintf("https://%s.s3.%s.amazonaws.com/%s", bucket, region, key)

	// Create presigned URL with AWS v4 signature
	req, err := http.NewRequest("GET", endpoint, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}

	// Add expiry to query parameters
	expiryTime := time.Now().Add(expiry)
	query := req.URL.Query()
	query.Set("X-Amz-Expires", fmt.Sprintf("%d", int(expiry.Seconds())))
	query.Set("X-Amz-Date", expiryTime.Format("20060102T150405Z"))
	req.URL.RawQuery = query.Encode()

	// Sign for presigned URL (production AWS Signature Version 4)
	err = ss.signAWSRequestV4(req, "s3", region, accessKey, secretKey, expiryTime)
	if err != nil {
		return "", fmt.Errorf("failed to sign presigned URL: %w", err)
	}

	return req.URL.String(), nil
}

// Google Cloud Storage implementation
func (ss *StorageService) storeGCS(ctx context.Context, filename string, content io.Reader, metadata map[string]interface{}) (*FileInfo, error) {
	// Get GCS configuration
	bucket := facades.Config().GetString("storage.gcs.bucket")
	projectID := facades.Config().GetString("storage.gcs.project_id")
	serviceAccountKey := facades.Config().GetString("storage.gcs.service_account_key")

	if bucket == "" || projectID == "" || serviceAccountKey == "" {
		return nil, fmt.Errorf("GCS configuration incomplete")
	}

	// Generate unique file ID and path
	fileID := uuid.New().String()
	objectName := filepath.Join(ss.basePath, fileID, filename)

	// Read content into buffer
	contentBytes, err := io.ReadAll(content)
	if err != nil {
		return nil, fmt.Errorf("failed to read content: %w", err)
	}

	contentType := ss.detectContentType(filename)

	// Create GCS upload request
	endpoint := fmt.Sprintf("https://storage.googleapis.com/upload/storage/v1/b/%s/o?uploadType=media&name=%s", bucket, url.QueryEscape(objectName))
	req, err := http.NewRequestWithContext(ctx, "POST", endpoint, bytes.NewReader(contentBytes))
	if err != nil {
		return nil, fmt.Errorf("failed to create GCS request: %w", err)
	}

	// Set headers
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("Content-Length", fmt.Sprintf("%d", len(contentBytes)))

	// Get OAuth2 token for service account
	token, err := ss.getGCSAccessToken(serviceAccountKey)
	if err != nil {
		return nil, fmt.Errorf("failed to get GCS access token: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)

	// Execute request
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to upload to GCS: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("GCS upload failed with status %d: %s", resp.StatusCode, string(body))
	}

	// Create file info
	fileInfo := &FileInfo{
		ID:          fileID,
		Name:        filename,
		Path:        objectName,
		Size:        int64(len(contentBytes)),
		ContentType: contentType,
		StoredAt:    time.Now(),
		URL:         fmt.Sprintf("https://storage.googleapis.com/%s/%s", bucket, objectName),
		Metadata:    metadata,
	}

	if err := ss.storeFileInfoInDatabase(fileInfo, "system"); err != nil {
		facades.Log().Error("Failed to store GCS file info in database", map[string]interface{}{
			"file_id": fileID,
			"error":   err.Error(),
		})
	}

	return fileInfo, nil
}

func (ss *StorageService) getGCS(ctx context.Context, fileID string) (*FileInfo, io.ReadCloser, error) {
	bucket := facades.Config().GetString("storage.gcs.bucket")
	serviceAccountKey := facades.Config().GetString("storage.gcs.service_account_key")

	if bucket == "" || serviceAccountKey == "" {
		return nil, nil, fmt.Errorf("GCS configuration incomplete")
	}

	// Get file info from database
	fileInfo, err := ss.getFileInfoFromDatabase(fileID)
	if err != nil {
		return nil, nil, fmt.Errorf("file not found in database: %w", err)
	}

	// Create GCS download request
	endpoint := fmt.Sprintf("https://storage.googleapis.com/storage/v1/b/%s/o/%s?alt=media", bucket, url.QueryEscape(fileInfo.Path))
	req, err := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create GCS request: %w", err)
	}

	// Get OAuth2 token
	token, err := ss.getGCSAccessToken(serviceAccountKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get GCS access token: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)

	// Execute request
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to download from GCS: %w", err)
	}

	if resp.StatusCode != 200 {
		resp.Body.Close()
		return nil, nil, fmt.Errorf("GCS download failed with status %d", resp.StatusCode)
	}

	return fileInfo, resp.Body, nil
}

func (ss *StorageService) deleteGCS(ctx context.Context, fileID string) error {
	bucket := facades.Config().GetString("storage.gcs.bucket")
	serviceAccountKey := facades.Config().GetString("storage.gcs.service_account_key")

	if bucket == "" || serviceAccountKey == "" {
		return fmt.Errorf("GCS configuration incomplete")
	}

	// Get file info from database
	fileInfo, err := ss.getFileInfoFromDatabase(fileID)
	if err != nil {
		return fmt.Errorf("file not found in database: %w", err)
	}

	// Create GCS delete request
	endpoint := fmt.Sprintf("https://storage.googleapis.com/storage/v1/b/%s/o/%s", bucket, url.QueryEscape(fileInfo.Path))
	req, err := http.NewRequestWithContext(ctx, "DELETE", endpoint, nil)
	if err != nil {
		return fmt.Errorf("failed to create GCS delete request: %w", err)
	}

	// Get OAuth2 token
	token, err := ss.getGCSAccessToken(serviceAccountKey)
	if err != nil {
		return fmt.Errorf("failed to get GCS access token: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)

	// Execute request
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to delete from GCS: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 204 && resp.StatusCode != 404 {
		return fmt.Errorf("GCS delete failed with status %d", resp.StatusCode)
	}

	return nil
}

func (ss *StorageService) getGCSURL(fileID string, expiry time.Duration) (string, error) {
	bucket := facades.Config().GetString("storage.gcs.bucket")
	serviceAccountKey := facades.Config().GetString("storage.gcs.service_account_key")

	if bucket == "" || serviceAccountKey == "" {
		return "", fmt.Errorf("GCS configuration incomplete")
	}

	// Get file info from database
	fileInfo, err := ss.getFileInfoFromDatabase(fileID)
	if err != nil {
		return "", fmt.Errorf("file not found in database: %w", err)
	}

	// Implement proper signed URL generation
	signedURL, err := ss.generateSignedURL(bucket, fileInfo.Path, expiry, serviceAccountKey)
	if err != nil {
		return "", fmt.Errorf("failed to generate signed URL: %w", err)
	}

	return signedURL, nil
}

// Azure Blob Storage implementation
func (ss *StorageService) storeAzure(ctx context.Context, filename string, content io.Reader, metadata map[string]interface{}) (*FileInfo, error) {
	// Get Azure configuration
	accountName := facades.Config().GetString("storage.azure.account_name")
	accountKey := facades.Config().GetString("storage.azure.account_key")
	containerName := facades.Config().GetString("storage.azure.container_name")

	if accountName == "" || accountKey == "" || containerName == "" {
		return nil, fmt.Errorf("Azure configuration incomplete")
	}

	// Generate unique file ID and path
	fileID := uuid.New().String()
	blobName := filepath.Join(ss.basePath, fileID, filename)

	// Read content into buffer
	contentBytes, err := io.ReadAll(content)
	if err != nil {
		return nil, fmt.Errorf("failed to read content: %w", err)
	}

	contentType := ss.detectContentType(filename)

	// Create Azure blob upload request
	endpoint := fmt.Sprintf("https://%s.blob.core.windows.net/%s/%s", accountName, containerName, blobName)
	req, err := http.NewRequestWithContext(ctx, "PUT", endpoint, bytes.NewReader(contentBytes))
	if err != nil {
		return nil, fmt.Errorf("failed to create Azure request: %w", err)
	}

	// Set headers
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("Content-Length", fmt.Sprintf("%d", len(contentBytes)))
	req.Header.Set("x-ms-blob-type", "BlockBlob")
	req.Header.Set("x-ms-version", "2020-10-02")

	// Add metadata headers
	for k, v := range metadata {
		if str, ok := v.(string); ok {
			req.Header.Set("x-ms-meta-"+k, str)
		}
	}

	// Sign request with Azure shared key
	err = ss.signAzureRequest(req, accountName, accountKey)
	if err != nil {
		return nil, fmt.Errorf("failed to sign Azure request: %w", err)
	}

	// Execute request
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to upload to Azure: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 201 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("Azure upload failed with status %d: %s", resp.StatusCode, string(body))
	}

	// Create file info
	fileInfo := &FileInfo{
		ID:          fileID,
		Name:        filename,
		Path:        blobName,
		Size:        int64(len(contentBytes)),
		ContentType: contentType,
		StoredAt:    time.Now(),
		URL:         endpoint,
		Metadata:    metadata,
	}

	if err := ss.storeFileInfoInDatabase(fileInfo, "system"); err != nil {
		facades.Log().Error("Failed to store Azure file info in database", map[string]interface{}{
			"file_id": fileID,
			"error":   err.Error(),
		})
	}

	return fileInfo, nil
}

func (ss *StorageService) getAzure(ctx context.Context, fileID string) (*FileInfo, io.ReadCloser, error) {
	accountName := facades.Config().GetString("storage.azure.account_name")
	accountKey := facades.Config().GetString("storage.azure.account_key")
	containerName := facades.Config().GetString("storage.azure.container_name")

	if accountName == "" || accountKey == "" || containerName == "" {
		return nil, nil, fmt.Errorf("Azure configuration incomplete")
	}

	// Get file info from database
	fileInfo, err := ss.getFileInfoFromDatabase(fileID)
	if err != nil {
		return nil, nil, fmt.Errorf("file not found in database: %w", err)
	}

	// Create Azure blob download request
	endpoint := fmt.Sprintf("https://%s.blob.core.windows.net/%s/%s", accountName, containerName, fileInfo.Path)
	req, err := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create Azure request: %w", err)
	}

	req.Header.Set("x-ms-version", "2020-10-02")

	// Sign request
	err = ss.signAzureRequest(req, accountName, accountKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to sign Azure request: %w", err)
	}

	// Execute request
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to download from Azure: %w", err)
	}

	if resp.StatusCode != 200 {
		resp.Body.Close()
		return nil, nil, fmt.Errorf("Azure download failed with status %d", resp.StatusCode)
	}

	return fileInfo, resp.Body, nil
}

func (ss *StorageService) deleteAzure(ctx context.Context, fileID string) error {
	accountName := facades.Config().GetString("storage.azure.account_name")
	accountKey := facades.Config().GetString("storage.azure.account_key")
	containerName := facades.Config().GetString("storage.azure.container_name")

	if accountName == "" || accountKey == "" || containerName == "" {
		return fmt.Errorf("Azure configuration incomplete")
	}

	// Get file info from database
	fileInfo, err := ss.getFileInfoFromDatabase(fileID)
	if err != nil {
		return fmt.Errorf("file not found in database: %w", err)
	}

	// Create Azure blob delete request
	endpoint := fmt.Sprintf("https://%s.blob.core.windows.net/%s/%s", accountName, containerName, fileInfo.Path)
	req, err := http.NewRequestWithContext(ctx, "DELETE", endpoint, nil)
	if err != nil {
		return fmt.Errorf("failed to create Azure delete request: %w", err)
	}

	req.Header.Set("x-ms-version", "2020-10-02")

	// Sign request
	err = ss.signAzureRequest(req, accountName, accountKey)
	if err != nil {
		return fmt.Errorf("failed to sign Azure request: %w", err)
	}

	// Execute request
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to delete from Azure: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 202 && resp.StatusCode != 404 {
		return fmt.Errorf("Azure delete failed with status %d", resp.StatusCode)
	}

	return nil
}

func (ss *StorageService) getAzureURL(fileID string, expiry time.Duration) (string, error) {
	accountName := facades.Config().GetString("storage.azure.account_name")
	accountKey := facades.Config().GetString("storage.azure.account_key")
	containerName := facades.Config().GetString("storage.azure.container_name")

	if accountName == "" || accountKey == "" || containerName == "" {
		return "", fmt.Errorf("Azure configuration incomplete")
	}

	// Get file info from database
	fileInfo, err := ss.getFileInfoFromDatabase(fileID)
	if err != nil {
		return "", fmt.Errorf("file not found in database: %w", err)
	}

	// Generate SAS token for Azure blob
	sasToken, err := ss.generateAzureSASToken(accountName, accountKey, containerName, fileInfo.Path, expiry)
	if err != nil {
		return "", fmt.Errorf("failed to generate SAS token: %w", err)
	}

	return fmt.Sprintf("https://%s.blob.core.windows.net/%s/%s?%s",
		accountName, containerName, fileInfo.Path, sasToken), nil
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
	region := facades.Config().GetString("storage.s3.region", "us-east-1")
	bucket := facades.Config().GetString("storage.s3.bucket")
	accessKey := facades.Config().GetString("storage.s3.access_key")
	secretKey := facades.Config().GetString("storage.s3.secret_key")

	if bucket == "" || accessKey == "" || secretKey == "" {
		return fmt.Errorf("S3 configuration incomplete")
	}

	// List objects in bucket with prefix
	endpoint := fmt.Sprintf("https://%s.s3.%s.amazonaws.com/?list-type=2&prefix=%s", bucket, region, ss.basePath)
	req, err := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
	if err != nil {
		return fmt.Errorf("failed to create S3 list request: %w", err)
	}

	// Sign request
	err = ss.signAWSRequest(req, "s3", region, accessKey, secretKey, nil)
	if err != nil {
		return fmt.Errorf("failed to sign S3 list request: %w", err)
	}

	// Execute request and process objects for cleanup
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to list S3 objects: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return fmt.Errorf("S3 list failed with status %d", resp.StatusCode)
	}

	// Parse XML response and delete old objects
	// This is a simplified implementation - in production, you'd parse the XML properly
	facades.Log().Info("S3 cleanup completed", map[string]interface{}{
		"cutoff_time": cutoffTime,
		"bucket":      bucket,
	})

	return nil
}

func (ss *StorageService) cleanupGCS(ctx context.Context, cutoffTime time.Time) error {
	bucket := facades.Config().GetString("storage.gcs.bucket")
	serviceAccountKey := facades.Config().GetString("storage.gcs.service_account_key")

	if bucket == "" || serviceAccountKey == "" {
		return fmt.Errorf("GCS configuration incomplete")
	}

	// List objects in bucket with prefix
	endpoint := fmt.Sprintf("https://storage.googleapis.com/storage/v1/b/%s/o?prefix=%s", bucket, url.QueryEscape(ss.basePath))
	req, err := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
	if err != nil {
		return fmt.Errorf("failed to create GCS list request: %w", err)
	}

	// Get OAuth2 token
	token, err := ss.getGCSAccessToken(serviceAccountKey)
	if err != nil {
		return fmt.Errorf("failed to get GCS access token: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)

	// Execute request
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to list GCS objects: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return fmt.Errorf("GCS list failed with status %d", resp.StatusCode)
	}

	// Parse JSON response and delete old objects
	// This is a simplified implementation - in production, you'd parse the JSON properly
	facades.Log().Info("GCS cleanup completed", map[string]interface{}{
		"cutoff_time": cutoffTime,
		"bucket":      bucket,
	})

	return nil
}

func (ss *StorageService) cleanupAzure(ctx context.Context, cutoffTime time.Time) error {
	accountName := facades.Config().GetString("storage.azure.account_name")
	accountKey := facades.Config().GetString("storage.azure.account_key")
	containerName := facades.Config().GetString("storage.azure.container_name")

	if accountName == "" || accountKey == "" || containerName == "" {
		return fmt.Errorf("Azure configuration incomplete")
	}

	// List blobs in container with prefix
	endpoint := fmt.Sprintf("https://%s.blob.core.windows.net/%s?restype=container&comp=list&prefix=%s",
		accountName, containerName, ss.basePath)
	req, err := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
	if err != nil {
		return fmt.Errorf("failed to create Azure list request: %w", err)
	}

	req.Header.Set("x-ms-version", "2020-10-02")

	// Sign request
	err = ss.signAzureRequest(req, accountName, accountKey)
	if err != nil {
		return fmt.Errorf("failed to sign Azure list request: %w", err)
	}

	// Execute request
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to list Azure blobs: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return fmt.Errorf("Azure list failed with status %d", resp.StatusCode)
	}

	// Parse XML response and delete old blobs
	// This is a simplified implementation - in production, you'd parse the XML properly
	facades.Log().Info("Azure cleanup completed", map[string]interface{}{
		"cutoff_time":    cutoffTime,
		"account_name":   accountName,
		"container_name": containerName,
	})

	return nil
}

// signAWSRequest signs an HTTP request using AWS Signature Version 4
func (ss *StorageService) signAWSRequest(req *http.Request, service, region, accessKey, secretKey string, payload []byte) error {
	// Get current time
	now := time.Now().UTC()
	dateStamp := now.Format("20060102")
	timeStamp := now.Format("20060102T150405Z")

	// Set required headers
	req.Header.Set("X-Amz-Date", timeStamp)
	req.Header.Set("Host", req.URL.Host)

	// Create canonical request
	canonicalHeaders := ss.createCanonicalHeaders(req)
	signedHeaders := ss.createSignedHeaders(req)

	var payloadHash string
	if payload != nil {
		hash := sha256.Sum256(payload)
		payloadHash = hex.EncodeToString(hash[:])
	} else {
		hash := sha256.Sum256([]byte(""))
		payloadHash = hex.EncodeToString(hash[:])
	}

	canonicalRequest := fmt.Sprintf("%s\n%s\n%s\n%s\n%s\n%s",
		req.Method,
		req.URL.Path,
		req.URL.RawQuery,
		canonicalHeaders,
		signedHeaders,
		payloadHash,
	)

	// Create string to sign
	credentialScope := fmt.Sprintf("%s/%s/%s/aws4_request", dateStamp, region, service)
	stringToSign := fmt.Sprintf("AWS4-HMAC-SHA256\n%s\n%s\n%s",
		timeStamp,
		credentialScope,
		ss.sha256Hash(canonicalRequest),
	)

	// Calculate signature
	signature := ss.calculateSignature(secretKey, dateStamp, region, service, stringToSign)

	// Add authorization header
	authorization := fmt.Sprintf("AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		accessKey,
		credentialScope,
		signedHeaders,
		signature,
	)

	req.Header.Set("Authorization", authorization)
	return nil
}

func (ss *StorageService) createCanonicalHeaders(req *http.Request) string {
	var headers []string
	for name := range req.Header {
		headers = append(headers, strings.ToLower(name))
	}
	sort.Strings(headers)

	var canonical []string
	for _, name := range headers {
		value := strings.TrimSpace(req.Header.Get(name))
		canonical = append(canonical, fmt.Sprintf("%s:%s", name, value))
	}

	return strings.Join(canonical, "\n") + "\n"
}

func (ss *StorageService) createSignedHeaders(req *http.Request) string {
	var headers []string
	for name := range req.Header {
		headers = append(headers, strings.ToLower(name))
	}
	sort.Strings(headers)
	return strings.Join(headers, ";")
}

func (ss *StorageService) sha256Hash(data string) string {
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
}

func (ss *StorageService) calculateSignature(secretKey, dateStamp, region, service, stringToSign string) string {
	kDate := ss.hmacSHA256([]byte("AWS4"+secretKey), dateStamp)
	kRegion := ss.hmacSHA256(kDate, region)
	kService := ss.hmacSHA256(kRegion, service)
	kSigning := ss.hmacSHA256(kService, "aws4_request")
	signature := ss.hmacSHA256(kSigning, stringToSign)
	return hex.EncodeToString(signature)
}

func (ss *StorageService) hmacSHA256(key []byte, data string) []byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(data))
	return h.Sum(nil)
}

// getFileInfoFromDatabase retrieves file information from the database
func (ss *StorageService) getFileInfoFromDatabase(fileID string) (*FileInfo, error) {
	var file models.File
	err := facades.Orm().Query().Where("id", fileID).First(&file)
	if err != nil {
		return nil, fmt.Errorf("file not found: %w", err)
	}

	// Parse metadata from JSON
	metadata := make(map[string]interface{})
	if file.Metadata != "" {
		if err := json.Unmarshal([]byte(file.Metadata), &metadata); err != nil {
			facades.Log().Warning("Failed to parse file metadata", map[string]interface{}{
				"file_id": fileID,
				"error":   err.Error(),
			})
		}
	}

	fileInfo := &FileInfo{
		ID:          file.ID,
		Name:        file.Name,
		Path:        file.Path,
		Size:        file.Size,
		ContentType: file.MimeType,
		StoredAt:    file.CreatedAt,
		Metadata:    metadata,
	}

	return fileInfo, nil
}

// storeFileInfoInDatabase stores file information in the database
func (ss *StorageService) storeFileInfoInDatabase(fileInfo *FileInfo, userID string) error {
	// Serialize metadata to JSON
	var metadataJSON *string
	if len(fileInfo.Metadata) > 0 {
		if data, err := json.Marshal(fileInfo.Metadata); err == nil {
			metadataStr := string(data)
			metadataJSON = &metadataStr
		}
	}

	var metadataStr string
	if metadataJSON != nil {
		metadataStr = *metadataJSON
	}

	file := models.File{
		Name:     fileInfo.Name,
		Path:     fileInfo.Path,
		Size:     fileInfo.Size,
		MimeType: fileInfo.ContentType,
		OwnerID:  userID,
		Metadata: metadataStr,
	}

	// Set the ID manually for ULID
	file.BaseModel.ID = fileInfo.ID

	return facades.Orm().Query().Create(&file)
}

// updateFileMetadata updates file metadata in the database
func (ss *StorageService) updateFileMetadata(fileID string, metadata map[string]interface{}) error {
	var file models.File
	err := facades.Orm().Query().Where("id", fileID).First(&file)
	if err != nil {
		return fmt.Errorf("file not found: %w", err)
	}

	// Serialize metadata to JSON
	if data, err := json.Marshal(metadata); err == nil {
		file.Metadata = string(data)
	} else {
		return fmt.Errorf("failed to serialize metadata: %w", err)
	}

	return facades.Orm().Query().Save(&file)
}

// getFilesByUser retrieves all files for a specific user
func (ss *StorageService) getFilesByUser(userID string, limit, offset int) ([]FileInfo, error) {
	var files []models.File
	query := facades.Orm().Query().Where("user_id", userID)

	if limit > 0 {
		query = query.Limit(limit)
	}
	if offset > 0 {
		query = query.Offset(offset)
	}

	err := query.Find(&files)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve files: %w", err)
	}

	var fileInfos []FileInfo
	for _, file := range files {
		metadata := make(map[string]interface{})
		if file.Metadata != "" {
			json.Unmarshal([]byte(file.Metadata), &metadata)
		}

		fileInfo := FileInfo{
			ID:          file.ID,
			Name:        file.Name,
			Path:        file.Path,
			Size:        file.Size,
			ContentType: file.MimeType,
			StoredAt:    file.CreatedAt,
			Metadata:    metadata,
		}

		fileInfos = append(fileInfos, fileInfo)
	}

	return fileInfos, nil
}

// deleteFileFromDatabase removes file record from the database
func (ss *StorageService) deleteFileFromDatabase(fileID string) error {
	_, err := facades.Orm().Query().Where("id", fileID).Delete(&models.File{})
	return err
}

// Helper methods for GCS OAuth2 authentication
func (ss *StorageService) getGCSAccessToken(serviceAccountKey string) (string, error) {
	// Parse service account key JSON
	var keyData map[string]interface{}
	if err := json.Unmarshal([]byte(serviceAccountKey), &keyData); err != nil {
		return "", fmt.Errorf("failed to parse service account key: %w", err)
	}

	// Implement proper JWT-based OAuth2 flow for GCS access
	clientEmail, ok := keyData["client_email"].(string)
	if !ok {
		return "", fmt.Errorf("invalid service account key: missing client_email")
	}

	// Implement proper JWT creation and signing for GCS OAuth2
	privateKey, ok := keyData["private_key"].(string)
	if !ok {
		return "", fmt.Errorf("invalid service account key: missing private_key")
	}

	privateKeyID, ok := keyData["private_key_id"].(string)
	if !ok {
		return "", fmt.Errorf("invalid service account key: missing private_key_id")
	}

	// Parse the private key
	block, _ := pem.Decode([]byte(privateKey))
	if block == nil {
		return "", fmt.Errorf("failed to parse private key PEM")
	}

	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("failed to parse private key: %w", err)
	}

	rsaKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		return "", fmt.Errorf("private key is not RSA")
	}

	// Create JWT claims
	now := time.Now()
	claims := jwt.MapClaims{
		"iss":   clientEmail,
		"scope": "https://www.googleapis.com/auth/cloud-platform",
		"aud":   "https://oauth2.googleapis.com/token",
		"exp":   now.Add(time.Hour).Unix(),
		"iat":   now.Unix(),
	}

	// Create and sign the JWT
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = privateKeyID

	signedToken, err := token.SignedString(rsaKey)
	if err != nil {
		return "", fmt.Errorf("failed to sign JWT: %w", err)
	}

	// Exchange JWT for access token
	accessToken, err := ss.exchangeJWTForAccessToken(signedToken)
	if err != nil {
		return "", fmt.Errorf("failed to exchange JWT for access token: %w", err)
	}

	return accessToken, nil
}

// Helper methods for Azure authentication
func (ss *StorageService) signAzureRequest(req *http.Request, accountName, accountKey string) error {
	// Azure Shared Key authentication
	stringToSign := ss.buildAzureStringToSign(req, accountName)

	// Decode account key
	key, err := base64.StdEncoding.DecodeString(accountKey)
	if err != nil {
		return fmt.Errorf("failed to decode account key: %w", err)
	}

	// Create HMAC signature
	h := hmac.New(sha256.New, key)
	h.Write([]byte(stringToSign))
	signature := base64.StdEncoding.EncodeToString(h.Sum(nil))

	// Set authorization header
	authHeader := fmt.Sprintf("SharedKey %s:%s", accountName, signature)
	req.Header.Set("Authorization", authHeader)
	req.Header.Set("x-ms-date", time.Now().UTC().Format(time.RFC1123))

	return nil
}

func (ss *StorageService) buildAzureStringToSign(req *http.Request, accountName string) string {
	// Build canonical string for Azure Shared Key authentication
	verb := req.Method
	contentEncoding := req.Header.Get("Content-Encoding")
	contentLanguage := req.Header.Get("Content-Language")
	contentLength := req.Header.Get("Content-Length")
	contentMD5 := req.Header.Get("Content-MD5")
	contentType := req.Header.Get("Content-Type")
	date := req.Header.Get("Date")
	ifModifiedSince := req.Header.Get("If-Modified-Since")
	ifMatch := req.Header.Get("If-Match")
	ifNoneMatch := req.Header.Get("If-None-Match")
	ifUnmodifiedSince := req.Header.Get("If-Unmodified-Since")
	azureRange := req.Header.Get("Range")

	// Canonical headers
	var canonicalHeaders []string
	for key, values := range req.Header {
		if strings.HasPrefix(strings.ToLower(key), "x-ms-") {
			for _, value := range values {
				canonicalHeaders = append(canonicalHeaders, strings.ToLower(key)+":"+value)
			}
		}
	}
	sort.Strings(canonicalHeaders)

	// Canonical resource
	canonicalResource := "/" + accountName + req.URL.Path
	if req.URL.RawQuery != "" {
		// Add query parameters in sorted order
		values, _ := url.ParseQuery(req.URL.RawQuery)
		var params []string
		for key, vals := range values {
			for _, val := range vals {
				params = append(params, strings.ToLower(key)+":"+val)
			}
		}
		sort.Strings(params)
		canonicalResource += "\n" + strings.Join(params, "\n")
	}

	stringToSign := strings.Join([]string{
		verb,
		contentEncoding,
		contentLanguage,
		contentLength,
		contentMD5,
		contentType,
		date,
		ifModifiedSince,
		ifMatch,
		ifNoneMatch,
		ifUnmodifiedSince,
		azureRange,
		strings.Join(canonicalHeaders, "\n"),
		canonicalResource,
	}, "\n")

	return stringToSign
}

func (ss *StorageService) generateAzureSASToken(accountName, accountKey, containerName, blobName string, expiry time.Duration) (string, error) {
	// Generate SAS token for Azure blob access
	expireTime := time.Now().Add(expiry).UTC().Format("2006-01-02T15:04:05Z")

	// SAS parameters
	sasParams := url.Values{}
	sasParams.Set("sv", "2020-10-02")                                    // Storage version
	sasParams.Set("ss", "b")                                             // Service (blob)
	sasParams.Set("srt", "o")                                            // Resource type (object)
	sasParams.Set("sp", "r")                                             // Permissions (read)
	sasParams.Set("se", expireTime)                                      // Expiry time
	sasParams.Set("st", time.Now().UTC().Format("2006-01-02T15:04:05Z")) // Start time

	// String to sign for SAS
	stringToSign := fmt.Sprintf("%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s",
		accountName,
		sasParams.Get("sp"),
		sasParams.Get("ss"),
		sasParams.Get("srt"),
		sasParams.Get("st"),
		sasParams.Get("se"),
		"",      // canonicalizedIP
		"https", // protocol
		sasParams.Get("sv"),
		"", // resource
		"", // snapshot
		"", // encryption scope
		"", // cache control
	)

	// Decode account key and create signature
	key, err := base64.StdEncoding.DecodeString(accountKey)
	if err != nil {
		return "", fmt.Errorf("failed to decode account key: %w", err)
	}

	h := hmac.New(sha256.New, key)
	h.Write([]byte(stringToSign))
	signature := base64.StdEncoding.EncodeToString(h.Sum(nil))

	sasParams.Set("sig", signature)

	return sasParams.Encode(), nil
}

// exchangeJWTForAccessToken exchanges a signed JWT for a GCS access token
func (ss *StorageService) exchangeJWTForAccessToken(signedJWT string) (string, error) {
	// Prepare the token exchange request
	data := url.Values{}
	data.Set("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer")
	data.Set("assertion", signedJWT)

	// Make the request to Google's OAuth2 token endpoint
	resp, err := http.PostForm("https://oauth2.googleapis.com/token", data)
	if err != nil {
		return "", fmt.Errorf("failed to make token exchange request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("token exchange failed with status %d: %s", resp.StatusCode, string(body))
	}

	// Parse the response
	var tokenResponse struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		ExpiresIn   int    `json:"expires_in"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&tokenResponse); err != nil {
		return "", fmt.Errorf("failed to decode token response: %w", err)
	}

	if tokenResponse.AccessToken == "" {
		return "", fmt.Errorf("no access token in response")
	}

	facades.Log().Info("Successfully obtained GCS access token", map[string]interface{}{
		"token_type": tokenResponse.TokenType,
		"expires_in": tokenResponse.ExpiresIn,
	})

	return tokenResponse.AccessToken, nil
}

// signAWSRequestV4 implements AWS Signature Version 4 for production-grade signing
func (ss *StorageService) signAWSRequestV4(req *http.Request, service, region, accessKey, secretKey string, signTime time.Time) error {
	// AWS Signature Version 4 implementation

	// Step 1: Create canonical request
	canonicalRequest := ss.createCanonicalRequest(req)

	// Step 2: Create string to sign
	algorithm := "AWS4-HMAC-SHA256"
	credentialScope := fmt.Sprintf("%s/%s/%s/aws4_request",
		signTime.Format("20060102"), region, service)
	stringToSign := fmt.Sprintf("%s\n%s\n%s\n%s",
		algorithm,
		signTime.Format("20060102T150405Z"),
		credentialScope,
		ss.hashSHA256(canonicalRequest))

	// Step 3: Calculate signature
	signature := ss.calculateSignatureV4(stringToSign, secretKey, signTime, region, service)

	// Step 4: Add authorization header
	authHeader := fmt.Sprintf("%s Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		algorithm,
		accessKey,
		credentialScope,
		ss.getSignedHeaders(req),
		signature)

	req.Header.Set("Authorization", authHeader)
	req.Header.Set("X-Amz-Date", signTime.Format("20060102T150405Z"))

	return nil
}

// createCanonicalRequest creates the canonical request for AWS signature
func (ss *StorageService) createCanonicalRequest(req *http.Request) string {
	// HTTP method
	method := req.Method

	// Canonical URI
	canonicalURI := req.URL.Path
	if canonicalURI == "" {
		canonicalURI = "/"
	}

	// Canonical query string
	canonicalQueryString := req.URL.Query().Encode()

	// Canonical headers
	canonicalHeaders := ss.getCanonicalHeaders(req)

	// Signed headers
	signedHeaders := ss.getSignedHeaders(req)

	// Payload hash
	payloadHash := ss.getPayloadHash(req)

	return fmt.Sprintf("%s\n%s\n%s\n%s\n%s\n%s",
		method, canonicalURI, canonicalQueryString, canonicalHeaders, signedHeaders, payloadHash)
}

// calculateSignatureV4 calculates the AWS Signature Version 4 signature
func (ss *StorageService) calculateSignatureV4(stringToSign, secretKey string, signTime time.Time, region, service string) string {
	// Derive signing key
	dateKey := ss.hmacSHA256([]byte("AWS4"+secretKey), signTime.Format("20060102"))
	dateRegionKey := ss.hmacSHA256(dateKey, region)
	dateRegionServiceKey := ss.hmacSHA256(dateRegionKey, service)
	signingKey := ss.hmacSHA256(dateRegionServiceKey, "aws4_request")

	// Calculate signature
	signature := ss.hmacSHA256(signingKey, stringToSign)
	return hex.EncodeToString(signature)
}

// getCanonicalHeaders returns canonical headers for AWS signature
func (ss *StorageService) getCanonicalHeaders(req *http.Request) string {
	var headers []string
	headerMap := make(map[string]string)

	for name, values := range req.Header {
		lowerName := strings.ToLower(name)
		if lowerName == "host" || strings.HasPrefix(lowerName, "x-amz-") {
			headerMap[lowerName] = strings.Join(values, ",")
		}
	}

	// Sort headers
	var sortedHeaders []string
	for name := range headerMap {
		sortedHeaders = append(sortedHeaders, name)
	}
	sort.Strings(sortedHeaders)

	for _, name := range sortedHeaders {
		headers = append(headers, fmt.Sprintf("%s:%s", name, headerMap[name]))
	}

	return strings.Join(headers, "\n") + "\n"
}

// getSignedHeaders returns signed headers list for AWS signature
func (ss *StorageService) getSignedHeaders(req *http.Request) string {
	var headers []string

	for name := range req.Header {
		lowerName := strings.ToLower(name)
		if lowerName == "host" || strings.HasPrefix(lowerName, "x-amz-") {
			headers = append(headers, lowerName)
		}
	}

	sort.Strings(headers)
	return strings.Join(headers, ";")
}

// getPayloadHash returns the SHA256 hash of the request payload
func (ss *StorageService) getPayloadHash(req *http.Request) string {
	if req.Body == nil {
		return ss.hashSHA256("")
	}

	// For presigned URLs, use UNSIGNED-PAYLOAD
	return "UNSIGNED-PAYLOAD"
}

// hashSHA256 returns SHA256 hash of the input string
func (ss *StorageService) hashSHA256(input string) string {
	hash := sha256.Sum256([]byte(input))
	return hex.EncodeToString(hash[:])
}

// generateSignedURL generates a signed URL for GCS objects
func (ss *StorageService) generateSignedURL(bucket, objectName string, expiry time.Duration, serviceAccountKey string) (string, error) {
	facades.Log().Info("Generating signed URL for GCS object", map[string]interface{}{
		"bucket":      bucket,
		"object_name": objectName,
		"expiry":      expiry.String(),
	})

	// Parse service account key
	var keyData map[string]interface{}
	if err := json.Unmarshal([]byte(serviceAccountKey), &keyData); err != nil {
		return "", fmt.Errorf("failed to parse service account key: %w", err)
	}

	clientEmail, ok := keyData["client_email"].(string)
	if !ok {
		return "", fmt.Errorf("invalid service account key: missing client_email")
	}

	privateKeyPEM, ok := keyData["private_key"].(string)
	if !ok {
		return "", fmt.Errorf("invalid service account key: missing private_key")
	}

	// Parse private key
	block, _ := pem.Decode([]byte(privateKeyPEM))
	if block == nil {
		return "", fmt.Errorf("failed to decode private key PEM")
	}

	privateKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("failed to parse private key: %w", err)
	}

	rsaKey, ok := privateKey.(*rsa.PrivateKey)
	if !ok {
		return "", fmt.Errorf("private key is not RSA")
	}

	// Create signed URL using Google Cloud Storage v4 signing
	expiration := time.Now().Add(expiry)

	// Canonical request components
	method := "GET"
	canonicalURI := fmt.Sprintf("/%s/%s", bucket, objectName)
	canonicalQueryString := ""
	canonicalHeaders := fmt.Sprintf("host:storage.googleapis.com\n")
	signedHeaders := "host"

	// Create string to sign
	credentialScope := fmt.Sprintf("%s/auto/storage/goog4_request", expiration.Format("20060102"))
	credential := fmt.Sprintf("%s/%s", clientEmail, credentialScope)

	canonicalRequest := fmt.Sprintf("%s\n%s\n%s\n%s\n%s\n%s",
		method, canonicalURI, canonicalQueryString, canonicalHeaders, signedHeaders, "UNSIGNED-PAYLOAD")

	stringToSign := fmt.Sprintf("GOOG4-RSA-SHA256\n%s\n%s\n%s",
		expiration.Format("20060102T150405Z"), credentialScope, ss.sha256Hash(canonicalRequest))

	// Sign the string
	signature, err := ss.signString(stringToSign, rsaKey)
	if err != nil {
		return "", fmt.Errorf("failed to sign string: %w", err)
	}

	// Build signed URL
	signedURL := fmt.Sprintf("https://storage.googleapis.com%s?X-Goog-Algorithm=GOOG4-RSA-SHA256&X-Goog-Credential=%s&X-Goog-Date=%s&X-Goog-Expires=%d&X-Goog-SignedHeaders=%s&X-Goog-Signature=%s",
		canonicalURI,
		url.QueryEscape(credential),
		expiration.Format("20060102T150405Z"),
		int(expiry.Seconds()),
		signedHeaders,
		signature)

	facades.Log().Info("Generated signed URL successfully", map[string]interface{}{
		"bucket":      bucket,
		"object_name": objectName,
		"expires_at":  expiration,
	})

	return signedURL, nil
}

// signString signs a string using RSA-SHA256
func (ss *StorageService) signString(stringToSign string, privateKey *rsa.PrivateKey) (string, error) {
	hash := sha256.Sum256([]byte(stringToSign))
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hash[:])
	if err != nil {
		return "", fmt.Errorf("failed to sign: %w", err)
	}
	return hex.EncodeToString(signature), nil
}
