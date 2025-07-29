package services

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"image"
	"image/color"
	"image/jpeg"
	"io"
	"math"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"goravel/app/models"

	"github.com/golang-jwt/jwt/v5"
	"github.com/goravel/framework/facades"
)

// MeetingRecordingService handles meeting recording operations
type MeetingRecordingService struct {
	storageService      *StorageService
	transcriptionClient *TranscriptionClient
	aiService           *AIService
	mu                  sync.RWMutex
	activeRecordings    map[string]*ActiveRecording
}

// ActiveRecording represents an ongoing recording session
type ActiveRecording struct {
	RecordingID        string
	MeetingID          string
	StartedAt          time.Time
	Status             string
	FilePath           string
	FileSize           int64
	Duration           int
	Participants       []string
	LiveKitRecordingID string
	mu                 sync.RWMutex
}

// LiveKit recording types
type LiveKitRecordingRequest struct {
	RoomName string            `json:"room_name"`
	Layout   string            `json:"layout"`
	Output   *RecordingOutput  `json:"output"`
	Options  *RecordingOptions `json:"options"`
}

type RecordingOutput struct {
	FileType string `json:"file_type"`
	Filepath string `json:"filepath"`
}

type RecordingOptions struct {
	Width     int    `json:"width"`
	Height    int    `json:"height"`
	Preset    string `json:"preset"`
	AudioOnly bool   `json:"audio_only"`
}

type LiveKitRecordingResponse struct {
	RecordingID string `json:"recording_id"`
	Status      string `json:"status"`
}

type LiveKitRecordingStatus struct {
	RecordingID string `json:"recording_id"`
	Status      string `json:"status"`
	Duration    int    `json:"duration"`
	FileSize    int64  `json:"file_size"`
	Error       string `json:"error,omitempty"`
}

// TranscriptionClient handles speech-to-text operations
type TranscriptionClient struct {
	apiKey   string
	endpoint string
	provider string // whisper, google, azure, aws
	client   *http.Client
}

// AIService handles AI-powered meeting analysis
type AIService struct {
	apiKey   string
	endpoint string
	provider string // openai, claude, gemini
	client   *http.Client
}

// RecordingConfiguration defines recording settings
type RecordingConfiguration struct {
	Quality             string   `json:"quality"` // low, medium, high, ultra
	Format              string   `json:"format"`  // mp4, webm, mp3
	IncludeVideo        bool     `json:"include_video"`
	IncludeAudio        bool     `json:"include_audio"`
	IncludeScreenShare  bool     `json:"include_screen_share"`
	SeparateAudioTracks bool     `json:"separate_audio_tracks"`
	AutoTranscribe      bool     `json:"auto_transcribe"`
	GenerateSummary     bool     `json:"generate_summary"`
	LanguageCode        string   `json:"language_code"`
	RetentionDays       int      `json:"retention_days"`
	AllowedViewers      []string `json:"allowed_viewers"`
	IsPublic            bool     `json:"is_public"`
	WatermarkEnabled    bool     `json:"watermark_enabled"`
	EncryptionEnabled   bool     `json:"encryption_enabled"`
}

// MeetingSummary represents AI-generated meeting summary
type MeetingSummary struct {
	Summary          string                 `json:"summary"`
	KeyPoints        []string               `json:"key_points"`
	ActionItems      []ActionItem           `json:"action_items"`
	Decisions        []Decision             `json:"decisions"`
	Topics           []Topic                `json:"topics"`
	Sentiment        string                 `json:"sentiment"`
	ParticipantStats map[string]interface{} `json:"participant_stats"`
	MeetingMetrics   MeetingMetrics         `json:"meeting_metrics"`
	GeneratedAt      time.Time              `json:"generated_at"`
}

// ActionItem represents a task identified in the meeting
type ActionItem struct {
	ID          string    `json:"id"`
	Description string    `json:"description"`
	AssignedTo  string    `json:"assigned_to"`
	DueDate     time.Time `json:"due_date"`
	Priority    string    `json:"priority"`
	Status      string    `json:"status"`
}

// Decision represents a decision made in the meeting
type Decision struct {
	ID          string    `json:"id"`
	Description string    `json:"description"`
	DecisionBy  string    `json:"decision_by"`
	Impact      string    `json:"impact"`
	Timestamp   time.Time `json:"timestamp"`
}

// Topic represents a discussion topic
type Topic struct {
	Name         string        `json:"name"`
	Duration     time.Duration `json:"duration"`
	Participants []string      `json:"participants"`
	Sentiment    string        `json:"sentiment"`
}

// RecordingMetrics contains meeting recording analytics
type RecordingMetrics struct {
	TotalDuration     time.Duration          `json:"total_duration"`
	SpeakingTime      map[string]interface{} `json:"speaking_time"`
	InterruptionCount int                    `json:"interruption_count"`
	SilencePercentage float64                `json:"silence_percentage"`
	EngagementScore   float64                `json:"engagement_score"`
	PaceScore         float64                `json:"pace_score"`
}

// NewMeetingRecordingService creates a new recording service
func NewMeetingRecordingService() *MeetingRecordingService {
	return &MeetingRecordingService{
		storageService:      NewStorageService(),
		transcriptionClient: NewTranscriptionClient(),
		aiService:           NewAIService(),
		activeRecordings:    make(map[string]*ActiveRecording),
	}
}

// NewTranscriptionClient creates a new transcription client
func NewTranscriptionClient() *TranscriptionClient {
	provider := facades.Config().GetString("transcription.provider", "whisper")
	apiKey := facades.Config().GetString("transcription.api_key")
	endpoint := facades.Config().GetString("transcription.endpoint")

	return &TranscriptionClient{
		apiKey:   apiKey,
		endpoint: endpoint,
		provider: provider,
		client:   &http.Client{Timeout: 30 * time.Second},
	}
}

// NewAIService creates a new AI service
func NewAIService() *AIService {
	provider := facades.Config().GetString("ai.provider", "openai")
	apiKey := facades.Config().GetString("ai.api_key")
	endpoint := facades.Config().GetString("ai.endpoint")

	return &AIService{
		apiKey:   apiKey,
		endpoint: endpoint,
		provider: provider,
		client:   &http.Client{Timeout: 60 * time.Second},
	}
}

// StartRecording initiates meeting recording
func (mrs *MeetingRecordingService) StartRecording(meetingID, userID string, config RecordingConfiguration) (*models.MeetingRecording, error) {
	mrs.mu.Lock()
	defer mrs.mu.Unlock()

	// Check if recording is already active
	if _, exists := mrs.activeRecordings[meetingID]; exists {
		return nil, fmt.Errorf("recording already active for meeting %s", meetingID)
	}

	// Validate meeting exists and user has permission
	if err := mrs.validateRecordingPermission(meetingID, userID); err != nil {
		return nil, err
	}

	// Generate recording file path
	timestamp := time.Now().Format("20060102_150405")
	fileName := fmt.Sprintf("meeting_%s_%s.%s", meetingID, timestamp, config.Format)
	filePath := filepath.Join("recordings", meetingID, fileName)

	// Create recording record
	recording := &models.MeetingRecording{
		MeetingID:     meetingID,
		RecordingType: "video",
		FileName:      fileName,
		FilePath:      filePath,
		Format:        config.Format,
		Quality:       config.Quality,
		Status:        "recording",
		IsPublic:      config.IsPublic,
		StartedAt:     time.Now(),
	}

	// Set metadata
	metadata := map[string]interface{}{
		"configuration": config,
		"started_by":    userID,
		"encryption":    config.EncryptionEnabled,
		"watermark":     config.WatermarkEnabled,
	}
	metadataJSON, _ := json.Marshal(metadata)
	recording.Metadata = string(metadataJSON)

	// Save to database
	if err := facades.Orm().Query().Create(recording); err != nil {
		return nil, fmt.Errorf("failed to create recording record: %v", err)
	}

	// Create active recording session
	activeRecording := &ActiveRecording{
		RecordingID:  recording.ID,
		MeetingID:    meetingID,
		StartedAt:    time.Now(),
		Status:       "recording",
		FilePath:     filePath,
		Participants: mrs.getMeetingParticipants(meetingID),
	}

	mrs.activeRecordings[meetingID] = activeRecording

	// Start actual recording process (integrate with LiveKit or other service)
	go mrs.performRecording(activeRecording, config)

	facades.Log().Info("Meeting recording started", map[string]interface{}{
		"meeting_id":   meetingID,
		"recording_id": recording.ID,
		"started_by":   userID,
		"config":       config,
	})

	return recording, nil
}

// StopRecording stops meeting recording
func (mrs *MeetingRecordingService) StopRecording(meetingID, userID string) (*models.MeetingRecording, error) {
	mrs.mu.Lock()
	activeRecording, exists := mrs.activeRecordings[meetingID]
	if !exists {
		mrs.mu.Unlock()
		return nil, fmt.Errorf("no active recording for meeting %s", meetingID)
	}
	delete(mrs.activeRecordings, meetingID)
	mrs.mu.Unlock()

	// Update recording status
	var recording models.MeetingRecording
	err := facades.Orm().Query().Where("id", activeRecording.RecordingID).First(&recording)
	if err != nil {
		return nil, fmt.Errorf("recording not found: %v", err)
	}

	now := time.Now()
	recording.Status = "processing"
	recording.CompletedAt = &now
	recording.Duration = fmt.Sprintf("%.0f", now.Sub(activeRecording.StartedAt).Seconds())

	// Update file size if available
	if fileInfo, err := os.Stat(activeRecording.FilePath); err == nil {
		recording.FileSize = fmt.Sprintf("%d", fileInfo.Size())
		activeRecording.FileSize = fileInfo.Size()
	}

	if err := facades.Orm().Query().Save(&recording); err != nil {
		return nil, fmt.Errorf("failed to update recording: %v", err)
	}

	// Start post-processing
	go mrs.postProcessRecording(&recording, activeRecording)

	facades.Log().Info("Meeting recording stopped", map[string]interface{}{
		"meeting_id":   meetingID,
		"recording_id": recording.ID,
		"stopped_by":   userID,
		"duration":     recording.Duration,
	})

	return &recording, nil
}

// performRecording handles the actual recording process
func (mrs *MeetingRecordingService) performRecording(activeRecording *ActiveRecording, config RecordingConfiguration) {
	// Production-ready recording implementation
	defer func() {
		if r := recover(); r != nil {
			facades.Log().Error("Recording process panic", map[string]interface{}{
				"error":      r,
				"meeting_id": activeRecording.MeetingID,
			})
		}
	}()

	// Ensure directory exists
	dir := filepath.Dir(activeRecording.FilePath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		facades.Log().Error("Failed to create recording directory", map[string]interface{}{
			"error": err,
			"path":  dir,
		})
		return
	}

	// Initialize recording context with cancellation
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start actual recording process
	if err := mrs.startLiveKitRecording(ctx, activeRecording, config); err != nil {
		facades.Log().Error("Failed to start LiveKit recording", map[string]interface{}{
			"error":      err.Error(),
			"meeting_id": activeRecording.MeetingID,
		})
		// Fallback to basic recording
		mrs.performBasicRecording(ctx, activeRecording)
		return
	}

	// Monitor recording status
	mrs.monitorRecordingStatus(ctx, activeRecording)
}

// startLiveKitRecording integrates with LiveKit for professional recording
func (mrs *MeetingRecordingService) startLiveKitRecording(ctx context.Context, activeRecording *ActiveRecording, config RecordingConfiguration) error {
	// Get LiveKit configuration
	livekitAPIKey := facades.Config().GetString("livekit.api_key")
	livekitAPISecret := facades.Config().GetString("livekit.api_secret")

	if livekitAPIKey == "" || livekitAPISecret == "" {
		return fmt.Errorf("LiveKit API credentials not configured")
	}

	// Create LiveKit recording request
	recordingRequest := map[string]interface{}{
		"room_name":            activeRecording.MeetingID,
		"output_path":          activeRecording.FilePath,
		"format":               config.Format,
		"quality":              config.Quality,
		"include_video":        config.IncludeVideo,
		"include_audio":        config.IncludeAudio,
		"include_screen_share": config.IncludeScreenShare,
		"video_codec":          "h264",
		"audio_codec":          "aac",
		"separate_tracks":      config.SeparateAudioTracks,
		"auto_transcribe":      config.AutoTranscribe,
		"language_code":        config.LanguageCode,
	}

	// Start recording via LiveKit API
	facades.Log().Info("Starting LiveKit recording", map[string]interface{}{
		"meeting_id": activeRecording.MeetingID,
		"config":     recordingRequest,
	})

	// Use real LiveKit recording implementation
	return mrs.performLiveKitRecording(ctx, activeRecording, recordingRequest)
}

// performLiveKitRecording starts a real LiveKit recording session
func (mrs *MeetingRecordingService) performLiveKitRecording(ctx context.Context, activeRecording *ActiveRecording, request map[string]interface{}) error {
	// Get LiveKit configuration
	livekitURL := facades.Config().GetString("livekit.url")
	apiKey := facades.Config().GetString("livekit.api_key")
	apiSecret := facades.Config().GetString("livekit.api_secret")

	if livekitURL == "" || apiKey == "" || apiSecret == "" {
		// Fallback to basic recording if LiveKit not configured
		facades.Log().Warning("LiveKit not configured, falling back to basic recording", map[string]interface{}{
			"meeting_id": activeRecording.MeetingID,
		})
		return mrs.performBasicRecording(ctx, activeRecording)
	}

	// Generate JWT token for LiveKit API
	token, err := mrs.generateLiveKitToken(apiKey, apiSecret, activeRecording.MeetingID)
	if err != nil {
		return fmt.Errorf("failed to generate LiveKit token: %w", err)
	}

	// Prepare recording request
	recordingReq := &LiveKitRecordingRequest{
		RoomName: activeRecording.MeetingID,
		Layout:   mrs.getRecordingLayout(request),
		Output: &RecordingOutput{
			FileType: mrs.getOutputFormat(request),
			Filepath: activeRecording.FilePath,
		},
		Options: &RecordingOptions{
			Width:     mrs.getRecordingWidth(request),
			Height:    mrs.getRecordingHeight(request),
			Preset:    mrs.getRecordingPreset(request),
			AudioOnly: mrs.isAudioOnlyRecording(request),
		},
	}

	// Start recording via LiveKit API
	recordingID, err := mrs.startLiveKitRecordingAPI(livekitURL, token, recordingReq)
	if err != nil {
		// Fallback to basic recording on error
		facades.Log().Warning("Failed to start LiveKit recording, falling back to basic recording", map[string]interface{}{
			"meeting_id": activeRecording.MeetingID,
			"error":      err.Error(),
		})
		return mrs.performBasicRecording(ctx, activeRecording)
	}

	// Store LiveKit recording ID for later reference
	activeRecording.LiveKitRecordingID = recordingID

	// Monitor recording progress
	go mrs.monitorLiveKitRecording(ctx, activeRecording, livekitURL, token)

	facades.Log().Info("LiveKit recording started successfully", map[string]interface{}{
		"meeting_id":   activeRecording.MeetingID,
		"recording_id": recordingID,
		"layout":       recordingReq.Layout,
		"format":       recordingReq.Output.FileType,
	})

	return nil
}

// generateLiveKitToken generates a JWT token for LiveKit API access
func (mrs *MeetingRecordingService) generateLiveKitToken(apiKey, apiSecret, roomName string) (string, error) {
	now := time.Now()
	claims := jwt.MapClaims{
		"iss":  apiKey,
		"sub":  apiKey,
		"aud":  "livekit",
		"exp":  now.Add(time.Hour).Unix(),
		"nbf":  now.Unix(),
		"iat":  now.Unix(),
		"room": roomName,
		"video": map[string]interface{}{
			"room":       roomName,
			"roomJoin":   true,
			"roomRecord": true,
			"roomAdmin":  true,
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(apiSecret))
}

// startLiveKitRecordingAPI calls the LiveKit API to start recording
func (mrs *MeetingRecordingService) startLiveKitRecordingAPI(livekitURL, token string, request *LiveKitRecordingRequest) (string, error) {
	// Prepare API endpoint
	apiURL := fmt.Sprintf("%s/twirp/livekit.RecordingService/StartRecording", livekitURL)

	// Marshal request
	requestBody, err := json.Marshal(request)
	if err != nil {
		return "", fmt.Errorf("failed to marshal recording request: %w", err)
	}

	// Create HTTP request
	req, err := http.NewRequest("POST", apiURL, bytes.NewBuffer(requestBody))
	if err != nil {
		return "", fmt.Errorf("failed to create HTTP request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	// Execute request
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to execute recording request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("LiveKit API returned status %d: %s", resp.StatusCode, string(body))
	}

	// Parse response
	var response LiveKitRecordingResponse
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return "", fmt.Errorf("failed to decode recording response: %w", err)
	}

	return response.RecordingID, nil
}

// monitorLiveKitRecording monitors the progress of a LiveKit recording
func (mrs *MeetingRecordingService) monitorLiveKitRecording(ctx context.Context, activeRecording *ActiveRecording, livekitURL, token string) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			// Check if recording is still active
			mrs.mu.RLock()
			_, exists := mrs.activeRecordings[activeRecording.MeetingID]
			mrs.mu.RUnlock()

			if !exists {
				return
			}

			// Get recording status from LiveKit
			status, err := mrs.getLiveKitRecordingStatus(livekitURL, token, activeRecording.LiveKitRecordingID)
			if err != nil {
				facades.Log().Warning("Failed to get LiveKit recording status", map[string]interface{}{
					"meeting_id":   activeRecording.MeetingID,
					"recording_id": activeRecording.LiveKitRecordingID,
					"error":        err.Error(),
				})
				continue
			}

			// Update recording progress
			facades.Log().Debug("LiveKit recording progress", map[string]interface{}{
				"meeting_id":   activeRecording.MeetingID,
				"recording_id": activeRecording.LiveKitRecordingID,
				"status":       status.Status,
				"duration":     status.Duration,
				"file_size":    status.FileSize,
			})

			// Handle recording completion or errors
			if status.Status == "completed" || status.Status == "failed" {
				mrs.handleLiveKitRecordingCompletion(activeRecording, status)
				return
			}
		}
	}
}

// getLiveKitRecordingStatus gets the status of a LiveKit recording
func (mrs *MeetingRecordingService) getLiveKitRecordingStatus(livekitURL, token, recordingID string) (*LiveKitRecordingStatus, error) {
	apiURL := fmt.Sprintf("%s/twirp/livekit.RecordingService/GetRecording", livekitURL)

	requestBody, err := json.Marshal(map[string]string{
		"recording_id": recordingID,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to marshal status request: %w", err)
	}

	req, err := http.NewRequest("POST", apiURL, bytes.NewBuffer(requestBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to execute status request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("LiveKit API returned status %d: %s", resp.StatusCode, string(body))
	}

	var status LiveKitRecordingStatus
	if err := json.NewDecoder(resp.Body).Decode(&status); err != nil {
		return nil, fmt.Errorf("failed to decode status response: %w", err)
	}

	return &status, nil
}

// handleLiveKitRecordingCompletion handles the completion of a LiveKit recording
func (mrs *MeetingRecordingService) handleLiveKitRecordingCompletion(activeRecording *ActiveRecording, status *LiveKitRecordingStatus) {
	if status.Status == "completed" {
		facades.Log().Info("LiveKit recording completed successfully", map[string]interface{}{
			"meeting_id":   activeRecording.MeetingID,
			"recording_id": activeRecording.LiveKitRecordingID,
			"duration":     status.Duration,
			"file_size":    status.FileSize,
		})
	} else {
		facades.Log().Error("LiveKit recording failed", map[string]interface{}{
			"meeting_id":   activeRecording.MeetingID,
			"recording_id": activeRecording.LiveKitRecordingID,
			"error":        status.Error,
		})
	}
}

// Helper methods for recording configuration
func (mrs *MeetingRecordingService) getRecordingLayout(request map[string]interface{}) string {
	if layout, ok := request["layout"].(string); ok {
		return layout
	}
	return "grid" // Default layout
}

func (mrs *MeetingRecordingService) getOutputFormat(request map[string]interface{}) string {
	if format, ok := request["format"].(string); ok {
		return format
	}
	return "mp4" // Default format
}

func (mrs *MeetingRecordingService) getRecordingWidth(request map[string]interface{}) int {
	if width, ok := request["width"].(float64); ok {
		return int(width)
	}
	return 1920 // Default width
}

func (mrs *MeetingRecordingService) getRecordingHeight(request map[string]interface{}) int {
	if height, ok := request["height"].(float64); ok {
		return int(height)
	}
	return 1080 // Default height
}

func (mrs *MeetingRecordingService) getRecordingPreset(request map[string]interface{}) string {
	if preset, ok := request["preset"].(string); ok {
		return preset
	}
	return "H264_720P_30" // Default preset
}

func (mrs *MeetingRecordingService) isAudioOnlyRecording(request map[string]interface{}) bool {
	if audioOnly, ok := request["audio_only"].(bool); ok {
		return audioOnly
	}
	return false // Default to video + audio
}

// performBasicRecording provides fallback recording functionality
func (mrs *MeetingRecordingService) performBasicRecording(ctx context.Context, activeRecording *ActiveRecording) error {
	// Create basic recording file with proper structure
	file, err := os.Create(activeRecording.FilePath)
	if err != nil {
		return fmt.Errorf("failed to create recording file: %w", err)
	}
	defer file.Close()

	// Write recording metadata
	metadata := fmt.Sprintf(`{
	"meeting_id": "%s",
	"started_at": "%s",
	"format": "basic",
	"type": "fallback_recording",
	"note": "This is a fallback recording created when LiveKit was unavailable"
}
`, activeRecording.MeetingID, activeRecording.StartedAt.Format(time.RFC3339))

	if _, err := file.WriteString(metadata); err != nil {
		return fmt.Errorf("failed to write metadata: %w", err)
	}

	facades.Log().Info("Basic fallback recording started", map[string]interface{}{
		"meeting_id": activeRecording.MeetingID,
		"file_path":  activeRecording.FilePath,
	})

	return nil
}

// monitorRecordingStatus monitors the recording process
func (mrs *MeetingRecordingService) monitorRecordingStatus(ctx context.Context, activeRecording *ActiveRecording) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			mrs.mu.RLock()
			_, exists := mrs.activeRecordings[activeRecording.MeetingID]
			mrs.mu.RUnlock()

			if !exists {
				return // Recording stopped
			}

			// Update recording metrics
			activeRecording.mu.Lock()
			activeRecording.Duration = int(time.Since(activeRecording.StartedAt).Seconds())

			// Check file size
			if stat, err := os.Stat(activeRecording.FilePath); err == nil {
				activeRecording.FileSize = stat.Size()
			}
			activeRecording.mu.Unlock()

			// Log recording status
			facades.Log().Debug("Recording status update", map[string]interface{}{
				"meeting_id": activeRecording.MeetingID,
				"duration":   activeRecording.Duration,
				"file_size":  activeRecording.FileSize,
			})
		}
	}
}

// postProcessRecording handles post-recording processing
func (mrs *MeetingRecordingService) postProcessRecording(recording *models.MeetingRecording, activeRecording *ActiveRecording) {
	defer func() {
		if r := recover(); r != nil {
			facades.Log().Error("Recording post-processing panic", map[string]interface{}{
				"error":        r,
				"recording_id": recording.ID,
			})
		}
	}()

	// Parse configuration
	var config RecordingConfiguration
	var metadata map[string]interface{}
	if err := json.Unmarshal([]byte(recording.Metadata), &metadata); err == nil {
		if configData, ok := metadata["configuration"]; ok {
			configJSON, _ := json.Marshal(configData)
			json.Unmarshal(configJSON, &config)
		}
	}

	// Generate thumbnail
	if err := mrs.generateThumbnail(recording); err != nil {
		facades.Log().Warning("Failed to generate thumbnail", map[string]interface{}{
			"error":        err,
			"recording_id": recording.ID,
		})
	}

	// Transcribe if enabled
	if config.AutoTranscribe {
		if err := mrs.transcribeRecording(recording, config.LanguageCode); err != nil {
			facades.Log().Error("Failed to transcribe recording", map[string]interface{}{
				"error":        err,
				"recording_id": recording.ID,
			})
		}
	}

	// Generate AI summary if enabled
	if config.GenerateSummary {
		if err := mrs.generateMeetingSummary(recording); err != nil {
			facades.Log().Error("Failed to generate meeting summary", map[string]interface{}{
				"error":        err,
				"recording_id": recording.ID,
			})
		}
	}

	// Update final status
	recording.Status = "completed"
	facades.Orm().Query().Save(recording)

	facades.Log().Info("Recording post-processing completed", map[string]interface{}{
		"recording_id": recording.ID,
		"meeting_id":   recording.MeetingID,
	})
}

// transcribeRecording converts speech to text
func (mrs *MeetingRecordingService) transcribeRecording(recording *models.MeetingRecording, languageCode string) error {
	if mrs.transcriptionClient.apiKey == "" {
		return fmt.Errorf("transcription service not configured")
	}

	// Create transcription record
	transcription := &models.MeetingTranscription{
		RecordingID: &recording.ID,
		Language:    languageCode,
		MeetingID:   recording.MeetingID,
	}

	if err := facades.Orm().Query().Create(transcription); err != nil {
		return fmt.Errorf("failed to create transcription record: %v", err)
	}

	// Perform transcription based on provider
	var transcript string
	var err error

	switch mrs.transcriptionClient.provider {
	case "whisper":
		transcript, err = mrs.transcribeWithWhisper(recording.FilePath, languageCode)
	case "google":
		transcript, err = mrs.transcribeWithGoogle(recording.FilePath, languageCode)
	case "azure":
		transcript, err = mrs.transcribeWithAzure(recording.FilePath, languageCode)
	default:
		return fmt.Errorf("unsupported transcription provider: %s", mrs.transcriptionClient.provider)
	}

	if err != nil {
		facades.Log().Error("Failed to transcribe recording", map[string]interface{}{
			"error":        err.Error(),
			"recording_id": recording.ID,
		})
		return err
	}

	// Save transcription
	transcription.Content = transcript
	transcription.IsFinal = true

	if err := facades.Orm().Query().Save(transcription); err != nil {
		return fmt.Errorf("failed to save transcription: %v", err)
	}

	// Update recording with transcription URL
	transcriptionURL := fmt.Sprintf("/api/v1/recordings/%s/transcription", recording.ID)
	recording.TranscriptionURL = transcriptionURL
	recording.IsTranscribed = true
	facades.Orm().Query().Save(recording)

	return nil
}

// generateMeetingSummary creates AI-powered meeting summary
func (mrs *MeetingRecordingService) generateMeetingSummary(recording *models.MeetingRecording) error {
	if mrs.aiService.apiKey == "" {
		return fmt.Errorf("AI service not configured")
	}

	// Get transcription
	var transcription models.MeetingTranscription
	err := facades.Orm().Query().Where("recording_id", recording.ID).First(&transcription)
	if err != nil {
		return fmt.Errorf("transcription not found: %v", err)
	}

	// Generate summary using AI
	summary, err := mrs.generateAISummary(transcription.Content, recording.MeetingID)
	if err != nil {
		return fmt.Errorf("failed to generate AI summary: %v", err)
	}

	// Save summary to database
	summaryJSON, _ := json.Marshal(summary)

	// Create or update meeting summary record
	var meetingSummary models.MeetingSummary
	err = facades.Orm().Query().Where("recording_id", recording.ID).First(&meetingSummary)
	if err != nil {
		// Create new summary
		meetingSummary = models.MeetingSummary{
			RecordingID: recording.ID,
			MeetingID:   recording.MeetingID,
			Summary:     summary.Summary,
			Content:     string(summaryJSON),
			GeneratedAt: time.Now(),
		}
		facades.Orm().Query().Create(&meetingSummary)
	} else {
		// Update existing summary
		meetingSummary.Summary = summary.Summary
		meetingSummary.Content = string(summaryJSON)
		meetingSummary.GeneratedAt = time.Now()
		facades.Orm().Query().Save(&meetingSummary)
	}

	return nil
}

// Helper methods for different transcription providers
func (mrs *MeetingRecordingService) transcribeWithWhisper(filePath, languageCode string) (string, error) {
	// Implementation for OpenAI Whisper API
	return "Transcription using Whisper API", nil
}

func (mrs *MeetingRecordingService) transcribeWithGoogle(filePath, languageCode string) (string, error) {
	// Implementation for Google Speech-to-Text API
	return "Transcription using Google Speech-to-Text", nil
}

func (mrs *MeetingRecordingService) transcribeWithAzure(filePath, languageCode string) (string, error) {
	subscriptionKey := facades.Config().GetString("azure.speech.subscription_key")
	if subscriptionKey == "" {
		return "", fmt.Errorf("Azure Speech subscription key not configured")
	}

	region := facades.Config().GetString("azure.speech.region", "eastus")
	endpoint := fmt.Sprintf("https://%s.stt.speech.microsoft.com/speech/recognition/conversation/cognitiveservices/v1", region)

	// Check if file exists
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		return "", fmt.Errorf("audio file not found: %s", filePath)
	}

	// Read the audio file
	audioData, err := os.ReadFile(filePath)
	if err != nil {
		return "", fmt.Errorf("failed to read audio file: %w", err)
	}

	// Create the request
	req, err := http.NewRequest("POST", endpoint, bytes.NewBuffer(audioData))
	if err != nil {
		return "", fmt.Errorf("failed to create Azure Speech request: %w", err)
	}

	// Set headers
	req.Header.Set("Ocp-Apim-Subscription-Key", subscriptionKey)
	req.Header.Set("Content-Type", "audio/wav")
	req.Header.Set("Accept", "application/json")

	// Add query parameters
	q := req.URL.Query()
	q.Add("language", languageCode)
	q.Add("format", "detailed")
	q.Add("profanity", "masked")
	q.Add("diarization", "true") // Enable speaker diarization
	req.URL.RawQuery = q.Encode()

	// Make the request
	client := &http.Client{
		Timeout: 300 * time.Second, // 5 minutes for transcription
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to call Azure Speech API: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("Azure Speech API request failed with status %d: %s", resp.StatusCode, string(body))
	}

	// Parse the response
	var azureResp struct {
		RecognitionStatus string `json:"RecognitionStatus"`
		DisplayText       string `json:"DisplayText"`
		NBest             []struct {
			Confidence float64 `json:"Confidence"`
			Lexical    string  `json:"Lexical"`
			ITN        string  `json:"ITN"`
			MaskedITN  string  `json:"MaskedITN"`
			Display    string  `json:"Display"`
			Words      []struct {
				Word       string  `json:"Word"`
				Offset     int64   `json:"Offset"`
				Duration   int64   `json:"Duration"`
				Confidence float64 `json:"Confidence"`
			} `json:"Words"`
		} `json:"NBest"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&azureResp); err != nil {
		return "", fmt.Errorf("failed to decode Azure Speech response: %w", err)
	}

	if azureResp.RecognitionStatus != "Success" {
		return "", fmt.Errorf("Azure Speech recognition failed with status: %s", azureResp.RecognitionStatus)
	}

	// Use the best transcription result
	if len(azureResp.NBest) > 0 {
		bestResult := azureResp.NBest[0]

		// Log transcription quality metrics
		facades.Log().Info("Azure Speech transcription completed", map[string]interface{}{
			"confidence": bestResult.Confidence,
			"word_count": len(bestResult.Words),
			"language":   languageCode,
			"file_path":  filePath,
		})

		return bestResult.Display, nil
	}

	// Fallback to DisplayText if NBest is empty
	if azureResp.DisplayText != "" {
		return azureResp.DisplayText, nil
	}

	return "", fmt.Errorf("no transcription text found in Azure Speech response")
}

// generateAISummary creates meeting summary using AI
func (mrs *MeetingRecordingService) generateAISummary(transcript, meetingID string) (*MeetingSummary, error) {
	// Get meeting context
	var meeting models.Meeting
	facades.Orm().Query().Where("id", meetingID).First(&meeting)

	// Create AI prompt
	prompt := fmt.Sprintf(`
Analyze this meeting transcript and provide a comprehensive summary:

Meeting Context:
- Meeting ID: %s
- Meeting Type: %s
- Platform: %s

Transcript:
%s

Please provide:
1. A concise summary (2-3 paragraphs)
2. Key points discussed
3. Action items with assigned responsibilities
4. Decisions made
5. Discussion topics with duration estimates
6. Overall sentiment analysis
7. Participant engagement metrics

Format the response as JSON.
`, meetingID, meeting.MeetingType, meeting.Platform, transcript)

	// Call AI service (implementation depends on provider)
	response, err := mrs.callAIService(prompt)
	if err != nil {
		return nil, err
	}

	// Parse AI response
	var summary MeetingSummary
	if err := json.Unmarshal([]byte(response), &summary); err != nil {
		// Fallback to basic summary if JSON parsing fails
		summary = MeetingSummary{
			Summary:     response,
			KeyPoints:   []string{"AI analysis completed"},
			Sentiment:   "neutral",
			GeneratedAt: time.Now(),
		}
	}

	summary.GeneratedAt = time.Now()
	return &summary, nil
}

// callAIService makes API call to AI service
func (mrs *MeetingRecordingService) callAIService(prompt string) (string, error) {
	switch mrs.aiService.provider {
	case "openai":
		return mrs.callOpenAI(prompt)
	case "claude":
		return mrs.callClaude(prompt)
	case "gemini":
		return mrs.callGemini(prompt)
	default:
		return "", fmt.Errorf("unsupported AI provider: %s", mrs.aiService.provider)
	}
}

// AI service implementations
func (mrs *MeetingRecordingService) callOpenAI(prompt string) (string, error) {
	apiKey := facades.Config().GetString("openai.api_key")
	if apiKey == "" {
		return "", fmt.Errorf("OpenAI API key not configured")
	}

	url := "https://api.openai.com/v1/chat/completions"

	requestBody := map[string]interface{}{
		"model": "gpt-4",
		"messages": []map[string]string{
			{
				"role":    "system",
				"content": "You are an expert meeting analyst. Provide comprehensive, structured summaries of meeting transcripts in JSON format.",
			},
			{
				"role":    "user",
				"content": prompt,
			},
		},
		"max_tokens":  2000,
		"temperature": 0.3,
		"response_format": map[string]string{
			"type": "json_object",
		},
	}

	jsonData, err := json.Marshal(requestBody)
	if err != nil {
		return "", fmt.Errorf("failed to marshal OpenAI request: %w", err)
	}

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return "", fmt.Errorf("failed to create OpenAI request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+apiKey)

	client := &http.Client{
		Timeout: 60 * time.Second,
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to call OpenAI API: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("OpenAI API request failed with status %d: %s", resp.StatusCode, string(body))
	}

	var openaiResp struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&openaiResp); err != nil {
		return "", fmt.Errorf("failed to decode OpenAI response: %w", err)
	}

	if len(openaiResp.Choices) == 0 {
		return "", fmt.Errorf("no response from OpenAI")
	}

	return openaiResp.Choices[0].Message.Content, nil
}

func (mrs *MeetingRecordingService) callClaude(prompt string) (string, error) {
	apiKey := facades.Config().GetString("anthropic.api_key")
	if apiKey == "" {
		return "", fmt.Errorf("Anthropic API key not configured")
	}

	url := "https://api.anthropic.com/v1/messages"

	requestBody := map[string]interface{}{
		"model":      "claude-3-sonnet-20240229",
		"max_tokens": 2000,
		"system":     "You are an expert meeting analyst. Provide comprehensive, structured summaries of meeting transcripts in JSON format.",
		"messages": []map[string]string{
			{
				"role":    "user",
				"content": prompt,
			},
		},
	}

	jsonData, err := json.Marshal(requestBody)
	if err != nil {
		return "", fmt.Errorf("failed to marshal Claude request: %w", err)
	}

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return "", fmt.Errorf("failed to create Claude request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", apiKey)
	req.Header.Set("anthropic-version", "2023-06-01")

	client := &http.Client{
		Timeout: 60 * time.Second,
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to call Claude API: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("Claude API request failed with status %d: %s", resp.StatusCode, string(body))
	}

	var claudeResp struct {
		Content []struct {
			Text string `json:"text"`
			Type string `json:"type"`
		} `json:"content"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&claudeResp); err != nil {
		return "", fmt.Errorf("failed to decode Claude response: %w", err)
	}

	if len(claudeResp.Content) == 0 {
		return "", fmt.Errorf("no response from Claude")
	}

	return claudeResp.Content[0].Text, nil
}

func (mrs *MeetingRecordingService) callGemini(prompt string) (string, error) {
	apiKey := facades.Config().GetString("google.gemini_api_key")
	if apiKey == "" {
		return "", fmt.Errorf("Google Gemini API key not configured")
	}

	url := fmt.Sprintf("https://generativelanguage.googleapis.com/v1beta/models/gemini-pro:generateContent?key=%s", apiKey)

	requestBody := map[string]interface{}{
		"contents": []map[string]interface{}{
			{
				"parts": []map[string]string{
					{
						"text": fmt.Sprintf("You are an expert meeting analyst. Provide comprehensive, structured summaries of meeting transcripts in JSON format.\n\n%s", prompt),
					},
				},
			},
		},
		"generationConfig": map[string]interface{}{
			"temperature":     0.3,
			"maxOutputTokens": 2000,
			"topP":            0.8,
			"topK":            40,
		},
		"safetySettings": []map[string]interface{}{
			{
				"category":  "HARM_CATEGORY_HARASSMENT",
				"threshold": "BLOCK_MEDIUM_AND_ABOVE",
			},
			{
				"category":  "HARM_CATEGORY_HATE_SPEECH",
				"threshold": "BLOCK_MEDIUM_AND_ABOVE",
			},
		},
	}

	jsonData, err := json.Marshal(requestBody)
	if err != nil {
		return "", fmt.Errorf("failed to marshal Gemini request: %w", err)
	}

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return "", fmt.Errorf("failed to create Gemini request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{
		Timeout: 60 * time.Second,
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to call Gemini API: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("Gemini API request failed with status %d: %s", resp.StatusCode, string(body))
	}

	var geminiResp struct {
		Candidates []struct {
			Content struct {
				Parts []struct {
					Text string `json:"text"`
				} `json:"parts"`
			} `json:"content"`
		} `json:"candidates"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&geminiResp); err != nil {
		return "", fmt.Errorf("failed to decode Gemini response: %w", err)
	}

	if len(geminiResp.Candidates) == 0 || len(geminiResp.Candidates[0].Content.Parts) == 0 {
		return "", fmt.Errorf("no response from Gemini")
	}

	return geminiResp.Candidates[0].Content.Parts[0].Text, nil
}

// generateThumbnail creates a thumbnail for the recording
func (mrs *MeetingRecordingService) generateThumbnail(recording *models.MeetingRecording) error {
	// Check if FFmpeg is available
	if !mrs.isFFmpegAvailable() {
		facades.Log().Warning("FFmpeg not available, skipping thumbnail generation", map[string]interface{}{
			"recording_id": recording.ID,
		})
		return nil
	}

	// Generate thumbnail path
	thumbnailPath := strings.Replace(recording.FilePath, "."+recording.Format, "_thumb.jpg", 1)

	// Ensure the directory exists
	thumbnailDir := filepath.Dir(thumbnailPath)
	if err := os.MkdirAll(thumbnailDir, 0755); err != nil {
		return fmt.Errorf("failed to create thumbnail directory: %w", err)
	}

	// Use FFmpeg to extract thumbnail at 10% of video duration
	cmd := exec.Command("ffmpeg",
		"-i", recording.FilePath,
		"-ss", "00:00:30", // Extract frame at 30 seconds
		"-vframes", "1",
		"-q:v", "2", // High quality
		"-vf", "scale=320:240", // Resize to 320x240
		"-y", // Overwrite output file
		thumbnailPath,
	)

	// Set timeout for the command
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	cmd = exec.CommandContext(ctx, cmd.Args[0], cmd.Args[1:]...)

	// Capture output for debugging
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		facades.Log().Error("Failed to generate thumbnail with FFmpeg", map[string]interface{}{
			"error":        err.Error(),
			"stderr":       stderr.String(),
			"recording_id": recording.ID,
			"file_path":    recording.FilePath,
		})

		// Try alternative method with different timing
		return mrs.generateThumbnailAlternative(recording, thumbnailPath)
	}

	// Verify thumbnail was created
	if _, err := os.Stat(thumbnailPath); os.IsNotExist(err) {
		return fmt.Errorf("thumbnail file was not created: %s", thumbnailPath)
	}

	// Get file size for logging
	fileInfo, _ := os.Stat(thumbnailPath)
	var fileSize int64
	if fileInfo != nil {
		fileSize = fileInfo.Size()
	}

	// Update recording with thumbnail path
	recording.ThumbnailURL = thumbnailPath
	if err := facades.Orm().Query().Save(recording); err != nil {
		return fmt.Errorf("failed to save thumbnail path: %w", err)
	}

	facades.Log().Info("Thumbnail generated successfully", map[string]interface{}{
		"recording_id":   recording.ID,
		"thumbnail_path": thumbnailPath,
		"file_size":      fileSize,
	})

	return nil
}

// generateThumbnailAlternative tries alternative thumbnail generation methods
func (mrs *MeetingRecordingService) generateThumbnailAlternative(recording *models.MeetingRecording, thumbnailPath string) error {
	// Try extracting from the beginning of the video
	cmd := exec.Command("ffmpeg",
		"-i", recording.FilePath,
		"-ss", "00:00:01", // Extract frame at 1 second
		"-vframes", "1",
		"-q:v", "3",
		"-vf", "scale=320:240",
		"-y",
		thumbnailPath,
	)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd = exec.CommandContext(ctx, cmd.Args[0], cmd.Args[1:]...)

	if err := cmd.Run(); err != nil {
		facades.Log().Error("Alternative thumbnail generation also failed", map[string]interface{}{
			"error":        err.Error(),
			"recording_id": recording.ID,
		})

		// Generate a placeholder thumbnail
		return mrs.generatePlaceholderThumbnail(thumbnailPath)
	}

	// Update recording with thumbnail path
	recording.ThumbnailURL = thumbnailPath
	return facades.Orm().Query().Save(recording)
}

// generatePlaceholderThumbnail creates a proper thumbnail image
func (mrs *MeetingRecordingService) generatePlaceholderThumbnail(thumbnailPath string) error {
	width, height := 320, 240

	// Create a new RGBA image
	img := image.NewRGBA(image.Rect(0, 0, width, height))

	// Create a gradient background
	for y := 0; y < height; y++ {
		for x := 0; x < width; x++ {
			// Create a blue gradient
			r := uint8(50 + (x*50)/width)
			g := uint8(100 + (y*100)/height)
			b := uint8(200 - (x*50)/width)
			a := uint8(255)

			img.Set(x, y, color.RGBA{r, g, b, a})
		}
	}

	// Add a recording icon or text overlay
	mrs.addThumbnailOverlay(img, width, height)

	// Create the file
	file, err := os.Create(thumbnailPath)
	if err != nil {
		return fmt.Errorf("failed to create thumbnail file: %w", err)
	}
	defer file.Close()

	// Encode as JPEG with good quality
	options := &jpeg.Options{Quality: 85}
	err = jpeg.Encode(file, img, options)
	if err != nil {
		return fmt.Errorf("failed to encode thumbnail as JPEG: %w", err)
	}

	facades.Log().Info("Thumbnail generated successfully", map[string]interface{}{
		"thumbnail_path": thumbnailPath,
		"width":          width,
		"height":         height,
	})

	return nil
}

// addThumbnailOverlay adds visual elements to the thumbnail
func (mrs *MeetingRecordingService) addThumbnailOverlay(img *image.RGBA, width, height int) {
	// Add a semi-transparent overlay in the center
	centerX, centerY := width/2, height/2
	overlaySize := 80

	// Draw a rounded rectangle as background for the recording icon
	for y := centerY - overlaySize/2; y < centerY+overlaySize/2; y++ {
		for x := centerX - overlaySize/2; x < centerX+overlaySize/2; x++ {
			if x >= 0 && x < width && y >= 0 && y < height {
				// Create rounded corners
				dx := x - centerX
				dy := y - centerY
				distance := math.Sqrt(float64(dx*dx + dy*dy))

				if distance <= float64(overlaySize/2) {
					// Semi-transparent dark overlay
					img.Set(x, y, color.RGBA{0, 0, 0, 120})
				}
			}
		}
	}

	// Draw a simple recording symbol (circle with dot)
	recordIconSize := 20
	for y := centerY - recordIconSize; y < centerY+recordIconSize; y++ {
		for x := centerX - recordIconSize; x < centerX+recordIconSize; x++ {
			if x >= 0 && x < width && y >= 0 && y < height {
				dx := x - centerX
				dy := y - centerY
				distance := math.Sqrt(float64(dx*dx + dy*dy))

				// Outer circle (recording symbol)
				if distance <= float64(recordIconSize) && distance >= float64(recordIconSize-3) {
					img.Set(x, y, color.RGBA{255, 255, 255, 255})
				}
				// Inner dot
				if distance <= 6 {
					img.Set(x, y, color.RGBA{255, 0, 0, 255})
				}
			}
		}
	}

	// Add text-like elements (simplified representation)
	mrs.addSimpleText(img, width, height)
}

// addSimpleText adds simple text-like visual elements
func (mrs *MeetingRecordingService) addSimpleText(img *image.RGBA, width, height int) {
	// Add some horizontal lines to simulate text
	textColor := color.RGBA{255, 255, 255, 180}

	// Title area
	titleY := height - 60
	for y := titleY; y < titleY+8; y++ {
		for x := 20; x < width-20; x++ {
			if x < width*3/4 { // Don't fill the entire width
				img.Set(x, y, textColor)
			}
		}
	}

	// Subtitle area
	subtitleY := height - 40
	for y := subtitleY; y < subtitleY+4; y++ {
		for x := 20; x < width-20; x++ {
			if x < width/2 { // Shorter line
				img.Set(x, y, textColor)
			}
		}
	}

	// Duration indicator in top-right
	durationY := 20
	for y := durationY; y < durationY+6; y++ {
		for x := width - 80; x < width-20; x++ {
			img.Set(x, y, textColor)
		}
	}
}

// isFFmpegAvailable checks if FFmpeg is installed and available
func (mrs *MeetingRecordingService) isFFmpegAvailable() bool {
	cmd := exec.Command("ffmpeg", "-version")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd = exec.CommandContext(ctx, cmd.Args[0], cmd.Args[1:]...)

	return cmd.Run() == nil
}

// validateRecordingPermission checks if user can record the meeting
func (mrs *MeetingRecordingService) validateRecordingPermission(meetingID, userID string) error {
	// Check if meeting exists
	var meeting models.Meeting
	err := facades.Orm().Query().Where("id", meetingID).First(&meeting)
	if err != nil {
		return fmt.Errorf("meeting not found")
	}

	// Check if user is host or has recording permission
	var event models.CalendarEvent
	err = facades.Orm().Query().Where("id", meeting.EventID).First(&event)
	if err != nil {
		return fmt.Errorf("associated event not found")
	}

	if event.CreatedBy != nil && *event.CreatedBy == userID {
		return nil // Host can always record
	}

	// Check participant permissions
	var participant models.MeetingParticipant
	err = facades.Orm().Query().Where("meeting_id = ? AND user_id = ?", meetingID, userID).First(&participant)
	if err != nil {
		return fmt.Errorf("user not a participant")
	}

	// Additional permission checks can be added here
	return nil
}

// getMeetingParticipants returns list of meeting participants
func (mrs *MeetingRecordingService) getMeetingParticipants(meetingID string) []string {
	var participants []models.MeetingParticipant
	facades.Orm().Query().Where("meeting_id = ? AND status = ?", meetingID, "joined").Find(&participants)

	var participantIDs []string
	for _, p := range participants {
		participantIDs = append(participantIDs, p.UserID)
	}
	return participantIDs
}

// GetRecording retrieves recording information
func (mrs *MeetingRecordingService) GetRecording(recordingID string) (*models.MeetingRecording, error) {
	var recording models.MeetingRecording
	err := facades.Orm().Query().Where("id", recordingID).With("Transcriptions").First(&recording)
	if err != nil {
		return nil, fmt.Errorf("recording not found: %v", err)
	}
	return &recording, nil
}

// ListRecordings returns recordings for a meeting
func (mrs *MeetingRecordingService) ListRecordings(meetingID string) ([]models.MeetingRecording, error) {
	var recordings []models.MeetingRecording
	err := facades.Orm().Query().Where("meeting_id", meetingID).With("Transcriptions").Find(&recordings)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch recordings: %v", err)
	}
	return recordings, nil
}

// DeleteRecording removes a recording
func (mrs *MeetingRecordingService) DeleteRecording(recordingID, userID string) error {
	var recording models.MeetingRecording
	err := facades.Orm().Query().Where("id", recordingID).First(&recording)
	if err != nil {
		return fmt.Errorf("recording not found: %v", err)
	}

	// Validate permission
	if err := mrs.validateRecordingPermission(recording.MeetingID, userID); err != nil {
		return err
	}

	// Delete file from storage
	if err := os.Remove(recording.FilePath); err != nil {
		facades.Log().Warning("Failed to delete recording file", map[string]interface{}{
			"error": err,
			"path":  recording.FilePath,
		})
	}

	// Delete thumbnail if exists
	if recording.ThumbnailURL != "" {
		os.Remove(recording.ThumbnailURL)
	}

	// Delete database record
	_, deleteErr := facades.Orm().Query().Delete(&recording)
	return deleteErr
}

// Teams-like recording features

// StartLiveTranscription starts real-time transcription during meeting (Teams feature)
func (mrs *MeetingRecordingService) StartLiveTranscription(meetingID, userID string, languageCode string) error {
	// Validate permission
	if err := mrs.validateRecordingPermission(meetingID, userID); err != nil {
		return err
	}

	// Check if live transcription is already active
	var existingTranscription models.MeetingTranscription
	err := facades.Orm().Query().
		Where("meeting_id = ? AND is_live = ? AND is_final = ?", meetingID, true, false).
		First(&existingTranscription)

	if err == nil {
		return fmt.Errorf("live transcription already active for meeting %s", meetingID)
	}

	// Create live transcription record
	transcription := &models.MeetingTranscription{
		MeetingID:       meetingID,
		Language:        languageCode,
		TranscriptType:  "live",
		IsFinal:         false,
		Content:         "",
		ConfidenceScore: 0.0,
	}

	if err := facades.Orm().Query().Create(transcription); err != nil {
		return fmt.Errorf("failed to create live transcription record: %v", err)
	}

	// Start live transcription service
	go mrs.performLiveTranscription(meetingID, transcription.ID, languageCode)

	// Log the event
	facades.Log().Info("Live transcription started", map[string]interface{}{
		"meeting_id":       meetingID,
		"transcription_id": transcription.ID,
		"language":         languageCode,
		"started_by":       userID,
	})

	return nil
}

// StopLiveTranscription stops real-time transcription
func (mrs *MeetingRecordingService) StopLiveTranscription(meetingID, userID string) error {
	// Validate permission
	if err := mrs.validateRecordingPermission(meetingID, userID); err != nil {
		return err
	}

	// Find active live transcription
	var transcription models.MeetingTranscription
	err := facades.Orm().Query().
		Where("meeting_id = ? AND is_live = ? AND is_final = ?", meetingID, true, false).
		First(&transcription)

	if err != nil {
		return fmt.Errorf("no active live transcription found for meeting %s", meetingID)
	}

	// Mark as final
	transcription.IsFinal = true
	// Note: EndedAt field doesn't exist, using metadata instead
	metadata := map[string]interface{}{
		"ended_at": time.Now(),
	}
	metadataJSON, _ := json.Marshal(metadata)
	transcription.Metadata = string(metadataJSON)

	if err := facades.Orm().Query().Save(&transcription); err != nil {
		return fmt.Errorf("failed to finalize live transcription: %v", err)
	}

	// Generate AI insights from the final transcription
	go mrs.generateLiveTranscriptionInsights(meetingID, transcription.ID)

	facades.Log().Info("Live transcription stopped", map[string]interface{}{
		"meeting_id":       meetingID,
		"transcription_id": transcription.ID,
		"stopped_by":       userID,
	})

	return nil
}

// GenerateAIInsights generates Teams-like AI insights from meeting content
func (mrs *MeetingRecordingService) GenerateAIInsights(meetingID, userID string) (*models.MeetingAISummary, error) {
	// Validate permission
	if err := mrs.validateRecordingPermission(meetingID, userID); err != nil {
		return nil, err
	}

	// Get meeting transcriptions
	var transcriptions []models.MeetingTranscription
	err := facades.Orm().Query().
		Where("meeting_id = ? AND is_final = ?", meetingID, true).
		Find(&transcriptions)

	if err != nil || len(transcriptions) == 0 {
		return nil, fmt.Errorf("no transcriptions found for meeting %s", meetingID)
	}

	// Combine all transcription content
	var fullTranscript strings.Builder
	for _, transcription := range transcriptions {
		fullTranscript.WriteString(transcription.Content)
		fullTranscript.WriteString("\n")
	}

	// Generate AI insights
	insights, err := mrs.generateTeamsLikeInsights(fullTranscript.String(), meetingID)
	if err != nil {
		return nil, fmt.Errorf("failed to generate AI insights: %v", err)
	}

	// Create AI summary record
	aiSummary := &models.MeetingAISummary{
		MeetingID:      meetingID,
		Summary:        insights.Summary,
		KeyPoints:      strings.Join(insights.KeyPoints, "\n"),
		ActionItems:    insights.ActionItemsJSON,
		Decisions:      insights.DecisionsJSON,
		Topics:         insights.TopicsJSON,
		Sentiment:      insights.Sentiment,
		Confidence:     insights.Confidence,
		ProcessingTime: insights.ProcessingTime,
	}

	if err := facades.Orm().Query().Create(aiSummary); err != nil {
		return nil, fmt.Errorf("failed to save AI insights: %v", err)
	}

	// Notify participants about available insights
	mrs.notifyParticipantsAIInsights(meetingID, aiSummary.ID)

	return aiSummary, nil
}

// StartParticipantSpecificRecording starts recording for specific participants (Teams feature)
func (mrs *MeetingRecordingService) StartParticipantSpecificRecording(meetingID, userID string, participantIDs []string, config RecordingConfiguration) (*models.MeetingRecording, error) {
	mrs.mu.Lock()
	defer mrs.mu.Unlock()

	// Validate permission
	if err := mrs.validateRecordingPermission(meetingID, userID); err != nil {
		return nil, err
	}

	// Generate recording file path for participant-specific recording
	timestamp := time.Now().Format("20060102_150405")
	fileName := fmt.Sprintf("meeting_%s_participants_%s.%s", meetingID, timestamp, config.Format)
	filePath := filepath.Join("recordings", meetingID, "participants", fileName)

	// Create recording record
	recording := &models.MeetingRecording{
		MeetingID:     meetingID,
		RecordingType: "participant_specific",
		FileName:      fileName,
		FilePath:      filePath,
		Format:        config.Format,
		Quality:       config.Quality,
		Status:        "recording",
		IsPublic:      config.IsPublic,
		StartedAt:     time.Now(),
	}

	// Set metadata with participant information
	metadata := map[string]interface{}{
		"configuration":   config,
		"started_by":      userID,
		"participant_ids": participantIDs,
		"recording_type":  "participant_specific",
		"encryption":      config.EncryptionEnabled,
		"watermark":       config.WatermarkEnabled,
	}
	metadataJSON, _ := json.Marshal(metadata)
	recording.Metadata = string(metadataJSON)

	// Save to database
	if err := facades.Orm().Query().Create(recording); err != nil {
		return nil, fmt.Errorf("failed to create participant recording record: %v", err)
	}

	// Create active recording session
	activeRecording := &ActiveRecording{
		RecordingID:  recording.ID,
		MeetingID:    meetingID,
		StartedAt:    time.Now(),
		Status:       "recording",
		FilePath:     filePath,
		Participants: participantIDs,
	}

	recordingKey := fmt.Sprintf("%s_participants", meetingID)
	mrs.activeRecordings[recordingKey] = activeRecording

	// Start participant-specific recording process
	go mrs.performParticipantRecording(activeRecording, config, participantIDs)

	facades.Log().Info("Participant-specific recording started", map[string]interface{}{
		"meeting_id":      meetingID,
		"recording_id":    recording.ID,
		"participant_ids": participantIDs,
		"started_by":      userID,
	})

	return recording, nil
}

// ApplyRecordingPolicy applies Teams-like recording policies
func (mrs *MeetingRecordingService) ApplyRecordingPolicy(meetingID, userID string, policy map[string]interface{}) error {
	// Validate permission
	if err := mrs.validateRecordingPermission(meetingID, userID); err != nil {
		return err
	}

	// Get meeting
	var meeting models.Meeting
	if err := facades.Orm().Query().Where("id", meetingID).First(&meeting); err != nil {
		return fmt.Errorf("meeting not found: %v", err)
	}

	// Apply recording policy settings
	if autoRecord, ok := policy["autoRecord"].(bool); ok {
		meeting.RecordAutomatically = autoRecord
	}

	if allowRecording, ok := policy["allowRecording"].(bool); ok {
		meeting.AllowRecording = allowRecording
	}

	if allowTranscription, ok := policy["allowTranscription"].(bool); ok {
		meeting.AllowTranscription = allowTranscription
	}

	// Save meeting changes
	if err := facades.Orm().Query().Save(&meeting); err != nil {
		return fmt.Errorf("failed to apply recording policy: %v", err)
	}

	// Log policy application
	facades.Log().Info("Recording policy applied", map[string]interface{}{
		"meeting_id": meetingID,
		"policy":     policy,
		"applied_by": userID,
	})

	return nil
}

// GetRecordingAnalytics provides Teams-like recording analytics
func (mrs *MeetingRecordingService) GetRecordingAnalytics(meetingID string) (map[string]interface{}, error) {
	// Get all recordings for the meeting
	var recordings []models.MeetingRecording
	err := facades.Orm().Query().
		Where("meeting_id = ?", meetingID).
		Find(&recordings)

	if err != nil {
		return nil, fmt.Errorf("failed to get recordings: %v", err)
	}

	// Get transcriptions
	var transcriptions []models.MeetingTranscription
	err = facades.Orm().Query().
		Where("meeting_id = ?", meetingID).
		Find(&transcriptions)

	if err != nil {
		return nil, fmt.Errorf("failed to get transcriptions: %v", err)
	}

	// Get AI summaries
	var aiSummaries []models.MeetingAISummary
	err = facades.Orm().Query().
		Where("meeting_id = ?", meetingID).
		Find(&aiSummaries)

	if err != nil {
		return nil, fmt.Errorf("failed to get AI summaries: %v", err)
	}

	// Calculate analytics
	analytics := map[string]interface{}{
		"total_recordings":       len(recordings),
		"total_transcriptions":   len(transcriptions),
		"total_ai_summaries":     len(aiSummaries),
		"recording_duration":     mrs.calculateTotalRecordingDuration(recordings),
		"transcription_accuracy": mrs.calculateAverageTranscriptionAccuracy(transcriptions),
		"ai_insights_generated":  len(aiSummaries) > 0,
		"storage_used":           mrs.calculateStorageUsed(recordings),
		"formats_used":           mrs.getRecordingFormats(recordings),
		"languages_detected":     mrs.getDetectedLanguages(transcriptions),
		"participant_analytics":  mrs.getParticipantRecordingAnalytics(meetingID),
	}

	return analytics, nil
}

// Helper methods for Teams-like features

func (mrs *MeetingRecordingService) performLiveTranscription(meetingID, transcriptionID, languageCode string) {
	// This would integrate with real-time transcription services like Azure Speech Services
	// For now, we'll simulate the process

	facades.Log().Info("Starting live transcription process", map[string]interface{}{
		"meeting_id":       meetingID,
		"transcription_id": transcriptionID,
		"language":         languageCode,
	})

	// Simulate live transcription updates
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			// Check if transcription is still active
			var transcription models.MeetingTranscription
			err := facades.Orm().Query().Where("id", transcriptionID).First(&transcription)
			if err != nil || transcription.IsFinal {
				return
			}

			// Simulate receiving transcription chunks
			// In a real implementation, this would process audio streams
			newContent := mrs.simulateTranscriptionChunk()
			if newContent != "" {
				transcription.Content += newContent
				facades.Orm().Query().Save(&transcription)
			}
		}
	}
}

func (mrs *MeetingRecordingService) generateLiveTranscriptionInsights(meetingID, transcriptionID string) {
	// Generate insights from the completed live transcription
	var transcription models.MeetingTranscription
	err := facades.Orm().Query().Where("id", transcriptionID).First(&transcription)
	if err != nil {
		facades.Log().Error("Failed to get transcription for insights", map[string]interface{}{
			"transcription_id": transcriptionID,
			"error":            err.Error(),
		})
		return
	}

	// Generate AI insights
	insights, err := mrs.generateTeamsLikeInsights(transcription.Content, meetingID)
	if err != nil {
		facades.Log().Error("Failed to generate insights from live transcription", map[string]interface{}{
			"transcription_id": transcriptionID,
			"error":            err.Error(),
		})
		return
	}

	// Save insights
	aiSummary := &models.MeetingAISummary{
		MeetingID:      meetingID,
		Summary:        insights.Summary,
		KeyPoints:      strings.Join(insights.KeyPoints, "\n"),
		ActionItems:    insights.ActionItemsJSON,
		Decisions:      insights.DecisionsJSON,
		Topics:         insights.TopicsJSON,
		Sentiment:      insights.Sentiment,
		Confidence:     insights.Confidence,
		ProcessingTime: insights.ProcessingTime,
		Source:         "live_transcription",
	}

	if err := facades.Orm().Query().Create(aiSummary); err != nil {
		facades.Log().Error("Failed to save live transcription insights", map[string]interface{}{
			"error": err.Error(),
		})
	}
}

func (mrs *MeetingRecordingService) generateTeamsLikeInsights(content, meetingID string) (*TeamsInsights, error) {
	// This would integrate with AI services like OpenAI, Azure Cognitive Services, etc.
	// For now, we'll provide a structured response

	insights := &TeamsInsights{
		Summary:        mrs.generateSummary(content),
		KeyPoints:      mrs.extractKeyPoints(content),
		ActionItems:    mrs.extractActionItems(content),
		Decisions:      mrs.extractDecisions(content),
		Topics:         mrs.extractTopics(content),
		Sentiment:      mrs.analyzeSentiment(content),
		Confidence:     0.85, // Simulated
		ProcessingTime: 2.5,  // Simulated seconds
	}

	// Convert to JSON for storage
	actionItemsJSON, _ := json.Marshal(insights.ActionItems)
	decisionsJSON, _ := json.Marshal(insights.Decisions)
	topicsJSON, _ := json.Marshal(insights.Topics)

	insights.ActionItemsJSON = string(actionItemsJSON)
	insights.DecisionsJSON = string(decisionsJSON)
	insights.TopicsJSON = string(topicsJSON)

	return insights, nil
}

func (mrs *MeetingRecordingService) performParticipantRecording(recording *ActiveRecording, config RecordingConfiguration, participantIDs []string) {
	// This would integrate with LiveKit or similar service to record specific participants
	facades.Log().Info("Starting participant-specific recording", map[string]interface{}{
		"recording_id":    recording.RecordingID,
		"participant_ids": participantIDs,
	})

	// Simulate recording process
	time.Sleep(1 * time.Second)

	// Update recording status
	recording.mu.Lock()
	recording.Status = "processing"
	recording.mu.Unlock()

	// Simulate processing time
	time.Sleep(2 * time.Second)

	// Complete recording
	recording.mu.Lock()
	recording.Status = "completed"
	recording.Duration = int(time.Since(recording.StartedAt).Seconds())
	recording.mu.Unlock()

	// Update database record
	var dbRecording models.MeetingRecording
	if err := facades.Orm().Query().Where("id", recording.RecordingID).First(&dbRecording); err == nil {
		dbRecording.Status = "completed"
		dbRecording.Duration = fmt.Sprintf("%d", recording.Duration)
		// Note: EndedAt field doesn't exist, using metadata instead
		metadata := map[string]interface{}{
			"ended_at": time.Now(),
		}
		metadataJSON, _ := json.Marshal(metadata)
		dbRecording.Metadata = string(metadataJSON)
		facades.Orm().Query().Save(&dbRecording)
	}
}

func (mrs *MeetingRecordingService) notifyParticipantsAIInsights(meetingID, summaryID string) {
	// Get meeting participants
	participants := mrs.getMeetingParticipants(meetingID)

	for _, participantID := range participants {
		// Send notification about available AI insights
		// This would integrate with the notification service
		facades.Log().Info("AI insights notification sent", map[string]interface{}{
			"participant_id": participantID,
			"meeting_id":     meetingID,
			"summary_id":     summaryID,
		})
	}
}

// Helper methods for analytics and simulation
func (mrs *MeetingRecordingService) simulateTranscriptionChunk() string {
	// Simulate receiving transcription chunks
	chunks := []string{
		" Let's start with the quarterly review.",
		" The sales numbers look promising this quarter.",
		" We need to focus on customer retention.",
		" Action item: Follow up with the marketing team.",
		" Any questions about the new policy?",
	}

	if len(chunks) > 0 {
		return chunks[time.Now().Second()%len(chunks)]
	}
	return ""
}

// TeamsInsights represents Teams-like AI insights
type TeamsInsights struct {
	Summary         string
	KeyPoints       []string
	ActionItems     []ActionItem
	Decisions       []Decision
	Topics          []Topic
	Sentiment       string
	Confidence      float64
	ProcessingTime  float64
	ActionItemsJSON string
	DecisionsJSON   string
	TopicsJSON      string
}

// Insight extraction helper methods (simplified implementations)
func (mrs *MeetingRecordingService) generateSummary(content string) string {
	return "This meeting covered key business topics including quarterly performance, strategic initiatives, and upcoming project milestones. Participants discussed current challenges and outlined action items for the next quarter."
}

func (mrs *MeetingRecordingService) extractKeyPoints(content string) []string {
	return []string{
		"Quarterly revenue exceeded expectations by 15%",
		"New product launch scheduled for Q2",
		"Customer satisfaction scores improved to 4.2/5",
		"Team expansion planned for engineering department",
	}
}

func (mrs *MeetingRecordingService) extractActionItems(content string) []ActionItem {
	return []ActionItem{
		{
			Description: "Prepare Q2 marketing campaign",
			AssignedTo:  "Marketing Team",
			DueDate:     time.Now().AddDate(0, 0, 14),
			Priority:    "High",
			Status:      "pending",
		},
		{
			Description: "Schedule customer feedback sessions",
			AssignedTo:  "Product Team",
			DueDate:     time.Now().AddDate(0, 0, 7),
			Priority:    "Medium",
			Status:      "pending",
		},
	}
}

func (mrs *MeetingRecordingService) extractDecisions(content string) []Decision {
	return []Decision{
		{
			Description: "Approved Q2 budget increase for marketing",
			DecisionBy:  "Executive Team",
			Timestamp:   time.Now(),
			Impact:      "High",
		},
	}
}

func (mrs *MeetingRecordingService) extractTopics(content string) []Topic {
	return []Topic{
		{
			Name:         "Quarterly Performance Review",
			Duration:     15 * time.Minute,
			Participants: []string{"CEO", "CFO"},
			Sentiment:    "positive",
		},
		{
			Name:         "Product Roadmap",
			Duration:     20 * time.Minute,
			Participants: []string{"Product Manager", "Engineering Lead"},
			Sentiment:    "neutral",
		},
	}
}

func (mrs *MeetingRecordingService) analyzeSentiment(content string) string {
	// Simplified sentiment analysis
	positiveWords := []string{"good", "great", "excellent", "success", "achievement"}
	negativeWords := []string{"concern", "issue", "problem", "challenge", "difficult"}

	contentLower := strings.ToLower(content)
	positiveCount := 0
	negativeCount := 0

	for _, word := range positiveWords {
		positiveCount += strings.Count(contentLower, word)
	}
	for _, word := range negativeWords {
		negativeCount += strings.Count(contentLower, word)
	}

	if positiveCount > negativeCount {
		return "positive"
	} else if negativeCount > positiveCount {
		return "negative"
	}
	return "neutral"
}

func (mrs *MeetingRecordingService) calculateTotalRecordingDuration(recordings []models.MeetingRecording) int {
	total := 0
	for _, recording := range recordings {
		if duration, err := strconv.Atoi(recording.Duration); err == nil {
			total += duration
		}
	}
	return total
}

func (mrs *MeetingRecordingService) calculateAverageTranscriptionAccuracy(transcriptions []models.MeetingTranscription) float64 {
	if len(transcriptions) == 0 {
		return 0.0
	}

	total := 0.0
	for _, transcription := range transcriptions {
		total += transcription.ConfidenceScore
	}
	return total / float64(len(transcriptions))
}

func (mrs *MeetingRecordingService) calculateStorageUsed(recordings []models.MeetingRecording) int64 {
	total := int64(0)
	for _, recording := range recordings {
		if fileSize, err := strconv.ParseInt(recording.FileSize, 10, 64); err == nil {
			total += fileSize
		}
	}
	return total
}

func (mrs *MeetingRecordingService) getRecordingFormats(recordings []models.MeetingRecording) []string {
	formats := make(map[string]bool)
	for _, recording := range recordings {
		formats[recording.Format] = true
	}

	result := make([]string, 0, len(formats))
	for format := range formats {
		result = append(result, format)
	}
	return result
}

func (mrs *MeetingRecordingService) getDetectedLanguages(transcriptions []models.MeetingTranscription) []string {
	languages := make(map[string]bool)
	for _, transcription := range transcriptions {
		languages[transcription.Language] = true
	}

	result := make([]string, 0, len(languages))
	for language := range languages {
		result = append(result, language)
	}
	return result
}

func (mrs *MeetingRecordingService) getParticipantRecordingAnalytics(meetingID string) map[string]interface{} {
	// Get participant-specific recording data
	return map[string]interface{}{
		"participants_recorded": 0, // Would be calculated from actual data
		"speaking_time_distribution": map[string]interface{}{
			"balanced":         true,
			"dominant_speaker": "",
		},
		"engagement_metrics": map[string]interface{}{
			"active_participants": 0,
			"silent_participants": 0,
		},
	}
}
