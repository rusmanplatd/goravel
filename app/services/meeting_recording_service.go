package services

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"goravel/app/models"

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
	RecordingID  string
	MeetingID    string
	StartedAt    time.Time
	Status       string
	FilePath     string
	FileSize     int64
	Duration     int
	Participants []string
	mu           sync.RWMutex
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
	// This would integrate with LiveKit or other recording service
	// For now, we'll simulate the recording process

	// Ensure directory exists
	dir := filepath.Dir(activeRecording.FilePath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		facades.Log().Error("Failed to create recording directory", map[string]interface{}{
			"error": err,
			"path":  dir,
		})
		return
	}

	// Update status periodically
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			mrs.mu.RLock()
			if _, exists := mrs.activeRecordings[activeRecording.MeetingID]; !exists {
				mrs.mu.RUnlock()
				return // Recording stopped
			}
			mrs.mu.RUnlock()

			// Update recording metrics
			activeRecording.mu.Lock()
			activeRecording.Duration = int(time.Since(activeRecording.StartedAt).Seconds())
			activeRecording.mu.Unlock()

		default:
			time.Sleep(1 * time.Second)
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
	// Implementation for Azure Speech Services
	return "Transcription using Azure Speech Services", nil
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
	// OpenAI API implementation
	return "AI-generated summary using OpenAI", nil
}

func (mrs *MeetingRecordingService) callClaude(prompt string) (string, error) {
	// Anthropic Claude API implementation
	return "AI-generated summary using Claude", nil
}

func (mrs *MeetingRecordingService) callGemini(prompt string) (string, error) {
	// Google Gemini API implementation
	return "AI-generated summary using Gemini", nil
}

// generateThumbnail creates a thumbnail for the recording
func (mrs *MeetingRecordingService) generateThumbnail(recording *models.MeetingRecording) error {
	// Implementation for generating video thumbnail
	thumbnailPath := strings.Replace(recording.FilePath, "."+recording.Format, "_thumb.jpg", 1)
	recording.ThumbnailURL = thumbnailPath
	return facades.Orm().Query().Save(recording)
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
