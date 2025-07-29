package feature

import (
	"testing"
	"time"

	"goravel/app/models"
	"goravel/app/services"

	"github.com/goravel/framework/facades"
	"github.com/stretchr/testify/assert"
)

func TestTeamsMeetingSystem(t *testing.T) {
	// Setup
	setupTestDatabase(t)

	t.Run("Teams-like Meeting Creation", func(t *testing.T) {
		testTeamsLikeMeetingCreation(t)
	})

	t.Run("Teams-like Security Features", func(t *testing.T) {
		testTeamsLikeSecurityFeatures(t)
	})

	t.Run("Teams-like Recording Features", func(t *testing.T) {
		testTeamsLikeRecordingFeatures(t)
	})

	t.Run("Teams-like Analytics Features", func(t *testing.T) {
		testTeamsLikeAnalyticsFeatures(t)
	})

	t.Run("Teams-like Meeting Flow", func(t *testing.T) {
		testTeamsLikeMeetingFlow(t)
	})
}

func testTeamsLikeMeetingCreation(t *testing.T) {
	// Create test user
	testUser := &models.User{
		Name:  "Test Host",
		Email: "host@example.com",
	}
	facades.Orm().Query().Create(testUser)
	defer facades.Orm().Query().Where("id", testUser.ID).Delete(&models.User{})

	// Create test meeting with Teams-like properties
	startTime := time.Now().Add(5 * time.Minute)
	endTime := startTime.Add(1 * time.Hour)

	testMeeting := &models.Meeting{
		Subject:                              "Teams Test Meeting",
		StartDateTime:                        &startTime,
		EndDateTime:                          &endTime,
		JoinWebUrl:                           "https://teams.example.com/meet/123",
		AllowAttendeeToEnableCamera:          true,
		AllowAttendeeToEnableMic:             true,
		AllowBreakoutRooms:                   false,
		AllowCopyingAndSharingMeetingContent: true,
		AllowLiveShare:                       "enabled",
		AllowMeetingChat:                     "enabled",
		AllowRecording:                       true,
		AllowTranscription:                   true,
		IsEndToEndEncryptionEnabled:          false,
		WatermarkProtection:                  "disabled",
		AllowedLobbyAdmitters:                "organizerAndCoOrganizers",
		Status:                               "scheduled",
		ExternalId:                           "test-meeting-001",
	}
	facades.Orm().Query().Create(testMeeting)
	defer facades.Orm().Query().Where("id", testMeeting.ID).Delete(&models.Meeting{})

	// Verify Teams-compatible properties
	assert.Equal(t, "Teams Test Meeting", testMeeting.Subject)
	assert.Equal(t, "test-meeting-001", testMeeting.ExternalId)
	assert.Equal(t, true, testMeeting.AllowRecording)
	assert.Equal(t, true, testMeeting.AllowTranscription)
	assert.Equal(t, "disabled", testMeeting.WatermarkProtection)
	assert.Equal(t, "enabled", testMeeting.AllowLiveShare)
	assert.Equal(t, "enabled", testMeeting.AllowMeetingChat)
	assert.NotEmpty(t, testMeeting.JoinWebUrl)
}

func testTeamsLikeSecurityFeatures(t *testing.T) {
	// Create test user and meeting
	testUser, testMeeting := createTestUserAndMeeting(t)
	defer cleanupTestData(t, testUser.ID, testMeeting.ID)

	securityService := services.NewMeetingSecurityService()

	// Test watermark protection
	err := securityService.EnableWatermarkProtection(testMeeting.ID, testUser.ID, true)
	assert.NoError(t, err)

	// Verify watermark was enabled
	var updatedMeeting models.Meeting
	facades.Orm().Query().Where("id", testMeeting.ID).First(&updatedMeeting)
	assert.Equal(t, "enabled", updatedMeeting.WatermarkProtection)

	// Test entry/exit announcements
	err = securityService.ConfigureEntryExitAnnouncements(testMeeting.ID, testUser.ID, true, true)
	assert.NoError(t, err)

	// Test lobby bypass settings
	lobbySettings := map[string]interface{}{
		"scope": "organization",
	}
	err = securityService.SetMeetingLobbyBypass(testMeeting.ID, testUser.ID, lobbySettings)
	assert.NoError(t, err)

	// Test end-to-end encryption
	err = securityService.EnableMeetingEncryption(testMeeting.ID, testUser.ID, true)
	assert.NoError(t, err)

	// Verify encryption was enabled
	facades.Orm().Query().Where("id", testMeeting.ID).First(&updatedMeeting)
	assert.Equal(t, true, updatedMeeting.IsEndToEndEncryptionEnabled)

	// Test chat restrictions
	chatRestrictions := map[string]interface{}{
		"allowed_chat_types": []string{"all"},
		"restricted_users":   []string{},
	}
	err = securityService.ConfigureMeetingChatRestrictions(testMeeting.ID, testUser.ID, "enabled", chatRestrictions)
	assert.NoError(t, err)

	// Test presenter controls
	presenterControls := map[string]interface{}{
		"allowPresentersToUnmute":       true,
		"allowPresentersToEnableCamera": true,
	}
	err = securityService.SetMeetingPresenterControls(testMeeting.ID, testUser.ID, presenterControls)
	assert.NoError(t, err)
}

func testTeamsLikeRecordingFeatures(t *testing.T) {
	// Create test user and meeting
	testUser, testMeeting := createTestUserAndMeeting(t)
	defer cleanupTestData(t, testUser.ID, testMeeting.ID)

	recordingService := services.NewMeetingRecordingService()

	// Test starting a recording with Teams-like configuration
	config := services.RecordingConfiguration{
		Quality:            "high",
		Format:             "mp4",
		IncludeVideo:       true,
		IncludeAudio:       true,
		IncludeScreenShare: true,
		AutoTranscribe:     true,
		GenerateSummary:    true,
		LanguageCode:       "en-US",
		WatermarkEnabled:   true,
		EncryptionEnabled:  true,
	}

	recording, err := recordingService.StartRecording(testMeeting.ID, testUser.ID, config)
	assert.NoError(t, err)
	assert.NotNil(t, recording)
	assert.Equal(t, "recording", recording.Status)
	assert.Equal(t, "mp4", recording.Format)
	assert.Equal(t, "high", recording.Quality)

	// Clean up recording
	defer facades.Orm().Query().Where("id", recording.ID).Delete(&models.MeetingRecording{})

	// Test live transcription
	err = recordingService.StartLiveTranscription(testMeeting.ID, testUser.ID, "en-US")
	assert.NoError(t, err)

	// Test participant-specific recording
	participantIDs := []string{testUser.ID}
	participantRecording, err := recordingService.StartParticipantSpecificRecording(
		testMeeting.ID, testUser.ID, participantIDs, config)
	assert.NoError(t, err)
	assert.NotNil(t, participantRecording)
	assert.Equal(t, "participant_specific", participantRecording.RecordingType)

	// Clean up participant recording
	defer facades.Orm().Query().Where("id", participantRecording.ID).Delete(&models.MeetingRecording{})

	// Test recording policy application
	policy := map[string]interface{}{
		"autoRecord":         true,
		"allowRecording":     true,
		"allowTranscription": true,
	}
	err = recordingService.ApplyRecordingPolicy(testMeeting.ID, testUser.ID, policy)
	assert.NoError(t, err)
}

func testTeamsLikeAnalyticsFeatures(t *testing.T) {
	// Create test user and meeting
	testUser, testMeeting := createTestUserAndMeeting(t)
	defer cleanupTestData(t, testUser.ID, testMeeting.ID)

	analyticsService := services.NewMeetingAnalyticsService()

	// Create test participant
	participant := &models.MeetingParticipant{
		MeetingID:       testMeeting.ID,
		UserID:          testUser.ID,
		Role:            "host",
		Status:          "joined",
		JoinedAt:        &[]time.Time{time.Now().Add(-30 * time.Minute)}[0],
		LeftAt:          &[]time.Time{time.Now().Add(-5 * time.Minute)}[0],
		DurationSeconds: 1500, // 25 minutes
		DeviceType:      "desktop",
		BrowserInfo:     "Chrome/91.0.4472.124",
		IPAddress:       "192.168.1.100",
	}
	facades.Orm().Query().Create(participant)
	defer facades.Orm().Query().Where("id", participant.ID).Delete(&models.MeetingParticipant{})

	// Test Teams-like attendance report generation
	attendanceReport, err := analyticsService.GenerateTeamsLikeAttendanceReport(testMeeting.ID)
	assert.NoError(t, err)
	assert.NotNil(t, attendanceReport)
	assert.Equal(t, testMeeting.ID, attendanceReport.MeetingID)
	assert.Equal(t, 1, attendanceReport.TotalParticipants)
	assert.Equal(t, 1, attendanceReport.UniqueParticipants)
	assert.Equal(t, "completed", attendanceReport.Status)
	assert.NotEmpty(t, attendanceReport.ReportData)

	// Clean up attendance report
	defer facades.Orm().Query().Where("id", attendanceReport.ID).Delete(&models.MeetingAttendanceReport{})

	// Test participant analytics
	analytics, err := analyticsService.GetTeamsLikeParticipantAnalytics(testMeeting.ID)
	assert.NoError(t, err)
	assert.NotNil(t, analytics)
	assert.Contains(t, analytics, "meeting_overview")
	assert.Contains(t, analytics, "attendance_summary")
	assert.Contains(t, analytics, "participation_details")
	assert.Contains(t, analytics, "engagement_metrics")

	// Test engagement insights
	insights, err := analyticsService.GetTeamsLikeEngagementInsights(testMeeting.ID)
	assert.NoError(t, err)
	assert.NotNil(t, insights)
	assert.Contains(t, insights, "overall_engagement")
	assert.Contains(t, insights, "communication_patterns")
	assert.Contains(t, insights, "participation_quality")
	assert.Contains(t, insights, "meeting_effectiveness")

	// Test report export
	jsonReport, err := analyticsService.ExportTeamsLikeReport(testMeeting.ID, "json")
	assert.NoError(t, err)
	assert.NotEmpty(t, jsonReport)
}

func testTeamsLikeMeetingFlow(t *testing.T) {
	// Create test user and meeting
	testUser, testMeeting := createTestUserAndMeeting(t)
	defer cleanupTestData(t, testUser.ID, testMeeting.ID)

	meetingService := services.NewMeetingService()
	securityService := services.NewMeetingSecurityService()

	// Test complete Teams-like meeting flow

	// 1. Start the meeting
	err := meetingService.StartMeeting(testMeeting.ID, testUser.ID)
	assert.NoError(t, err)

	// 2. Join as participant
	deviceInfo := map[string]string{
		"device_type": "desktop",
		"browser":     "Chrome",
	}
	_, err = meetingService.JoinMeeting(testMeeting.ID, testUser.ID, "conn_123", deviceInfo)
	assert.NoError(t, err)

	// 3. Apply security monitoring
	securityEvents, err := securityService.MonitorMeetingSecurity(testMeeting.ID)
	assert.NoError(t, err)
	assert.NotNil(t, securityEvents)

	// 4. Monitor compliance
	complianceEvents, err := securityService.MonitorMeetingCompliance(testMeeting.ID)
	assert.NoError(t, err)
	assert.NotNil(t, complianceEvents)

	// 5. Leave the meeting
	err = meetingService.LeaveMeeting(testMeeting.ID, testUser.ID)
	assert.NoError(t, err)

	// 6. End the meeting
	err = meetingService.EndMeeting(testMeeting.ID, testUser.ID)
	assert.NoError(t, err)

	// Verify meeting status
	var updatedMeeting models.Meeting
	facades.Orm().Query().Where("id", testMeeting.ID).First(&updatedMeeting)
	assert.Equal(t, "completed", updatedMeeting.Status)
	assert.NotNil(t, updatedMeeting.EndedAt)
}

// Helper functions
func createTestUserAndMeeting(t *testing.T) (*models.User, *models.Meeting) {
	// Create test user
	testUser := &models.User{
		Name:  "Test Host",
		Email: "host@example.com",
	}
	facades.Orm().Query().Create(testUser)

	// Create test meeting with Teams-like properties
	startTime := time.Now().Add(5 * time.Minute)
	endTime := startTime.Add(1 * time.Hour)

	testMeeting := &models.Meeting{
		Subject:                              "Teams Test Meeting",
		StartDateTime:                        &startTime,
		EndDateTime:                          &endTime,
		JoinWebUrl:                           "https://teams.example.com/meet/123",
		AllowAttendeeToEnableCamera:          true,
		AllowAttendeeToEnableMic:             true,
		AllowBreakoutRooms:                   false,
		AllowCopyingAndSharingMeetingContent: true,
		AllowLiveShare:                       "enabled",
		AllowMeetingChat:                     "enabled",
		AllowRecording:                       true,
		AllowTranscription:                   true,
		IsEndToEndEncryptionEnabled:          false,
		WatermarkProtection:                  "disabled",
		AllowedLobbyAdmitters:                "organizerAndCoOrganizers",
		Status:                               "scheduled",
		ExternalId:                           "test-meeting-001",
	}
	facades.Orm().Query().Create(testMeeting)

	return testUser, testMeeting
}

func cleanupTestData(t *testing.T, userID, meetingID string) {
	// Clean up test data
	facades.Orm().Query().Where("id", userID).Delete(&models.User{})
	facades.Orm().Query().Where("id", meetingID).Delete(&models.Meeting{})
	facades.Orm().Query().Where("meeting_id", meetingID).Delete(&models.MeetingParticipant{})
	facades.Orm().Query().Where("meeting_id", meetingID).Delete(&models.MeetingRecording{})
	facades.Orm().Query().Where("meeting_id", meetingID).Delete(&models.MeetingTranscription{})
	facades.Orm().Query().Where("meeting_id", meetingID).Delete(&models.MeetingAttendanceReport{})
	facades.Orm().Query().Where("meeting_id", meetingID).Delete(&models.MeetingAISummary{})
}
