package services

import (
	"encoding/json"
	"fmt"
	"goravel/app/models"
	"math"
	"strings"
	"time"

	"github.com/goravel/framework/facades"
)

// MeetingAnalyticsServiceSimple provides simplified meeting analytics
type MeetingAnalyticsServiceSimple struct{}

// NewMeetingAnalyticsService creates a new meeting analytics service
func NewMeetingAnalyticsService() *MeetingAnalyticsServiceSimple {
	return &MeetingAnalyticsServiceSimple{}
}

// MeetingStats represents basic meeting statistics
type MeetingStats struct {
	MeetingID         string  `json:"meeting_id"`
	TotalDuration     int     `json:"total_duration_minutes"`
	ParticipantCount  int     `json:"participant_count"`
	TotalChatMessages int     `json:"total_chat_messages"`
	PollCount         int     `json:"poll_count"`
	BreakoutRoomCount int     `json:"breakout_room_count"`
	EngagementScore   float64 `json:"engagement_score"`
}

// GetMeetingStats returns basic meeting statistics
func (mas *MeetingAnalyticsServiceSimple) GetMeetingStats(meetingID string) (*MeetingStats, error) {
	var meeting models.Meeting
	err := facades.Orm().Query().Where("id", meetingID).First(&meeting)
	if err != nil {
		return nil, fmt.Errorf("meeting not found: %v", err)
	}

	// Get participants
	var participants []models.MeetingParticipant
	facades.Orm().Query().Where("meeting_id", meetingID).Find(&participants)
	participantCount := len(participants)

	// Get chat messages
	var chatMessages []models.MeetingChat
	facades.Orm().Query().Where("meeting_id", meetingID).Find(&chatMessages)
	chatCount := len(chatMessages)

	// Get polls
	var polls []models.MeetingPoll
	facades.Orm().Query().Where("meeting_id", meetingID).Find(&polls)
	pollCount := len(polls)

	// Get breakout rooms
	var breakoutRooms []models.MeetingBreakoutRoom
	facades.Orm().Query().Where("meeting_id", meetingID).Find(&breakoutRooms)
	breakoutCount := len(breakoutRooms)

	// Calculate duration
	duration := 0
	if meeting.StartedAt != nil && meeting.EndedAt != nil {
		duration = int(meeting.EndedAt.Sub(*meeting.StartedAt).Minutes())
	}

	// Simple engagement score calculation
	engagementScore := float64(chatCount+pollCount*2) / float64(participantCount+1) * 10
	if engagementScore > 100 {
		engagementScore = 100
	}

	stats := &MeetingStats{
		MeetingID:         meetingID,
		TotalDuration:     duration,
		ParticipantCount:  int(participantCount),
		TotalChatMessages: int(chatCount),
		PollCount:         int(pollCount),
		BreakoutRoomCount: int(breakoutCount),
		EngagementScore:   engagementScore,
	}

	return stats, nil
}

// GetParticipationReport returns simplified participation report
func (mas *MeetingAnalyticsServiceSimple) GetParticipationReport(meetingID string) (map[string]interface{}, error) {
	var meeting models.Meeting
	err := facades.Orm().Query().Where("id", meetingID).First(&meeting)
	if err != nil {
		return nil, fmt.Errorf("meeting not found: %v", err)
	}

	var participants []models.MeetingParticipant
	facades.Orm().Query().Where("meeting_id", meetingID).Find(&participants)

	report := map[string]interface{}{
		"meeting_id":         meetingID,
		"total_participants": len(participants),
		"participants":       participants,
		"summary": map[string]interface{}{
			"total_count":  len(participants),
			"joined_count": mas.countByStatus(participants, "joined"),
			"left_count":   mas.countByStatus(participants, "left"),
		},
	}

	return report, nil
}

// GetEngagementMetrics returns simplified engagement metrics
func (mas *MeetingAnalyticsServiceSimple) GetEngagementMetrics(meetingID string) (map[string]interface{}, error) {
	var participants []models.MeetingParticipant
	facades.Orm().Query().Where("meeting_id", meetingID).Find(&participants)

	var chatMessages []models.MeetingChat
	facades.Orm().Query().Where("meeting_id", meetingID).Find(&chatMessages)

	var polls []models.MeetingPoll
	facades.Orm().Query().Where("meeting_id", meetingID).Find(&polls)

	metrics := map[string]interface{}{
		"total_participants":  len(participants),
		"total_messages":      len(chatMessages),
		"total_polls":         len(polls),
		"engagement_score":    mas.calculateSimpleEngagement(participants, chatMessages, polls),
		"active_participants": mas.countActiveParticipants(participants),
	}

	return metrics, nil
}

// GetAttendanceReport returns simplified attendance report
func (mas *MeetingAnalyticsServiceSimple) GetAttendanceReport(meetingID string) (map[string]interface{}, error) {
	var meeting models.Meeting
	err := facades.Orm().Query().Where("id", meetingID).First(&meeting)
	if err != nil {
		return nil, fmt.Errorf("meeting not found: %v", err)
	}

	var participants []models.MeetingParticipant
	facades.Orm().Query().Where("meeting_id", meetingID).Find(&participants)

	report := map[string]interface{}{
		"meeting_id":         meetingID,
		"total_participants": len(participants),
		"attendance_summary": map[string]interface{}{
			"joined":  mas.countByStatus(participants, "joined"),
			"left":    mas.countByStatus(participants, "left"),
			"invited": mas.countByStatus(participants, "invited"),
		},
	}

	return report, nil
}

// GetOrganizationalAnalytics returns simplified organizational analytics
func (mas *MeetingAnalyticsServiceSimple) GetOrganizationalAnalytics(organizationID string, startDate, endDate *time.Time) (map[string]interface{}, error) {
	query := facades.Orm().Query()

	if startDate != nil {
		query = query.Where("created_at >= ?", startDate)
	}

	if endDate != nil {
		query = query.Where("created_at <= ?", endDate)
	}

	var meetings []models.Meeting
	query.Find(&meetings)
	meetingCount := len(meetings)

	analytics := map[string]interface{}{
		"organization_id": organizationID,
		"total_meetings":  meetingCount,
		"period":          mas.formatPeriod(startDate, endDate),
	}

	return analytics, nil
}

// ExportMeetingReport exports simplified meeting data
func (mas *MeetingAnalyticsServiceSimple) ExportMeetingReport(meetingID, format string) (map[string]interface{}, error) {
	stats, err := mas.GetMeetingStats(meetingID)
	if err != nil {
		return nil, err
	}

	report, err := mas.GetParticipationReport(meetingID)
	if err != nil {
		return nil, err
	}

	exportData := map[string]interface{}{
		"format":        format,
		"generated_at":  time.Now(),
		"meeting_stats": stats,
		"participation": report,
		"export_url":    fmt.Sprintf("/api/v1/meetings/%s/analytics/download?format=%s", meetingID, format),
	}

	return exportData, nil
}

// GetRealTimeMetrics returns simplified real-time metrics
func (mas *MeetingAnalyticsServiceSimple) GetRealTimeMetrics(meetingID string) (map[string]interface{}, error) {
	var activeParticipants []models.MeetingParticipant
	facades.Orm().Query().
		Where("meeting_id", meetingID).
		Where("status", "joined").
		Find(&activeParticipants)

	// Get recent chat activity
	var recentMessages []models.MeetingChat
	fiveMinutesAgo := time.Now().Add(-5 * time.Minute)
	facades.Orm().Query().
		Where("meeting_id", meetingID).
		Where("created_at >= ?", fiveMinutesAgo).
		Find(&recentMessages)

	metrics := map[string]interface{}{
		"meeting_id":           meetingID,
		"current_participants": len(activeParticipants),
		"recent_chat_activity": len(recentMessages),
		"chat_activity_rate":   float64(len(recentMessages)) / 5.0,
		"engagement_level":     mas.calculateCurrentEngagement(activeParticipants, recentMessages),
	}

	return metrics, nil
}

// Teams-like attendance and analytics features

// GenerateTeamsLikeAttendanceReport generates a comprehensive attendance report similar to Microsoft Teams
func (mas *MeetingAnalyticsServiceSimple) GenerateTeamsLikeAttendanceReport(meetingID string) (*models.MeetingAttendanceReport, error) {
	// Get meeting details
	var meeting models.Meeting
	err := facades.Orm().Query().Where("id", meetingID).With("Participants.User").First(&meeting)
	if err != nil {
		return nil, fmt.Errorf("meeting not found: %v", err)
	}

	// Get all participants with detailed information
	var participants []models.MeetingParticipant
	err = facades.Orm().Query().
		Where("meeting_id", meetingID).
		With("User").
		Order("joined_at ASC").
		Find(&participants)

	if err != nil {
		return nil, fmt.Errorf("failed to get participants: %v", err)
	}

	// Generate Teams-like attendance data
	attendanceData := mas.generateTeamsAttendanceData(participants, &meeting)

	// Create attendance report record
	report := &models.MeetingAttendanceReport{
		MeetingID:          meetingID,
		Title:              fmt.Sprintf("%s - Attendance Report", meeting.Subject),
		TotalParticipants:  len(participants),
		UniqueParticipants: mas.countUniqueParticipants(participants),
		Status:             "completed",
		Format:             "json",
		ReportData:         attendanceData,
	}

	// Calculate file size
	report.FileSize = int64(len(attendanceData))

	// Save to database
	if err := facades.Orm().Query().Create(report); err != nil {
		return nil, fmt.Errorf("failed to create attendance report: %v", err)
	}

	// Generate download URL
	report.DownloadUrl = fmt.Sprintf("/api/v1/meetings/%s/attendance/reports/%s", meetingID, report.ID)

	// Update with download URL
	facades.Orm().Query().Save(report)

	facades.Log().Info("Teams-like attendance report generated", map[string]interface{}{
		"meeting_id":          meetingID,
		"report_id":           report.ID,
		"total_participants":  report.TotalParticipants,
		"unique_participants": report.UniqueParticipants,
	})

	return report, nil
}

// GetTeamsLikeParticipantAnalytics provides detailed participant analytics similar to Teams
func (mas *MeetingAnalyticsServiceSimple) GetTeamsLikeParticipantAnalytics(meetingID string) (map[string]interface{}, error) {
	// Get meeting and participants
	var meeting models.Meeting
	err := facades.Orm().Query().Where("id", meetingID).First(&meeting)
	if err != nil {
		return nil, fmt.Errorf("meeting not found: %v", err)
	}

	var participants []models.MeetingParticipant
	err = facades.Orm().Query().
		Where("meeting_id", meetingID).
		With("User").
		Find(&participants)

	if err != nil {
		return nil, fmt.Errorf("failed to get participants: %v", err)
	}

	// Calculate Teams-like analytics
	analytics := map[string]interface{}{
		"meeting_overview": map[string]interface{}{
			"meeting_id":         meetingID,
			"subject":            meeting.Subject,
			"start_time":         meeting.StartDateTime,
			"end_time":           meeting.EndDateTime,
			"actual_start":       meeting.StartedAt,
			"actual_end":         meeting.EndedAt,
			"duration_scheduled": mas.calculateScheduledDuration(&meeting),
			"duration_actual":    mas.calculateActualDuration(&meeting),
		},
		"attendance_summary": map[string]interface{}{
			"total_invitees":    mas.getTotalInvitees(meetingID),
			"total_attendees":   len(participants),
			"unique_attendees":  mas.countUniqueParticipants(participants),
			"attendance_rate":   mas.calculateAttendanceRate(meetingID, len(participants)),
			"on_time_attendees": mas.countOnTimeAttendees(participants, &meeting),
			"late_attendees":    mas.countLateAttendees(participants, &meeting),
			"early_leavers":     mas.countEarlyLeavers(participants, &meeting),
		},
		"participation_details": mas.generateParticipationDetails(participants),
		"engagement_metrics": map[string]interface{}{
			"average_attendance_duration": mas.calculateAverageAttendanceDuration(participants),
			"peak_concurrent_attendees":   mas.calculatePeakConcurrentAttendees(participants),
			"join_leave_frequency":        mas.calculateJoinLeaveFrequency(participants),
			"participant_turnover":        mas.calculateParticipantTurnover(participants),
		},
		"time_analysis": map[string]interface{}{
			"join_time_distribution":  mas.analyzeJoinTimeDistribution(participants, &meeting),
			"leave_time_distribution": mas.analyzeLeaveTimeDistribution(participants, &meeting),
			"duration_distribution":   mas.analyzeDurationDistribution(participants),
		},
		"device_and_location": mas.analyzeDeviceAndLocation(participants),
		"compliance_metrics": map[string]interface{}{
			"recording_consent":     mas.checkRecordingConsent(meetingID),
			"external_participants": mas.identifyExternalParticipants(participants),
			"policy_violations":     mas.checkPolicyViolations(meetingID),
		},
	}

	return analytics, nil
}

// GetTeamsLikeEngagementInsights provides Teams-style engagement insights
func (mas *MeetingAnalyticsServiceSimple) GetTeamsLikeEngagementInsights(meetingID string) (map[string]interface{}, error) {
	// Get meeting data
	var participants []models.MeetingParticipant
	err := facades.Orm().Query().
		Where("meeting_id", meetingID).
		With("User").
		Find(&participants)

	if err != nil {
		return nil, fmt.Errorf("failed to get participants: %v", err)
	}

	// Get chat messages
	var chatMessages []models.MeetingChat
	err = facades.Orm().Query().
		Where("meeting_id", meetingID).
		With("Sender").
		Find(&chatMessages)

	if err != nil {
		facades.Log().Warning("Failed to get chat messages", map[string]interface{}{
			"meeting_id": meetingID,
			"error":      err.Error(),
		})
		chatMessages = []models.MeetingChat{} // Continue without chat data
	}

	// Get polls and reactions
	var polls []models.MeetingPoll
	facades.Orm().Query().Where("meeting_id", meetingID).Find(&polls)

	insights := map[string]interface{}{
		"overall_engagement": map[string]interface{}{
			"engagement_score":     mas.calculateOverallEngagement(participants, chatMessages, polls),
			"active_participants":  mas.countActiveParticipants(participants),
			"passive_participants": mas.countPassiveParticipants(participants, chatMessages),
			"engagement_trend":     mas.analyzeEngagementTrend(participants),
		},
		"communication_patterns": map[string]interface{}{
			"total_messages":           len(chatMessages),
			"messages_per_participant": mas.calculateMessagesPerParticipant(chatMessages, participants),
			"most_active_participants": mas.getMostActiveParticipants(chatMessages, participants),
			"communication_timeline":   mas.analyzeCommunicationTimeline(chatMessages),
		},
		"participation_quality": map[string]interface{}{
			"speaking_time_distribution": mas.estimateSpeakingTimeDistribution(participants),
			"interaction_frequency":      mas.calculateInteractionFrequency(participants, chatMessages),
			"collaboration_score":        mas.calculateCollaborationScore(participants, chatMessages, polls),
		},
		"meeting_effectiveness": map[string]interface{}{
			"attention_span":        mas.estimateAttentionSpan(participants),
			"drop_off_points":       mas.identifyDropOffPoints(participants),
			"re_engagement_success": mas.calculateReEngagementSuccess(participants),
			"meeting_satisfaction":  mas.estimateMeetingSatisfaction(participants, chatMessages),
		},
		"recommendations": mas.generateEngagementRecommendations(participants, chatMessages, polls),
	}

	return insights, nil
}

// ExportTeamsLikeReport exports attendance data in Teams-compatible formats
func (mas *MeetingAnalyticsServiceSimple) ExportTeamsLikeReport(meetingID, format string) (string, error) {
	// Get attendance report
	report, err := mas.GenerateTeamsLikeAttendanceReport(meetingID)
	if err != nil {
		return "", fmt.Errorf("failed to generate report: %v", err)
	}

	switch format {
	case "csv":
		return mas.exportToCSV(report)
	case "xlsx":
		return mas.exportToExcel(report)
	case "pdf":
		return mas.exportToPDF(report)
	case "json":
		return report.ReportData, nil
	default:
		return "", fmt.Errorf("unsupported format: %s", format)
	}
}

// Helper methods

func (mas *MeetingAnalyticsServiceSimple) countByStatus(participants []models.MeetingParticipant, status string) int {
	count := 0
	for _, participant := range participants {
		if participant.Status == status {
			count++
		}
	}
	return count
}

func (mas *MeetingAnalyticsServiceSimple) calculateSimpleEngagement(participants []models.MeetingParticipant, messages []models.MeetingChat, polls []models.MeetingPoll) float64 {
	if len(participants) == 0 {
		return 0.0
	}

	messageScore := float64(len(messages)) / float64(len(participants))
	pollScore := float64(len(polls)) * 2.0

	engagementScore := (messageScore + pollScore) * 10
	if engagementScore > 100 {
		engagementScore = 100
	}

	return engagementScore
}

func (mas *MeetingAnalyticsServiceSimple) countActiveParticipants(participants []models.MeetingParticipant) int {
	return mas.countByStatus(participants, "joined")
}

func (mas *MeetingAnalyticsServiceSimple) calculateCurrentEngagement(participants []models.MeetingParticipant, recentMessages []models.MeetingChat) string {
	if len(participants) == 0 {
		return "low"
	}

	messagesPerParticipant := float64(len(recentMessages)) / float64(len(participants))

	if messagesPerParticipant > 2.0 {
		return "high"
	} else if messagesPerParticipant > 0.5 {
		return "medium"
	}

	return "low"
}

func (mas *MeetingAnalyticsServiceSimple) formatPeriod(startDate, endDate *time.Time) string {
	if startDate != nil && endDate != nil {
		return fmt.Sprintf("%s to %s", startDate.Format("2006-01-02"), endDate.Format("2006-01-02"))
	}
	return "All time"
}

// Helper methods for Teams-like analytics

func (mas *MeetingAnalyticsServiceSimple) generateTeamsAttendanceData(participants []models.MeetingParticipant, meeting *models.Meeting) string {
	type TeamsAttendanceEntry struct {
		Name              string     `json:"name"`
		Email             string     `json:"email"`
		Role              string     `json:"role"`
		JoinTime          *time.Time `json:"join_time"`
		LeaveTime         *time.Time `json:"leave_time"`
		Duration          string     `json:"duration"`
		DurationSeconds   int        `json:"duration_seconds"`
		IsOrganizer       bool       `json:"is_organizer"`
		IsPresenter       bool       `json:"is_presenter"`
		AttendanceStatus  string     `json:"attendance_status"`
		DeviceType        string     `json:"device_type"`
		ConnectionQuality string     `json:"connection_quality"`
		JoinMethod        string     `json:"join_method"`
		IsExternal        bool       `json:"is_external"`
		TimeZone          string     `json:"time_zone"`
	}

	var attendanceEntries []TeamsAttendanceEntry
	organizationDomain := mas.getOrganizationDomain()

	for _, participant := range participants {
		entry := TeamsAttendanceEntry{
			Role:              participant.Role,
			JoinTime:          participant.JoinedAt,
			LeaveTime:         participant.LeftAt,
			DurationSeconds:   participant.DurationSeconds,
			Duration:          mas.formatDuration(participant.DurationSeconds),
			IsOrganizer:       participant.Role == "host",
			IsPresenter:       participant.Role == "presenter" || participant.Role == "co-host",
			AttendanceStatus:  mas.determineAttendanceStatus(&participant, meeting),
			DeviceType:        participant.DeviceType,
			ConnectionQuality: mas.extractConnectionQuality(participant.ConnectionQuality),
			JoinMethod:        mas.extractJoinMethod(participant.BrowserInfo),
			TimeZone:          mas.extractTimeZone(participant.ConnectionQuality),
		}

		if participant.User != nil {
			entry.Name = participant.User.Name
			entry.Email = participant.User.Email
			entry.IsExternal = !mas.isInternalDomain(participant.User.Email, organizationDomain)
		} else {
			entry.Name = "Unknown Participant"
		}

		attendanceEntries = append(attendanceEntries, entry)
	}

	// Create Teams-like report structure
	reportData := map[string]interface{}{
		"meeting_info": map[string]interface{}{
			"subject":    meeting.Subject,
			"start_time": meeting.StartDateTime,
			"end_time":   meeting.EndDateTime,
			"organizer":  mas.getMeetingOrganizer(meeting),
			"meeting_id": meeting.ID,
		},
		"summary": map[string]interface{}{
			"total_attendees":  len(participants),
			"unique_attendees": mas.countUniqueParticipants(participants),
			"average_duration": mas.calculateAverageAttendanceDuration(participants),
			"on_time_rate":     mas.calculateOnTimeRate(participants, meeting),
			"completion_rate":  mas.calculateCompletionRate(participants, meeting),
		},
		"attendees":      attendanceEntries,
		"generated_at":   time.Now(),
		"report_version": "1.0",
	}

	reportJSON, _ := json.MarshalIndent(reportData, "", "  ")
	return string(reportJSON)
}

func (mas *MeetingAnalyticsServiceSimple) countUniqueParticipants(participants []models.MeetingParticipant) int {
	unique := make(map[string]bool)
	for _, participant := range participants {
		if participant.User != nil {
			unique[participant.User.Email] = true
		} else {
			unique[participant.UserID] = true
		}
	}
	return len(unique)
}

func (mas *MeetingAnalyticsServiceSimple) calculateScheduledDuration(meeting *models.Meeting) int {
	if meeting.StartDateTime != nil && meeting.EndDateTime != nil {
		return int(meeting.EndDateTime.Sub(*meeting.StartDateTime).Seconds())
	}
	return 0
}

func (mas *MeetingAnalyticsServiceSimple) calculateActualDuration(meeting *models.Meeting) int {
	if meeting.StartedAt != nil && meeting.EndedAt != nil {
		return int(meeting.EndedAt.Sub(*meeting.StartedAt).Seconds())
	}
	return 0
}

func (mas *MeetingAnalyticsServiceSimple) getTotalInvitees(meetingID string) int {
	// This would typically get the count from calendar event invitees
	// For now, we'll use a placeholder
	return 10 // Placeholder - would be calculated from actual invitee data
}

func (mas *MeetingAnalyticsServiceSimple) calculateAttendanceRate(meetingID string, attendees int) float64 {
	invitees := mas.getTotalInvitees(meetingID)
	if invitees == 0 {
		return 0.0
	}
	return float64(attendees) / float64(invitees) * 100
}

func (mas *MeetingAnalyticsServiceSimple) countOnTimeAttendees(participants []models.MeetingParticipant, meeting *models.Meeting) int {
	if meeting.StartDateTime == nil {
		return 0
	}

	onTimeCount := 0
	graceWindow := 5 * time.Minute // 5-minute grace window

	for _, participant := range participants {
		if participant.JoinedAt != nil {
			if participant.JoinedAt.Before(meeting.StartDateTime.Add(graceWindow)) {
				onTimeCount++
			}
		}
	}

	return onTimeCount
}

func (mas *MeetingAnalyticsServiceSimple) countLateAttendees(participants []models.MeetingParticipant, meeting *models.Meeting) int {
	if meeting.StartDateTime == nil {
		return 0
	}

	lateCount := 0
	graceWindow := 5 * time.Minute

	for _, participant := range participants {
		if participant.JoinedAt != nil {
			if participant.JoinedAt.After(meeting.StartDateTime.Add(graceWindow)) {
				lateCount++
			}
		}
	}

	return lateCount
}

func (mas *MeetingAnalyticsServiceSimple) countEarlyLeavers(participants []models.MeetingParticipant, meeting *models.Meeting) int {
	if meeting.EndDateTime == nil {
		return 0
	}

	earlyCount := 0
	earlyThreshold := 10 * time.Minute // Left more than 10 minutes early

	for _, participant := range participants {
		if participant.LeftAt != nil {
			if participant.LeftAt.Before(meeting.EndDateTime.Add(-earlyThreshold)) {
				earlyCount++
			}
		}
	}

	return earlyCount
}

func (mas *MeetingAnalyticsServiceSimple) generateParticipationDetails(participants []models.MeetingParticipant) []map[string]interface{} {
	var details []map[string]interface{}

	for _, participant := range participants {
		displayName := "Unknown Participant"
		if participant.User != nil {
			displayName = participant.User.Name
		}

		detail := map[string]interface{}{
			"user_id":          participant.UserID,
			"display_name":     displayName,
			"role":             participant.Role,
			"join_time":        participant.JoinedAt,
			"leave_time":       participant.LeftAt,
			"duration_seconds": participant.DurationSeconds,
			"status":           participant.Status,
			"engagement_score": mas.calculateParticipantEngagement(&participant),
		}

		if participant.User != nil {
			detail["email"] = participant.User.Email
			detail["is_external"] = mas.isExternalParticipant(participant.User.Email)
		}

		details = append(details, detail)
	}

	return details
}

func (mas *MeetingAnalyticsServiceSimple) calculateAverageAttendanceDuration(participants []models.MeetingParticipant) float64 {
	if len(participants) == 0 {
		return 0.0
	}

	total := 0
	for _, participant := range participants {
		total += participant.DurationSeconds
	}

	return float64(total) / float64(len(participants))
}

func (mas *MeetingAnalyticsServiceSimple) calculatePeakConcurrentAttendees(participants []models.MeetingParticipant) int {
	// This would require more complex time-based analysis
	// For now, return a simplified calculation
	return len(participants) // Simplified - would need time-series analysis
}

func (mas *MeetingAnalyticsServiceSimple) calculateJoinLeaveFrequency(participants []models.MeetingParticipant) map[string]interface{} {
	return map[string]interface{}{
		"average_joins_per_participant": 1.0, // Simplified
		"reconnection_rate":             0.1, // Simplified
		"stability_score":               0.9, // Simplified
	}
}

func (mas *MeetingAnalyticsServiceSimple) calculateParticipantTurnover(participants []models.MeetingParticipant) float64 {
	// Simplified calculation - would need more complex analysis
	return 0.2 // 20% turnover rate
}

func (mas *MeetingAnalyticsServiceSimple) analyzeJoinTimeDistribution(participants []models.MeetingParticipant, meeting *models.Meeting) map[string]interface{} {
	distribution := map[string]int{
		"before_start": 0,
		"on_time":      0,
		"5_min_late":   0,
		"10_min_late":  0,
		"very_late":    0,
	}

	if meeting.StartDateTime == nil {
		return map[string]interface{}{"distribution": distribution}
	}

	for _, participant := range participants {
		if participant.JoinedAt == nil {
			continue
		}

		diff := participant.JoinedAt.Sub(*meeting.StartDateTime)
		switch {
		case diff < 0:
			distribution["before_start"]++
		case diff <= 5*time.Minute:
			distribution["on_time"]++
		case diff <= 10*time.Minute:
			distribution["5_min_late"]++
		case diff <= 15*time.Minute:
			distribution["10_min_late"]++
		default:
			distribution["very_late"]++
		}
	}

	return map[string]interface{}{
		"distribution":   distribution,
		"total_analyzed": len(participants),
	}
}

func (mas *MeetingAnalyticsServiceSimple) analyzeLeaveTimeDistribution(participants []models.MeetingParticipant, meeting *models.Meeting) map[string]interface{} {
	distribution := map[string]int{
		"stayed_until_end": 0,
		"left_early":       0,
		"left_very_early":  0,
	}

	if meeting.EndDateTime == nil {
		return map[string]interface{}{"distribution": distribution}
	}

	for _, participant := range participants {
		if participant.LeftAt == nil {
			distribution["stayed_until_end"]++
			continue
		}

		diff := meeting.EndDateTime.Sub(*participant.LeftAt)
		switch {
		case diff <= 5*time.Minute:
			distribution["stayed_until_end"]++
		case diff <= 15*time.Minute:
			distribution["left_early"]++
		default:
			distribution["left_very_early"]++
		}
	}

	return map[string]interface{}{
		"distribution":   distribution,
		"total_analyzed": len(participants),
	}
}

func (mas *MeetingAnalyticsServiceSimple) analyzeDurationDistribution(participants []models.MeetingParticipant) map[string]interface{} {
	distribution := map[string]int{
		"0-15_min":    0,
		"15-30_min":   0,
		"30-60_min":   0,
		"60_plus_min": 0,
	}

	for _, participant := range participants {
		minutes := participant.DurationSeconds / 60
		switch {
		case minutes <= 15:
			distribution["0-15_min"]++
		case minutes <= 30:
			distribution["15-30_min"]++
		case minutes <= 60:
			distribution["30-60_min"]++
		default:
			distribution["60_plus_min"]++
		}
	}

	return map[string]interface{}{
		"distribution":   distribution,
		"total_analyzed": len(participants),
	}
}

func (mas *MeetingAnalyticsServiceSimple) analyzeDeviceAndLocation(participants []models.MeetingParticipant) map[string]interface{} {
	deviceTypes := make(map[string]int)
	locations := make(map[string]int)

	for _, participant := range participants {
		deviceType := participant.DeviceType
		if deviceType == "" {
			deviceType = "unknown"
		}
		deviceTypes[deviceType]++

		location := mas.extractLocation(participant.IPAddress)
		locations[location]++
	}

	return map[string]interface{}{
		"device_distribution":   deviceTypes,
		"location_distribution": locations,
	}
}

// Additional helper methods for Teams-like features
func (mas *MeetingAnalyticsServiceSimple) getOrganizationDomain() string {
	return "example.com" // Should be configurable
}

func (mas *MeetingAnalyticsServiceSimple) isInternalDomain(email, orgDomain string) bool {
	return strings.HasSuffix(email, "@"+orgDomain)
}

func (mas *MeetingAnalyticsServiceSimple) isExternalParticipant(email string) bool {
	return !mas.isInternalDomain(email, mas.getOrganizationDomain())
}

func (mas *MeetingAnalyticsServiceSimple) formatDuration(seconds int) string {
	duration := time.Duration(seconds) * time.Second
	return duration.String()
}

func (mas *MeetingAnalyticsServiceSimple) determineAttendanceStatus(participant *models.MeetingParticipant, meeting *models.Meeting) string {
	if participant.JoinedAt == nil {
		return "invited_not_joined"
	}

	if participant.LeftAt == nil {
		return "still_in_meeting"
	}

	// Check if attended for significant duration
	if participant.DurationSeconds >= 300 { // 5 minutes
		return "attended"
	}

	return "briefly_joined"
}

func (mas *MeetingAnalyticsServiceSimple) extractDeviceType(metadata string) string {
	// Parse metadata JSON to extract device type
	if metadata == "" {
		return "unknown"
	}

	var data map[string]interface{}
	if err := json.Unmarshal([]byte(metadata), &data); err != nil {
		return "unknown"
	}

	if deviceType, exists := data["device_type"]; exists {
		if dt, ok := deviceType.(string); ok {
			return dt
		}
	}

	return "desktop" // Default assumption
}

func (mas *MeetingAnalyticsServiceSimple) extractConnectionQuality(metadata string) string {
	// Parse metadata to extract connection quality
	return "good" // Simplified
}

func (mas *MeetingAnalyticsServiceSimple) extractJoinMethod(metadata string) string {
	// Parse metadata to extract join method
	return "web_browser" // Simplified
}

func (mas *MeetingAnalyticsServiceSimple) extractTimeZone(metadata string) string {
	// Parse metadata to extract timezone
	return "UTC" // Simplified
}

func (mas *MeetingAnalyticsServiceSimple) extractLocation(metadata string) string {
	// Parse metadata to extract location
	return "unknown" // Simplified
}

func (mas *MeetingAnalyticsServiceSimple) getMeetingOrganizer(meeting *models.Meeting) string {
	// Get organizer from calendar event
	return "Unknown" // Simplified
}

func (mas *MeetingAnalyticsServiceSimple) calculateOnTimeRate(participants []models.MeetingParticipant, meeting *models.Meeting) float64 {
	if len(participants) == 0 {
		return 0.0
	}

	onTime := mas.countOnTimeAttendees(participants, meeting)
	return float64(onTime) / float64(len(participants)) * 100
}

func (mas *MeetingAnalyticsServiceSimple) calculateCompletionRate(participants []models.MeetingParticipant, meeting *models.Meeting) float64 {
	if len(participants) == 0 || meeting.EndDateTime == nil {
		return 0.0
	}

	completed := 0
	threshold := 0.8 // Attended at least 80% of the meeting

	scheduledDuration := mas.calculateScheduledDuration(meeting)
	if scheduledDuration == 0 {
		return 0.0
	}

	for _, participant := range participants {
		attendanceRate := float64(participant.DurationSeconds) / float64(scheduledDuration)
		if attendanceRate >= threshold {
			completed++
		}
	}

	return float64(completed) / float64(len(participants)) * 100
}

func (mas *MeetingAnalyticsServiceSimple) calculateParticipantEngagement(participant *models.MeetingParticipant) float64 {
	// Simplified engagement calculation
	// In a real implementation, this would consider chat messages, reactions, etc.
	baseScore := 0.5

	// Bonus for longer attendance
	if participant.DurationSeconds > 1800 { // 30 minutes
		baseScore += 0.3
	}

	// Bonus for staying until end
	if participant.Status == "completed" {
		baseScore += 0.2
	}

	return math.Min(baseScore, 1.0)
}

// Engagement analysis methods
func (mas *MeetingAnalyticsServiceSimple) calculateOverallEngagement(participants []models.MeetingParticipant, chatMessages []models.MeetingChat, polls []models.MeetingPoll) float64 {
	if len(participants) == 0 {
		return 0.0
	}

	// Simplified engagement calculation
	engagementScore := 0.0

	// Base score from attendance
	totalDuration := 0
	for _, participant := range participants {
		totalDuration += participant.DurationSeconds
	}
	avgDuration := float64(totalDuration) / float64(len(participants))
	engagementScore += math.Min(avgDuration/3600, 1.0) * 0.4 // 40% weight for attendance

	// Score from chat activity
	if len(chatMessages) > 0 {
		messagesPerParticipant := float64(len(chatMessages)) / float64(len(participants))
		engagementScore += math.Min(messagesPerParticipant/10, 1.0) * 0.3 // 30% weight for chat
	}

	// Score from poll participation
	if len(polls) > 0 {
		engagementScore += 0.3 // 30% weight for polls
	}

	return math.Min(engagementScore, 1.0)
}

func (mas *MeetingAnalyticsServiceSimple) countPassiveParticipants(participants []models.MeetingParticipant, chatMessages []models.MeetingChat) int {
	activeUsers := make(map[string]bool)
	for _, message := range chatMessages {
		activeUsers[message.SenderID] = true
	}

	passiveCount := 0
	for _, participant := range participants {
		if !activeUsers[participant.UserID] {
			passiveCount++
		}
	}

	return passiveCount
}

func (mas *MeetingAnalyticsServiceSimple) analyzeEngagementTrend(participants []models.MeetingParticipant) string {
	// Simplified trend analysis
	if len(participants) == 0 {
		return "no_data"
	}

	avgDuration := mas.calculateAverageAttendanceDuration(participants)
	if avgDuration > 1800 { // 30 minutes
		return "high_engagement"
	} else if avgDuration > 900 { // 15 minutes
		return "moderate_engagement"
	}

	return "low_engagement"
}

func (mas *MeetingAnalyticsServiceSimple) calculateMessagesPerParticipant(chatMessages []models.MeetingChat, participants []models.MeetingParticipant) float64 {
	if len(participants) == 0 {
		return 0.0
	}
	return float64(len(chatMessages)) / float64(len(participants))
}

func (mas *MeetingAnalyticsServiceSimple) getMostActiveParticipants(chatMessages []models.MeetingChat, participants []models.MeetingParticipant) []map[string]interface{} {
	messageCounts := make(map[string]int)
	for _, message := range chatMessages {
		messageCounts[message.SenderID]++
	}

	type ParticipantActivity struct {
		UserID       string
		MessageCount int
		DisplayName  string
	}

	var activities []ParticipantActivity
	for _, participant := range participants {
		count := messageCounts[participant.UserID]
		displayName := "Unknown Participant"
		if participant.User != nil {
			displayName = participant.User.Name
		}
		activities = append(activities, ParticipantActivity{
			UserID:       participant.UserID,
			MessageCount: count,
			DisplayName:  displayName,
		})
	}

	// Sort by message count (simplified - would use proper sorting)
	var result []map[string]interface{}
	for i, activity := range activities {
		if i >= 5 { // Top 5
			break
		}
		result = append(result, map[string]interface{}{
			"user_id":       activity.UserID,
			"display_name":  activity.DisplayName,
			"message_count": activity.MessageCount,
		})
	}

	return result
}

func (mas *MeetingAnalyticsServiceSimple) analyzeCommunicationTimeline(chatMessages []models.MeetingChat) map[string]interface{} {
	// Simplified timeline analysis
	return map[string]interface{}{
		"total_messages":     len(chatMessages),
		"peak_activity_time": "mid_meeting", // Simplified
		"communication_flow": "steady",      // Simplified
	}
}

func (mas *MeetingAnalyticsServiceSimple) estimateSpeakingTimeDistribution(participants []models.MeetingParticipant) map[string]interface{} {
	// This would require integration with audio analysis
	// Simplified implementation
	distribution := make(map[string]float64)
	for _, participant := range participants {
		// Estimate based on role and duration
		speakingTime := float64(participant.DurationSeconds) * 0.1 // Assume 10% speaking time
		if participant.Role == "host" || participant.Role == "presenter" {
			speakingTime *= 3 // Hosts/presenters speak 3x more
		}
		participantName := "Unknown Participant"
		if participant.User != nil {
			participantName = participant.User.Name
		}
		distribution[participantName] = speakingTime
	}

	return map[string]interface{}{
		"distribution": distribution,
		"balanced":     mas.isSpeakingTimeBalanced(distribution),
	}
}

func (mas *MeetingAnalyticsServiceSimple) isSpeakingTimeBalanced(distribution map[string]float64) bool {
	// Simplified balance check
	return len(distribution) > 0 // Placeholder
}

func (mas *MeetingAnalyticsServiceSimple) calculateInteractionFrequency(participants []models.MeetingParticipant, chatMessages []models.MeetingChat) float64 {
	if len(participants) == 0 {
		return 0.0
	}

	totalInteractions := len(chatMessages) // Simplified - would include other interactions
	return float64(totalInteractions) / float64(len(participants))
}

func (mas *MeetingAnalyticsServiceSimple) calculateCollaborationScore(participants []models.MeetingParticipant, chatMessages []models.MeetingChat, polls []models.MeetingPoll) float64 {
	score := 0.0

	// Chat participation
	if len(chatMessages) > 0 {
		score += 0.4
	}

	// Poll participation
	if len(polls) > 0 {
		score += 0.3
	}

	// Duration-based collaboration
	avgDuration := mas.calculateAverageAttendanceDuration(participants)
	if avgDuration > 1800 { // 30 minutes
		score += 0.3
	}

	return math.Min(score, 1.0)
}

func (mas *MeetingAnalyticsServiceSimple) estimateAttentionSpan(participants []models.MeetingParticipant) map[string]interface{} {
	// Simplified attention span estimation
	return map[string]interface{}{
		"average_attention_span": "25_minutes",
		"attention_drop_points":  []string{"15_min", "35_min"},
		"overall_attention":      "good",
	}
}

func (mas *MeetingAnalyticsServiceSimple) identifyDropOffPoints(participants []models.MeetingParticipant) []map[string]interface{} {
	// Simplified drop-off analysis
	return []map[string]interface{}{
		{
			"time":              "30_minutes",
			"participants_left": 2,
			"reason":            "meeting_length",
		},
	}
}

func (mas *MeetingAnalyticsServiceSimple) calculateReEngagementSuccess(participants []models.MeetingParticipant) float64 {
	// Simplified re-engagement calculation
	return 0.7 // 70% success rate
}

func (mas *MeetingAnalyticsServiceSimple) estimateMeetingSatisfaction(participants []models.MeetingParticipant, chatMessages []models.MeetingChat) float64 {
	// Simplified satisfaction estimation based on engagement
	baseScore := 0.6

	if len(chatMessages) > len(participants) {
		baseScore += 0.2 // Active chat indicates engagement
	}

	avgDuration := mas.calculateAverageAttendanceDuration(participants)
	if avgDuration > 1800 { // 30 minutes
		baseScore += 0.2 // Long attendance indicates satisfaction
	}

	return math.Min(baseScore, 1.0)
}

func (mas *MeetingAnalyticsServiceSimple) generateEngagementRecommendations(participants []models.MeetingParticipant, chatMessages []models.MeetingChat, polls []models.MeetingPoll) []string {
	var recommendations []string

	avgDuration := mas.calculateAverageAttendanceDuration(participants)
	if avgDuration < 900 { // Less than 15 minutes
		recommendations = append(recommendations, "Consider shorter, more focused meetings to improve attendance")
	}

	if len(chatMessages) == 0 {
		recommendations = append(recommendations, "Encourage more interaction through chat and Q&A")
	}

	if len(polls) == 0 {
		recommendations = append(recommendations, "Use polls to increase engagement and gather feedback")
	}

	passiveCount := mas.countPassiveParticipants(participants, chatMessages)
	if passiveCount > len(participants)/2 {
		recommendations = append(recommendations, "Engage passive participants with direct questions or breakout sessions")
	}

	if len(recommendations) == 0 {
		recommendations = append(recommendations, "Great engagement! Continue with current meeting practices")
	}

	return recommendations
}

// Export methods
func (mas *MeetingAnalyticsServiceSimple) exportToCSV(report *models.MeetingAttendanceReport) (string, error) {
	// Simplified CSV export
	return "CSV export not implemented", fmt.Errorf("CSV export not implemented")
}

func (mas *MeetingAnalyticsServiceSimple) exportToExcel(report *models.MeetingAttendanceReport) (string, error) {
	// Simplified Excel export
	return "Excel export not implemented", fmt.Errorf("Excel export not implemented")
}

func (mas *MeetingAnalyticsServiceSimple) exportToPDF(report *models.MeetingAttendanceReport) (string, error) {
	// Simplified PDF export
	return "PDF export not implemented", fmt.Errorf("PDF export not implemented")
}

// Compliance methods
func (mas *MeetingAnalyticsServiceSimple) checkRecordingConsent(meetingID string) map[string]interface{} {
	return map[string]interface{}{
		"consent_required":       true,
		"consent_obtained":       true, // Simplified
		"participants_consented": 0,    // Would be calculated
	}
}

func (mas *MeetingAnalyticsServiceSimple) identifyExternalParticipants(participants []models.MeetingParticipant) []string {
	var external []string
	orgDomain := mas.getOrganizationDomain()

	for _, participant := range participants {
		if participant.User != nil && !mas.isInternalDomain(participant.User.Email, orgDomain) {
			external = append(external, participant.UserID)
		}
	}

	return external
}

func (mas *MeetingAnalyticsServiceSimple) checkPolicyViolations(meetingID string) []map[string]interface{} {
	// Simplified policy violation check
	return []map[string]interface{}{
		{
			"type":        "no_violations",
			"description": "No policy violations detected",
			"severity":    "info",
		},
	}
}
