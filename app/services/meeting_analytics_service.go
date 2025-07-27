package services

import (
	"fmt"
	"goravel/app/models"
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
