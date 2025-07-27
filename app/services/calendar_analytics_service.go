package services

import (
	"fmt"
	"time"

	"goravel/app/models"

	"github.com/goravel/framework/facades"
)

type CalendarAnalyticsService struct{}

func NewCalendarAnalyticsService() *CalendarAnalyticsService {
	return &CalendarAnalyticsService{}
}

// GetUserAnalytics returns comprehensive analytics for a user's calendar usage
func (cas *CalendarAnalyticsService) GetUserAnalytics(userID string, startDate, endDate time.Time) (map[string]interface{}, error) {
	analytics := make(map[string]interface{})

	// Get basic event statistics
	eventStats, err := cas.getUserEventStats(userID, startDate, endDate)
	if err != nil {
		return nil, err
	}
	analytics["event_stats"] = eventStats

	// Get meeting effectiveness metrics
	meetingMetrics, err := cas.getMeetingEffectivenessMetrics(userID, startDate, endDate)
	if err != nil {
		return nil, err
	}
	analytics["meeting_metrics"] = meetingMetrics

	// Get time distribution analysis
	timeDistribution, err := cas.getTimeDistributionAnalysis(userID, startDate, endDate)
	if err != nil {
		return nil, err
	}
	analytics["time_distribution"] = timeDistribution

	// Get productivity insights
	productivityInsights, err := cas.getProductivityInsights(userID, startDate, endDate)
	if err != nil {
		return nil, err
	}
	analytics["productivity_insights"] = productivityInsights

	// Get collaboration metrics
	collaborationMetrics, err := cas.getCollaborationMetrics(userID, startDate, endDate)
	if err != nil {
		return nil, err
	}
	analytics["collaboration_metrics"] = collaborationMetrics

	return analytics, nil
}

// GetTenantAnalytics returns analytics for an entire tenant/organization
func (cas *CalendarAnalyticsService) GetTenantAnalytics(tenantID string, startDate, endDate time.Time) (map[string]interface{}, error) {
	analytics := make(map[string]interface{})

	// Get tenant overview
	overview, err := cas.getTenantOverview(tenantID, startDate, endDate)
	if err != nil {
		return nil, err
	}
	analytics["overview"] = overview

	// Get department/team analytics
	teamAnalytics, err := cas.getTeamAnalytics(tenantID, startDate, endDate)
	if err != nil {
		return nil, err
	}
	analytics["team_analytics"] = teamAnalytics

	// Get resource utilization
	resourceUtilization, err := cas.getResourceUtilization(tenantID, startDate, endDate)
	if err != nil {
		return nil, err
	}
	analytics["resource_utilization"] = resourceUtilization

	// Get meeting patterns
	meetingPatterns, err := cas.getMeetingPatterns(tenantID, startDate, endDate)
	if err != nil {
		return nil, err
	}
	analytics["meeting_patterns"] = meetingPatterns

	return analytics, nil
}

// getUserEventStats calculates basic event statistics for a user
func (cas *CalendarAnalyticsService) getUserEventStats(userID string, startDate, endDate time.Time) (map[string]interface{}, error) {
	// Total events
	totalEvents, err := facades.Orm().Query().Model(&models.CalendarEvent{}).
		Join("JOIN event_participants ON calendar_events.id = event_participants.event_id").
		Where("event_participants.user_id = ?", userID).
		Where("start_time >= ? AND start_time <= ?", startDate, endDate).
		Count()
	if err != nil {
		return nil, err
	}

	// Events by status
	var eventsByStatus []struct {
		Status string `json:"status"`
		Count  int64  `json:"count"`
	}
	err = facades.Orm().Query().Model(&models.CalendarEvent{}).
		Select("status, COUNT(*) as count").
		Join("JOIN event_participants ON calendar_events.id = event_participants.event_id").
		Where("event_participants.user_id = ?", userID).
		Where("start_time >= ? AND start_time <= ?", startDate, endDate).
		Group("status").
		Scan(&eventsByStatus)
	if err != nil {
		return nil, err
	}

	// Events by type
	var eventsByType []struct {
		Type  string `json:"type"`
		Count int64  `json:"count"`
	}
	err = facades.Orm().Query().Model(&models.CalendarEvent{}).
		Select("type, COUNT(*) as count").
		Join("JOIN event_participants ON calendar_events.id = event_participants.event_id").
		Where("event_participants.user_id = ?", userID).
		Where("start_time >= ? AND start_time <= ?", startDate, endDate).
		Group("type").
		Scan(&eventsByType)
	if err != nil {
		return nil, err
	}

	// Average event duration
	var avgDuration float64
	err = facades.Orm().Query().Model(&models.CalendarEvent{}).
		Select("AVG(EXTRACT(EPOCH FROM (end_time - start_time))/60) as avg_duration").
		Join("JOIN event_participants ON calendar_events.id = event_participants.event_id").
		Where("event_participants.user_id = ?", userID).
		Where("start_time >= ? AND start_time <= ?", startDate, endDate).
		Pluck("avg_duration", &avgDuration)
	if err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"total_events":      totalEvents,
		"events_by_status":  eventsByStatus,
		"events_by_type":    eventsByType,
		"avg_duration_mins": avgDuration,
	}, nil
}

// getMeetingEffectivenessMetrics calculates meeting effectiveness metrics
func (cas *CalendarAnalyticsService) getMeetingEffectivenessMetrics(userID string, startDate, endDate time.Time) (map[string]interface{}, error) {
	// Get meetings with attendance data
	var meetings []models.Meeting
	err := facades.Orm().Query().Model(&models.Meeting{}).
		Join("JOIN calendar_events ON meetings.event_id = calendar_events.id").
		Join("JOIN event_participants ON calendar_events.id = event_participants.event_id").
		Where("event_participants.user_id = ?", userID).
		Where("calendar_events.start_time >= ? AND calendar_events.start_time <= ?", startDate, endDate).
		With("Event").
		Find(&meetings)
	if err != nil {
		return nil, err
	}

	totalMeetings := len(meetings)
	if totalMeetings == 0 {
		return map[string]interface{}{
			"total_meetings":          0,
			"avg_attendance_rate":     0,
			"meetings_with_recording": 0,
			"avg_meeting_duration":    0,
			"on_time_start_rate":      0,
		}, nil
	}

	// Calculate metrics
	var totalAttendanceRate float64
	var meetingsWithRecording int
	var totalDuration float64
	var onTimeStarts int

	for _, meeting := range meetings {
		if meeting.Event != nil {
			// Calculate attendance rate
			var totalParticipants int64
			var attendedParticipants int64

			totalParticipants, _ = facades.Orm().Query().Model(&models.EventParticipant{}).
				Where("event_id = ?", meeting.EventID).Count()

			if totalParticipants > 0 {
				attendedParticipants = int64(meeting.AttendanceCount)
				attendanceRate := float64(attendedParticipants) / float64(totalParticipants)
				totalAttendanceRate += attendanceRate
			}

			// Check if recording exists
			if meeting.RecordingURL != "" {
				meetingsWithRecording++
			}

			// Calculate duration
			duration := meeting.Event.EndTime.Sub(meeting.Event.StartTime).Minutes()
			totalDuration += duration

			// Check on-time start (within 5 minutes of scheduled time)
			if meeting.StartedAt != nil {
				timeDiff := meeting.StartedAt.Sub(meeting.Event.StartTime).Minutes()
				if timeDiff <= 5 && timeDiff >= -5 {
					onTimeStarts++
				}
			}
		}
	}

	avgAttendanceRate := totalAttendanceRate / float64(totalMeetings)
	avgDuration := totalDuration / float64(totalMeetings)
	onTimeRate := float64(onTimeStarts) / float64(totalMeetings)

	return map[string]interface{}{
		"total_meetings":          totalMeetings,
		"avg_attendance_rate":     avgAttendanceRate,
		"meetings_with_recording": meetingsWithRecording,
		"recording_rate":          float64(meetingsWithRecording) / float64(totalMeetings),
		"avg_meeting_duration":    avgDuration,
		"on_time_start_rate":      onTimeRate,
	}, nil
}

// getTimeDistributionAnalysis analyzes how time is distributed across different activities
func (cas *CalendarAnalyticsService) getTimeDistributionAnalysis(userID string, startDate, endDate time.Time) (map[string]interface{}, error) {
	// Get events grouped by hour of day
	var hourlyDistribution []struct {
		Hour  int   `json:"hour"`
		Count int64 `json:"count"`
	}
	err := facades.Orm().Query().Model(&models.CalendarEvent{}).
		Select("EXTRACT(HOUR FROM start_time) as hour, COUNT(*) as count").
		Join("JOIN event_participants ON calendar_events.id = event_participants.event_id").
		Where("event_participants.user_id = ?", userID).
		Where("start_time >= ? AND start_time <= ?", startDate, endDate).
		Group("EXTRACT(HOUR FROM start_time)").
		Order("hour").
		Scan(&hourlyDistribution)
	if err != nil {
		return nil, err
	}

	// Get events grouped by day of week
	var weeklyDistribution []struct {
		DayOfWeek int   `json:"day_of_week"`
		Count     int64 `json:"count"`
	}
	err = facades.Orm().Query().Model(&models.CalendarEvent{}).
		Select("EXTRACT(DOW FROM start_time) as day_of_week, COUNT(*) as count").
		Join("JOIN event_participants ON calendar_events.id = event_participants.event_id").
		Where("event_participants.user_id = ?", userID).
		Where("start_time >= ? AND start_time <= ?", startDate, endDate).
		Group("EXTRACT(DOW FROM start_time)").
		Order("day_of_week").
		Scan(&weeklyDistribution)
	if err != nil {
		return nil, err
	}

	// Calculate time spent by event type
	var timeByType []struct {
		Type         string  `json:"type"`
		TotalMinutes float64 `json:"total_minutes"`
	}
	err = facades.Orm().Query().Model(&models.CalendarEvent{}).
		Select("type, SUM(EXTRACT(EPOCH FROM (end_time - start_time))/60) as total_minutes").
		Join("JOIN event_participants ON calendar_events.id = event_participants.event_id").
		Where("event_participants.user_id = ?", userID).
		Where("start_time >= ? AND start_time <= ?", startDate, endDate).
		Group("type").
		Scan(&timeByType)
	if err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"hourly_distribution": hourlyDistribution,
		"weekly_distribution": weeklyDistribution,
		"time_by_type":        timeByType,
	}, nil
}

// getProductivityInsights provides productivity insights based on calendar data
func (cas *CalendarAnalyticsService) getProductivityInsights(userID string, startDate, endDate time.Time) (map[string]interface{}, error) {
	// Calculate focus time (gaps between meetings)
	var events []models.CalendarEvent
	err := facades.Orm().Query().Model(&models.CalendarEvent{}).
		Join("JOIN event_participants ON calendar_events.id = event_participants.event_id").
		Where("event_participants.user_id = ?", userID).
		Where("start_time >= ? AND start_time <= ?", startDate, endDate).
		Order("start_time").
		Find(&events)
	if err != nil {
		return nil, err
	}

	// Calculate focus time blocks (time between meetings)
	var focusTimeBlocks []time.Duration
	var totalMeetingTime time.Duration

	for i, event := range events {
		meetingDuration := event.EndTime.Sub(event.StartTime)
		totalMeetingTime += meetingDuration

		if i > 0 {
			// Calculate gap between this meeting and the previous one
			gap := event.StartTime.Sub(events[i-1].EndTime)
			if gap > 0 && gap < 4*time.Hour { // Only count reasonable gaps
				focusTimeBlocks = append(focusTimeBlocks, gap)
			}
		}
	}

	// Calculate average focus time
	var totalFocusTime time.Duration
	for _, block := range focusTimeBlocks {
		totalFocusTime += block
	}

	avgFocusTime := time.Duration(0)
	if len(focusTimeBlocks) > 0 {
		avgFocusTime = totalFocusTime / time.Duration(len(focusTimeBlocks))
	}

	// Calculate meeting density (meetings per day)
	daysDiff := endDate.Sub(startDate).Hours() / 24
	meetingDensity := float64(len(events)) / daysDiff

	// Calculate response rate to meeting invitations
	var responseStats struct {
		Total    int64 `json:"total"`
		Accepted int64 `json:"accepted"`
		Declined int64 `json:"declined"`
		Pending  int64 `json:"pending"`
	}

	err = facades.Orm().Query().Model(&models.EventParticipant{}).
		Select("COUNT(*) as total, "+
			"SUM(CASE WHEN response_status = 'accepted' THEN 1 ELSE 0 END) as accepted, "+
			"SUM(CASE WHEN response_status = 'declined' THEN 1 ELSE 0 END) as declined, "+
			"SUM(CASE WHEN response_status = 'pending' THEN 1 ELSE 0 END) as pending").
		Join("JOIN calendar_events ON event_participants.event_id = calendar_events.id").
		Where("event_participants.user_id = ?", userID).
		Where("calendar_events.start_time >= ? AND calendar_events.start_time <= ?", startDate, endDate).
		Scan(&responseStats)
	if err != nil {
		return nil, err
	}

	responseRate := float64(0)
	if responseStats.Total > 0 {
		responseRate = float64(responseStats.Accepted+responseStats.Declined) / float64(responseStats.Total)
	}

	return map[string]interface{}{
		"avg_focus_time_minutes":   avgFocusTime.Minutes(),
		"total_meeting_time_hours": totalMeetingTime.Hours(),
		"focus_blocks_count":       len(focusTimeBlocks),
		"meeting_density_per_day":  meetingDensity,
		"invitation_response_rate": responseRate,
		"response_breakdown":       responseStats,
	}, nil
}

// getCollaborationMetrics analyzes collaboration patterns
func (cas *CalendarAnalyticsService) getCollaborationMetrics(userID string, startDate, endDate time.Time) (map[string]interface{}, error) {
	// Get frequent collaborators
	var collaborators []struct {
		UserID       string `json:"user_id"`
		UserName     string `json:"user_name"`
		MeetingCount int64  `json:"meeting_count"`
	}

	err := facades.Orm().Query().
		Select("u.id as user_id, u.name as user_name, COUNT(*) as meeting_count").
		Table("event_participants ep1").
		Join("JOIN event_participants ep2 ON ep1.event_id = ep2.event_id AND ep1.user_id != ep2.user_id").
		Join("JOIN users u ON ep2.user_id = u.id").
		Join("JOIN calendar_events ce ON ep1.event_id = ce.id").
		Where("ep1.user_id = ?", userID).
		Where("ce.start_time >= ? AND ce.start_time <= ?", startDate, endDate).
		Group("u.id, u.name").
		Order("meeting_count DESC").
		Limit(10).
		Scan(&collaborators)
	if err != nil {
		return nil, err
	}

	// Calculate meeting size distribution
	var meetingSizes []struct {
		ParticipantCount int   `json:"participant_count"`
		MeetingCount     int64 `json:"meeting_count"`
	}

	err = facades.Orm().Query().
		Select("participant_count, COUNT(*) as meeting_count").
		Table("(SELECT event_id, COUNT(*) as participant_count FROM event_participants GROUP BY event_id) as pc").
		Join("JOIN event_participants ep ON pc.event_id = ep.event_id").
		Join("JOIN calendar_events ce ON ep.event_id = ce.id").
		Where("ep.user_id = ?", userID).
		Where("ce.start_time >= ? AND ce.start_time <= ?", startDate, endDate).
		Group("participant_count").
		Order("participant_count").
		Scan(&meetingSizes)
	if err != nil {
		return nil, err
	}

	// Calculate cross-department meetings (if department info is available)
	// This would require additional user/department data

	return map[string]interface{}{
		"frequent_collaborators":    collaborators,
		"meeting_size_distribution": meetingSizes,
	}, nil
}

// getTenantOverview provides high-level tenant analytics
func (cas *CalendarAnalyticsService) getTenantOverview(tenantID string, startDate, endDate time.Time) (map[string]interface{}, error) {
	// Total events in tenant
	totalEvents, err := facades.Orm().Query().Model(&models.CalendarEvent{}).
		Where("tenant_id = ?", tenantID).
		Where("start_time >= ? AND start_time <= ?", startDate, endDate).
		Count()
	if err != nil {
		return nil, err
	}

	// Active users (users who have events)
	activeUsers, err := facades.Orm().Query().
		Select("COUNT(DISTINCT ep.user_id) as count").
		Table("event_participants ep").
		Join("JOIN calendar_events ce ON ep.event_id = ce.id").
		Where("ce.tenant_id = ?", tenantID).
		Where("ce.start_time >= ? AND ce.start_time <= ?", startDate, endDate).
		Count()
	if err != nil {
		return nil, err
	}

	// Total meeting hours
	var totalHours float64
	err = facades.Orm().Query().Model(&models.CalendarEvent{}).
		Select("SUM(EXTRACT(EPOCH FROM (end_time - start_time))/3600) as total_hours").
		Where("tenant_id = ?", tenantID).
		Where("start_time >= ? AND start_time <= ?", startDate, endDate).
		Pluck("total_hours", &totalHours)
	if err != nil {
		return nil, err
	}

	// Most popular meeting times
	var popularTimes []struct {
		Hour  int   `json:"hour"`
		Count int64 `json:"count"`
	}
	err = facades.Orm().Query().Model(&models.CalendarEvent{}).
		Select("EXTRACT(HOUR FROM start_time) as hour, COUNT(*) as count").
		Where("tenant_id = ?", tenantID).
		Where("start_time >= ? AND start_time <= ?", startDate, endDate).
		Group("EXTRACT(HOUR FROM start_time)").
		Order("count DESC").
		Limit(5).
		Scan(&popularTimes)
	if err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"total_events":       totalEvents,
		"active_users":       activeUsers,
		"total_hours":        totalHours,
		"popular_times":      popularTimes,
		"avg_hours_per_user": totalHours / float64(activeUsers),
	}, nil
}

// getTeamAnalytics provides team-level analytics (placeholder for future implementation)
func (cas *CalendarAnalyticsService) getTeamAnalytics(tenantID string, startDate, endDate time.Time) (map[string]interface{}, error) {
	// This would require team/department structure in the database
	// For now, return basic structure
	return map[string]interface{}{
		"teams": []map[string]interface{}{},
		"note":  "Team analytics require department/team structure to be implemented",
	}, nil
}

// getResourceUtilization analyzes meeting room and resource usage
func (cas *CalendarAnalyticsService) getResourceUtilization(tenantID string, startDate, endDate time.Time) (map[string]interface{}, error) {
	// Get location usage statistics
	var locationUsage []struct {
		Location string  `json:"location"`
		Count    int64   `json:"count"`
		Hours    float64 `json:"hours"`
	}

	err := facades.Orm().Query().Model(&models.CalendarEvent{}).
		Select("location, COUNT(*) as count, SUM(EXTRACT(EPOCH FROM (end_time - start_time))/3600) as hours").
		Where("tenant_id = ?", tenantID).
		Where("start_time >= ? AND start_time <= ?", startDate, endDate).
		Where("location != ''").
		Group("location").
		Order("count DESC").
		Limit(10).
		Scan(&locationUsage)
	if err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"location_usage": locationUsage,
	}, nil
}

// getMeetingPatterns analyzes meeting patterns and trends
func (cas *CalendarAnalyticsService) getMeetingPatterns(tenantID string, startDate, endDate time.Time) (map[string]interface{}, error) {
	// Get daily meeting counts
	var dailyPattern []struct {
		Date  string `json:"date"`
		Count int64  `json:"count"`
	}

	err := facades.Orm().Query().Model(&models.CalendarEvent{}).
		Select("DATE(start_time) as date, COUNT(*) as count").
		Where("tenant_id = ?", tenantID).
		Where("start_time >= ? AND start_time <= ?", startDate, endDate).
		Group("DATE(start_time)").
		Order("date").
		Scan(&dailyPattern)
	if err != nil {
		return nil, err
	}

	// Get recurring vs one-time events
	var eventTypes struct {
		Recurring int64 `json:"recurring"`
		OneTime   int64 `json:"one_time"`
	}

	err = facades.Orm().Query().Model(&models.CalendarEvent{}).
		Select("SUM(CASE WHEN is_recurring = true THEN 1 ELSE 0 END) as recurring, "+
			"SUM(CASE WHEN is_recurring = false THEN 1 ELSE 0 END) as one_time").
		Where("tenant_id = ?", tenantID).
		Where("start_time >= ? AND start_time <= ?", startDate, endDate).
		Scan(&eventTypes)
	if err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"daily_pattern": dailyPattern,
		"event_types":   eventTypes,
	}, nil
}

// GenerateCalendarReport generates a comprehensive calendar report
func (cas *CalendarAnalyticsService) GenerateCalendarReport(reportType string, targetID string, startDate, endDate time.Time) (map[string]interface{}, error) {
	report := map[string]interface{}{
		"report_type":  reportType,
		"target_id":    targetID,
		"period_start": startDate,
		"period_end":   endDate,
		"generated_at": time.Now(),
	}

	switch reportType {
	case "user":
		analytics, err := cas.GetUserAnalytics(targetID, startDate, endDate)
		if err != nil {
			return nil, err
		}
		report["analytics"] = analytics

	case "tenant":
		analytics, err := cas.GetTenantAnalytics(targetID, startDate, endDate)
		if err != nil {
			return nil, err
		}
		report["analytics"] = analytics

	default:
		return nil, fmt.Errorf("unsupported report type: %s", reportType)
	}

	return report, nil
}
