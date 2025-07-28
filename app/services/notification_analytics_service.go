package services

import (
	"fmt"
	"goravel/app/models"
	"time"

	"github.com/goravel/framework/facades"
)

// NotificationAnalyticsService handles notification analytics and metrics
type NotificationAnalyticsService struct{}

// NewNotificationAnalyticsService creates a new notification analytics service
func NewNotificationAnalyticsService() *NotificationAnalyticsService {
	return &NotificationAnalyticsService{}
}

// NotificationMetrics holds notification metrics data
type NotificationMetrics struct {
	TotalSent       int64   `json:"total_sent"`
	TotalDelivered  int64   `json:"total_delivered"`
	TotalRead       int64   `json:"total_read"`
	TotalFailed     int64   `json:"total_failed"`
	DeliveryRate    float64 `json:"delivery_rate"`
	ReadRate        float64 `json:"read_rate"`
	FailureRate     float64 `json:"failure_rate"`
	AvgDeliveryTime float64 `json:"avg_delivery_time_seconds"`
	AvgReadTime     float64 `json:"avg_read_time_seconds"`
}

// ChannelMetrics holds channel-specific metrics
type ChannelMetrics struct {
	Channel     string  `json:"channel"`
	TotalSent   int64   `json:"total_sent"`
	TotalFailed int64   `json:"total_failed"`
	SuccessRate float64 `json:"success_rate"`
	AvgTime     float64 `json:"avg_delivery_time_seconds"`
}

// NotificationTypeMetrics holds notification type specific metrics
type NotificationTypeMetrics struct {
	Type        string  `json:"type"`
	TotalSent   int64   `json:"total_sent"`
	TotalRead   int64   `json:"total_read"`
	ReadRate    float64 `json:"read_rate"`
	AvgReadTime float64 `json:"avg_read_time_seconds"`
}

// UserEngagementMetrics holds user engagement metrics
type UserEngagementMetrics struct {
	UserID              string     `json:"user_id"`
	TotalReceived       int64      `json:"total_received"`
	TotalRead           int64      `json:"total_read"`
	ReadRate            float64    `json:"read_rate"`
	AvgReadTime         float64    `json:"avg_read_time_seconds"`
	PreferredChannels   []string   `json:"preferred_channels"`
	MostActiveHour      int        `json:"most_active_hour"`
	LastInteractionTime *time.Time `json:"last_interaction_time"`
}

// GetOverallMetrics returns overall notification metrics
func (s *NotificationAnalyticsService) GetOverallMetrics(startDate, endDate time.Time) (*NotificationMetrics, error) {
	var metrics NotificationMetrics

	// Get total counts
	query := facades.Orm().Query().Model(&models.Notification{}).
		Where("created_at >= ?", startDate).
		Where("created_at <= ?", endDate)

	// Total sent
	totalSent, err := query.Count()
	if err != nil {
		return nil, fmt.Errorf("failed to get total sent count: %w", err)
	}
	metrics.TotalSent = totalSent

	// Total delivered
	totalDelivered, err := query.Where("delivery_status IN ?", []string{"delivered", "read"}).Count()
	if err != nil {
		return nil, fmt.Errorf("failed to get total delivered count: %w", err)
	}
	metrics.TotalDelivered = totalDelivered

	// Total read
	totalRead, err := query.Where("read_at IS NOT NULL").Count()
	if err != nil {
		return nil, fmt.Errorf("failed to get total read count: %w", err)
	}
	metrics.TotalRead = totalRead

	// Total failed
	totalFailed, err := query.Where("delivery_status = ?", "failed").Count()
	if err != nil {
		return nil, fmt.Errorf("failed to get total failed count: %w", err)
	}
	metrics.TotalFailed = totalFailed

	// Calculate rates
	if metrics.TotalSent > 0 {
		metrics.DeliveryRate = float64(metrics.TotalDelivered) / float64(metrics.TotalSent) * 100
		metrics.FailureRate = float64(metrics.TotalFailed) / float64(metrics.TotalSent) * 100
	}

	if metrics.TotalDelivered > 0 {
		metrics.ReadRate = float64(metrics.TotalRead) / float64(metrics.TotalDelivered) * 100
	}

	// Calculate average delivery time
	metrics.AvgDeliveryTime = s.calculateAverageDeliveryTime(startDate, endDate)

	// Calculate average read time
	metrics.AvgReadTime = s.calculateAverageReadTime(startDate, endDate)

	return &metrics, nil
}

// GetChannelMetrics returns metrics broken down by channel
func (s *NotificationAnalyticsService) GetChannelMetrics(startDate, endDate time.Time) ([]ChannelMetrics, error) {
	var results []struct {
		Channel     string `json:"channel"`
		TotalSent   int64  `json:"total_sent"`
		TotalFailed int64  `json:"total_failed"`
	}

	err := facades.Orm().Query().Model(&models.Notification{}).
		Select("channel, COUNT(*) as total_sent, SUM(CASE WHEN delivery_status = 'failed' THEN 1 ELSE 0 END) as total_failed").
		Where("created_at >= ?", startDate).
		Where("created_at <= ?", endDate).
		Group("channel").
		Find(&results)

	if err != nil {
		return nil, fmt.Errorf("failed to get channel metrics: %w", err)
	}

	var metrics []ChannelMetrics
	for _, result := range results {
		channelMetric := ChannelMetrics{
			Channel:     result.Channel,
			TotalSent:   result.TotalSent,
			TotalFailed: result.TotalFailed,
		}

		if result.TotalSent > 0 {
			channelMetric.SuccessRate = float64(result.TotalSent-result.TotalFailed) / float64(result.TotalSent) * 100
		}

		channelMetric.AvgTime = s.calculateChannelAverageTime(result.Channel, startDate, endDate)
		metrics = append(metrics, channelMetric)
	}

	return metrics, nil
}

// GetNotificationTypeMetrics returns metrics broken down by notification type
func (s *NotificationAnalyticsService) GetNotificationTypeMetrics(startDate, endDate time.Time) ([]NotificationTypeMetrics, error) {
	var results []struct {
		Type      string `json:"type"`
		TotalSent int64  `json:"total_sent"`
		TotalRead int64  `json:"total_read"`
	}

	err := facades.Orm().Query().Model(&models.Notification{}).
		Select("type, COUNT(*) as total_sent, SUM(CASE WHEN read_at IS NOT NULL THEN 1 ELSE 0 END) as total_read").
		Where("created_at >= ?", startDate).
		Where("created_at <= ?", endDate).
		Group("type").
		Find(&results)

	if err != nil {
		return nil, fmt.Errorf("failed to get notification type metrics: %w", err)
	}

	var metrics []NotificationTypeMetrics
	for _, result := range results {
		typeMetric := NotificationTypeMetrics{
			Type:      result.Type,
			TotalSent: result.TotalSent,
			TotalRead: result.TotalRead,
		}

		if result.TotalSent > 0 {
			typeMetric.ReadRate = float64(result.TotalRead) / float64(result.TotalSent) * 100
		}

		typeMetric.AvgReadTime = s.calculateTypeAverageReadTime(result.Type, startDate, endDate)
		metrics = append(metrics, typeMetric)
	}

	return metrics, nil
}

// GetUserEngagementMetrics returns user engagement metrics
func (s *NotificationAnalyticsService) GetUserEngagementMetrics(userID string, startDate, endDate time.Time) (*UserEngagementMetrics, error) {
	metrics := &UserEngagementMetrics{
		UserID: userID,
	}

	query := facades.Orm().Query().Model(&models.Notification{}).
		Where("notifiable_id = ?", userID).
		Where("created_at >= ?", startDate).
		Where("created_at <= ?", endDate)

	// Total received
	totalReceived, err := query.Count()
	if err != nil {
		return nil, fmt.Errorf("failed to get total received count: %w", err)
	}
	metrics.TotalReceived = totalReceived

	// Total read
	totalRead, err := query.Where("read_at IS NOT NULL").Count()
	if err != nil {
		return nil, fmt.Errorf("failed to get total read count: %w", err)
	}
	metrics.TotalRead = totalRead

	// Calculate read rate
	if metrics.TotalReceived > 0 {
		metrics.ReadRate = float64(metrics.TotalRead) / float64(metrics.TotalReceived) * 100
	}

	// Calculate average read time
	metrics.AvgReadTime = s.calculateUserAverageReadTime(userID, startDate, endDate)

	// Get preferred channels
	metrics.PreferredChannels = s.getUserPreferredChannels(userID, startDate, endDate)

	// Get most active hour
	metrics.MostActiveHour = s.getUserMostActiveHour(userID, startDate, endDate)

	// Get last interaction time
	metrics.LastInteractionTime = s.getUserLastInteractionTime(userID)

	return metrics, nil
}

// GetDailyMetrics returns daily notification metrics for a date range
func (s *NotificationAnalyticsService) GetDailyMetrics(startDate, endDate time.Time) (map[string]*NotificationMetrics, error) {
	dailyMetrics := make(map[string]*NotificationMetrics)

	// Iterate through each day in the range
	for d := startDate; d.Before(endDate) || d.Equal(endDate); d = d.AddDate(0, 0, 1) {
		dayStart := time.Date(d.Year(), d.Month(), d.Day(), 0, 0, 0, 0, d.Location())
		dayEnd := dayStart.AddDate(0, 0, 1).Add(-time.Nanosecond)

		metrics, err := s.GetOverallMetrics(dayStart, dayEnd)
		if err != nil {
			facades.Log().Warning("Failed to get daily metrics", map[string]interface{}{
				"date":  d.Format("2006-01-02"),
				"error": err.Error(),
			})
			continue
		}

		dailyMetrics[d.Format("2006-01-02")] = metrics
	}

	return dailyMetrics, nil
}

// GetTopPerformingNotifications returns the top performing notification types
func (s *NotificationAnalyticsService) GetTopPerformingNotifications(startDate, endDate time.Time, limit int) ([]NotificationTypeMetrics, error) {
	metrics, err := s.GetNotificationTypeMetrics(startDate, endDate)
	if err != nil {
		return nil, err
	}

	// Sort by read rate
	for i := 0; i < len(metrics)-1; i++ {
		for j := i + 1; j < len(metrics); j++ {
			if metrics[i].ReadRate < metrics[j].ReadRate {
				metrics[i], metrics[j] = metrics[j], metrics[i]
			}
		}
	}

	// Return top N
	if len(metrics) > limit {
		metrics = metrics[:limit]
	}

	return metrics, nil
}

// calculateAverageDeliveryTime calculates average time from creation to delivery
func (s *NotificationAnalyticsService) calculateAverageDeliveryTime(startDate, endDate time.Time) float64 {
	var result struct {
		AvgSeconds float64 `json:"avg_seconds"`
	}

	err := facades.Orm().Query().Model(&models.Notification{}).
		Select("AVG(EXTRACT(EPOCH FROM (delivered_at - created_at))) as avg_seconds").
		Where("created_at >= ?", startDate).
		Where("created_at <= ?", endDate).
		Where("delivered_at IS NOT NULL").
		First(&result)

	if err != nil {
		return 0
	}

	return result.AvgSeconds
}

// calculateAverageReadTime calculates average time from delivery to read
func (s *NotificationAnalyticsService) calculateAverageReadTime(startDate, endDate time.Time) float64 {
	var result struct {
		AvgSeconds float64 `json:"avg_seconds"`
	}

	err := facades.Orm().Query().Model(&models.Notification{}).
		Select("AVG(EXTRACT(EPOCH FROM (read_at - delivered_at))) as avg_seconds").
		Where("created_at >= ?", startDate).
		Where("created_at <= ?", endDate).
		Where("read_at IS NOT NULL").
		Where("delivered_at IS NOT NULL").
		First(&result)

	if err != nil {
		return 0
	}

	return result.AvgSeconds
}

// calculateChannelAverageTime calculates average delivery time for a specific channel
func (s *NotificationAnalyticsService) calculateChannelAverageTime(channel string, startDate, endDate time.Time) float64 {
	var result struct {
		AvgSeconds float64 `json:"avg_seconds"`
	}

	err := facades.Orm().Query().Model(&models.Notification{}).
		Select("AVG(EXTRACT(EPOCH FROM (delivered_at - created_at))) as avg_seconds").
		Where("channel = ?", channel).
		Where("created_at >= ?", startDate).
		Where("created_at <= ?", endDate).
		Where("delivered_at IS NOT NULL").
		First(&result)

	if err != nil {
		return 0
	}

	return result.AvgSeconds
}

// calculateTypeAverageReadTime calculates average read time for a notification type
func (s *NotificationAnalyticsService) calculateTypeAverageReadTime(notificationType string, startDate, endDate time.Time) float64 {
	var result struct {
		AvgSeconds float64 `json:"avg_seconds"`
	}

	err := facades.Orm().Query().Model(&models.Notification{}).
		Select("AVG(EXTRACT(EPOCH FROM (read_at - delivered_at))) as avg_seconds").
		Where("type = ?", notificationType).
		Where("created_at >= ?", startDate).
		Where("created_at <= ?", endDate).
		Where("read_at IS NOT NULL").
		Where("delivered_at IS NOT NULL").
		First(&result)

	if err != nil {
		return 0
	}

	return result.AvgSeconds
}

// calculateUserAverageReadTime calculates average read time for a user
func (s *NotificationAnalyticsService) calculateUserAverageReadTime(userID string, startDate, endDate time.Time) float64 {
	var result struct {
		AvgSeconds float64 `json:"avg_seconds"`
	}

	err := facades.Orm().Query().Model(&models.Notification{}).
		Select("AVG(EXTRACT(EPOCH FROM (read_at - delivered_at))) as avg_seconds").
		Where("notifiable_id = ?", userID).
		Where("created_at >= ?", startDate).
		Where("created_at <= ?", endDate).
		Where("read_at IS NOT NULL").
		Where("delivered_at IS NOT NULL").
		First(&result)

	if err != nil {
		return 0
	}

	return result.AvgSeconds
}

// getUserPreferredChannels gets the user's most used channels
func (s *NotificationAnalyticsService) getUserPreferredChannels(userID string, startDate, endDate time.Time) []string {
	var results []struct {
		Channel string `json:"channel"`
		Count   int64  `json:"count"`
	}

	err := facades.Orm().Query().Model(&models.Notification{}).
		Select("channel, COUNT(*) as count").
		Where("notifiable_id = ?", userID).
		Where("created_at >= ?", startDate).
		Where("created_at <= ?", endDate).
		Group("channel").
		OrderBy("count DESC").
		Limit(3).
		Find(&results)

	if err != nil {
		return []string{}
	}

	var channels []string
	for _, result := range results {
		channels = append(channels, result.Channel)
	}

	return channels
}

// getUserMostActiveHour gets the hour when user is most active (reads most notifications)
func (s *NotificationAnalyticsService) getUserMostActiveHour(userID string, startDate, endDate time.Time) int {
	var result struct {
		Hour int `json:"hour"`
	}

	err := facades.Orm().Query().Model(&models.Notification{}).
		Select("EXTRACT(HOUR FROM read_at) as hour").
		Where("notifiable_id = ?", userID).
		Where("created_at >= ?", startDate).
		Where("created_at <= ?", endDate).
		Where("read_at IS NOT NULL").
		Group("EXTRACT(HOUR FROM read_at)").
		OrderBy("COUNT(*) DESC").
		First(&result)

	if err != nil {
		return 12 // Default to noon
	}

	return result.Hour
}

// getUserLastInteractionTime gets the user's last notification interaction
func (s *NotificationAnalyticsService) getUserLastInteractionTime(userID string) *time.Time {
	var notification models.Notification

	err := facades.Orm().Query().Model(&models.Notification{}).
		Where("notifiable_id = ?", userID).
		Where("read_at IS NOT NULL").
		OrderBy("read_at DESC").
		First(&notification)

	if err != nil {
		return nil
	}

	return notification.ReadAt
}

// RecordNotificationEvent records a notification event for analytics
func (s *NotificationAnalyticsService) RecordNotificationEvent(notificationID, eventType string, metadata map[string]interface{}) error {
	// Store analytics event in cache for real-time processing
	analyticsKey := fmt.Sprintf("notification_analytics:%s:%s", eventType, time.Now().Format("2006-01-02"))

	// Create analytics event data
	eventData := map[string]interface{}{
		"notification_id": notificationID,
		"event_type":      eventType,
		"metadata":        metadata,
		"timestamp":       time.Now().Unix(),
		"date":            time.Now().Format("2006-01-02"),
		"hour":            time.Now().Hour(),
	}

	// Store in cache for aggregation
	cacheData := facades.Cache().Get(analyticsKey)
	var events []map[string]interface{}

	if cacheData != nil {
		if existingEvents, ok := cacheData.([]map[string]interface{}); ok {
			events = existingEvents
		}
	}

	events = append(events, eventData)

	// Store back in cache with 24-hour expiry
	if err := facades.Cache().Put(analyticsKey, events, 24*time.Hour); err != nil {
		facades.Log().Error("Failed to cache notification analytics event", map[string]interface{}{
			"key":   analyticsKey,
			"error": err.Error(),
		})
	}

	// Also increment counters for quick metrics
	counterKey := fmt.Sprintf("notification_counter:%s:%s", eventType, time.Now().Format("2006-01-02"))
	currentCount := facades.Cache().GetInt(counterKey, 0)
	facades.Cache().Put(counterKey, currentCount+1, 24*time.Hour)

	// Log the event for immediate visibility
	facades.Log().Info("Notification analytics event recorded", map[string]interface{}{
		"notification_id": notificationID,
		"event_type":      eventType,
		"metadata":        metadata,
		"timestamp":       time.Now(),
		"analytics_key":   analyticsKey,
	})

	return nil
}

// GenerateReport generates a comprehensive notification report
func (s *NotificationAnalyticsService) GenerateReport(startDate, endDate time.Time) (map[string]interface{}, error) {
	report := make(map[string]interface{})

	// Overall metrics
	overallMetrics, err := s.GetOverallMetrics(startDate, endDate)
	if err != nil {
		return nil, fmt.Errorf("failed to get overall metrics: %w", err)
	}
	report["overall"] = overallMetrics

	// Channel metrics
	channelMetrics, err := s.GetChannelMetrics(startDate, endDate)
	if err != nil {
		return nil, fmt.Errorf("failed to get channel metrics: %w", err)
	}
	report["channels"] = channelMetrics

	// Notification type metrics
	typeMetrics, err := s.GetNotificationTypeMetrics(startDate, endDate)
	if err != nil {
		return nil, fmt.Errorf("failed to get notification type metrics: %w", err)
	}
	report["types"] = typeMetrics

	// Top performing notifications
	topPerforming, err := s.GetTopPerformingNotifications(startDate, endDate, 5)
	if err != nil {
		return nil, fmt.Errorf("failed to get top performing notifications: %w", err)
	}
	report["top_performing"] = topPerforming

	// Daily metrics
	dailyMetrics, err := s.GetDailyMetrics(startDate, endDate)
	if err != nil {
		return nil, fmt.Errorf("failed to get daily metrics: %w", err)
	}
	report["daily"] = dailyMetrics

	// Report metadata
	report["generated_at"] = time.Now()
	report["period"] = map[string]interface{}{
		"start": startDate,
		"end":   endDate,
		"days":  int(endDate.Sub(startDate).Hours() / 24),
	}

	return report, nil
}
