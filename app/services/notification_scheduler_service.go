package services

import (
	"context"
	"fmt"
	"time"

	"goravel/app/helpers"
	"goravel/app/models"
	"goravel/app/notificationcore"
	"goravel/app/notifications"

	"github.com/goravel/framework/facades"
)

// NotificationSchedulerService handles scheduling notifications
type NotificationSchedulerService struct {
	notificationService *NotificationService
}

// NewNotificationSchedulerService creates a new scheduler service
func NewNotificationSchedulerService() *NotificationSchedulerService {
	return &NotificationSchedulerService{
		notificationService: NewNotificationService(),
	}
}

// ScheduledNotificationModel represents a scheduled notification in the database
type ScheduledNotificationModel struct {
	models.BaseModel
	ID               string                 `json:"id" gorm:"primaryKey"`
	NotificationType string                 `json:"notification_type" gorm:"not null"`
	NotificationData map[string]interface{} `json:"notification_data" gorm:"type:json"`
	NotifiableID     string                 `json:"notifiable_id" gorm:"not null"`
	NotifiableType   string                 `json:"notifiable_type" gorm:"not null"`
	ScheduledAt      time.Time              `json:"scheduled_at" gorm:"not null"`
	Status           string                 `json:"status" gorm:"default:pending"` // pending, sent, cancelled, failed
	ProcessedAt      *time.Time             `json:"processed_at"`
	FailureReason    *string                `json:"failure_reason"`
	Attempts         int                    `json:"attempts" gorm:"default:0"`
	MaxAttempts      int                    `json:"max_attempts" gorm:"default:3"`

	// Recurring notification fields
	IsRecurring        bool       `json:"is_recurring" gorm:"default:false"`
	RecurrencePattern  string     `json:"recurrence_pattern"` // daily, weekly, monthly, yearly, custom
	RecurrenceInterval int        `json:"recurrence_interval" gorm:"default:1"`
	RecurrenceEnd      *time.Time `json:"recurrence_end"`
	NextScheduledAt    *time.Time `json:"next_scheduled_at"`

	// Time zone and localization
	TimeZone string `json:"timezone" gorm:"default:UTC"`
	Locale   string `json:"locale" gorm:"default:en"`

	// Metadata
	Metadata map[string]interface{} `json:"metadata" gorm:"type:json"`
}

// TableName specifies the table name
func (s *ScheduledNotificationModel) TableName() string {
	return "scheduled_notifications"
}

// Schedule schedules a notification for later delivery
func (s *NotificationSchedulerService) Schedule(ctx context.Context, notification notificationcore.Notification, notifiable notificationcore.Notifiable, scheduledAt time.Time) (string, error) {
	// Serialize notification data
	notificationData := map[string]interface{}{
		"type":        notification.GetType(),
		"data":        notification.GetData(),
		"template":    notification.GetTemplate(),
		"subject":     notification.GetSubject(),
		"title":       notification.GetTitle(),
		"body":        notification.GetBody(),
		"action_url":  notification.GetActionURL(),
		"action_text": notification.GetActionText(),
		"icon":        notification.GetIcon(),
		"color":       notification.GetColor(),
		"image_url":   notification.GetImageURL(),
		"sound":       notification.GetSound(),
		"channels":    notification.GetChannels(),
		"priority":    notification.GetPriority(),
		"category":    notification.GetCategory(),
		"tags":        notification.GetTags(),
		"metadata":    notification.GetMetadata(),
	}

	// Create scheduled notification record
	scheduledNotification := &ScheduledNotificationModel{
		ID:               helpers.GenerateULID(),
		NotificationType: notification.GetType(),
		NotificationData: notificationData,
		NotifiableID:     notifiable.GetID(),
		NotifiableType:   notifiable.GetType(),
		ScheduledAt:      scheduledAt,
		Status:           "pending",
		TimeZone:         notifiable.GetTimezone(),
		Locale:           notifiable.GetLocale(),
		Metadata:         notification.GetMetadata(),
	}

	// Set retry policy
	retryPolicy := notification.GetRetryPolicy()
	scheduledNotification.MaxAttempts = retryPolicy.MaxAttempts

	// Save to database
	if err := facades.Orm().Query().Create(scheduledNotification); err != nil {
		return "", fmt.Errorf("failed to schedule notification: %w", err)
	}

	facades.Log().Info("Notification scheduled", map[string]interface{}{
		"schedule_id":       scheduledNotification.ID,
		"notification_type": notification.GetType(),
		"notifiable_id":     notifiable.GetID(),
		"scheduled_at":      scheduledAt,
	})

	return scheduledNotification.ID, nil
}

// ScheduleRecurring schedules a recurring notification
func (s *NotificationSchedulerService) ScheduleRecurring(ctx context.Context, notification notificationcore.Notification, notifiable notificationcore.Notifiable, firstScheduledAt time.Time, pattern string, interval int, endAt *time.Time) (string, error) {
	scheduleID, err := s.Schedule(ctx, notification, notifiable, firstScheduledAt)
	if err != nil {
		return "", err
	}

	// Update the record to mark it as recurring
	var scheduledNotification ScheduledNotificationModel
	if err := facades.Orm().Query().Where("id = ?", scheduleID).First(&scheduledNotification); err != nil {
		return "", fmt.Errorf("failed to find scheduled notification: %w", err)
	}

	scheduledNotification.IsRecurring = true
	scheduledNotification.RecurrencePattern = pattern
	scheduledNotification.RecurrenceInterval = interval
	scheduledNotification.RecurrenceEnd = endAt
	scheduledNotification.NextScheduledAt = s.calculateNextScheduledTime(firstScheduledAt, pattern, interval)

	if err := facades.Orm().Query().Save(&scheduledNotification); err != nil {
		return "", fmt.Errorf("failed to update recurring notification: %w", err)
	}

	facades.Log().Info("Recurring notification scheduled", map[string]interface{}{
		"schedule_id":        scheduleID,
		"notification_type":  notification.GetType(),
		"pattern":            pattern,
		"interval":           interval,
		"first_scheduled_at": firstScheduledAt,
		"end_at":             endAt,
	})

	return scheduleID, nil
}

// Cancel cancels a scheduled notification
func (s *NotificationSchedulerService) Cancel(scheduleID string) error {
	var scheduledNotification ScheduledNotificationModel
	if err := facades.Orm().Query().Where("id = ?", scheduleID).First(&scheduledNotification); err != nil {
		return fmt.Errorf("scheduled notification not found: %w", err)
	}

	if scheduledNotification.Status != "pending" {
		return fmt.Errorf("cannot cancel notification with status: %s", scheduledNotification.Status)
	}

	scheduledNotification.Status = "cancelled"
	now := time.Now()
	scheduledNotification.ProcessedAt = &now

	if err := facades.Orm().Query().Save(&scheduledNotification); err != nil {
		return fmt.Errorf("failed to cancel notification: %w", err)
	}

	facades.Log().Info("Notification cancelled", map[string]interface{}{
		"schedule_id": scheduleID,
	})

	return nil
}

// Update updates the scheduled time of a notification
func (s *NotificationSchedulerService) Update(scheduleID string, scheduledAt time.Time) error {
	var scheduledNotification ScheduledNotificationModel
	if err := facades.Orm().Query().Where("id = ?", scheduleID).First(&scheduledNotification); err != nil {
		return fmt.Errorf("scheduled notification not found: %w", err)
	}

	if scheduledNotification.Status != "pending" {
		return fmt.Errorf("cannot update notification with status: %s", scheduledNotification.Status)
	}

	scheduledNotification.ScheduledAt = scheduledAt

	// Update next scheduled time for recurring notifications
	if scheduledNotification.IsRecurring {
		scheduledNotification.NextScheduledAt = s.calculateNextScheduledTime(
			scheduledAt,
			scheduledNotification.RecurrencePattern,
			scheduledNotification.RecurrenceInterval,
		)
	}

	if err := facades.Orm().Query().Save(&scheduledNotification); err != nil {
		return fmt.Errorf("failed to update notification: %w", err)
	}

	facades.Log().Info("Scheduled notification updated", map[string]interface{}{
		"schedule_id":  scheduleID,
		"scheduled_at": scheduledAt,
	})

	return nil
}

// GetScheduled returns scheduled notifications for a notifiable
func (s *NotificationSchedulerService) GetScheduled(notifiableID string) ([]notificationcore.ScheduledNotification, error) {
	var scheduledNotifications []ScheduledNotificationModel

	err := facades.Orm().Query().
		Where("notifiable_id = ?", notifiableID).
		Where("status = ?", "pending").
		OrderBy("scheduled_at ASC").
		Find(&scheduledNotifications)

	if err != nil {
		return nil, fmt.Errorf("failed to get scheduled notifications: %w", err)
	}

	var result []notificationcore.ScheduledNotification
	for _, sn := range scheduledNotifications {
		result = append(result, notificationcore.ScheduledNotification{
			ID:          sn.ID,
			ScheduledAt: sn.ScheduledAt,
			Status:      sn.Status,
			CreatedAt:   sn.CreatedAt,
			UpdatedAt:   sn.UpdatedAt,
		})
	}

	return result, nil
}

// ProcessDue processes all due notifications
func (s *NotificationSchedulerService) ProcessDue(ctx context.Context) error {
	now := time.Now()

	// Get all pending notifications that are due
	var dueNotifications []ScheduledNotificationModel
	err := facades.Orm().Query().
		Where("status = ?", "pending").
		Where("scheduled_at <= ?", now).
		Find(&dueNotifications)

	if err != nil {
		return fmt.Errorf("failed to get due notifications: %w", err)
	}

	facades.Log().Info("Processing due notifications", map[string]interface{}{
		"count": len(dueNotifications),
	})

	// Process each notification
	for _, scheduledNotification := range dueNotifications {
		if err := s.processSingleNotification(ctx, &scheduledNotification); err != nil {
			facades.Log().Error("Failed to process scheduled notification", map[string]interface{}{
				"schedule_id": scheduledNotification.ID,
				"error":       err.Error(),
			})
		}
	}

	return nil
}

// processSingleNotification processes a single scheduled notification
func (s *NotificationSchedulerService) processSingleNotification(ctx context.Context, scheduledNotification *ScheduledNotificationModel) error {
	// Increment attempts
	scheduledNotification.Attempts++

	// Deserialize notification data
	notification, err := s.deserializeNotification(scheduledNotification.NotificationData)
	if err != nil {
		return s.markNotificationFailed(scheduledNotification, fmt.Sprintf("failed to deserialize notification: %v", err))
	}

	// Create notifiable (this would need to be implemented based on your user model)
	notifiable, err := s.createNotifiable(scheduledNotification.NotifiableID, scheduledNotification.NotifiableType)
	if err != nil {
		return s.markNotificationFailed(scheduledNotification, fmt.Sprintf("failed to create notifiable: %v", err))
	}

	// Send the notification
	if err := s.notificationService.SendNow(ctx, notification, notifiable); err != nil {
		if scheduledNotification.Attempts >= scheduledNotification.MaxAttempts {
			return s.markNotificationFailed(scheduledNotification, fmt.Sprintf("max attempts reached: %v", err))
		} else {
			// Schedule for retry
			return s.scheduleRetry(scheduledNotification, err)
		}
	}

	// Mark as sent
	return s.markNotificationSent(scheduledNotification)
}

// markNotificationSent marks a notification as successfully sent
func (s *NotificationSchedulerService) markNotificationSent(scheduledNotification *ScheduledNotificationModel) error {
	scheduledNotification.Status = "sent"
	now := time.Now()
	scheduledNotification.ProcessedAt = &now

	// Handle recurring notifications
	if scheduledNotification.IsRecurring {
		if err := s.scheduleNextRecurrence(scheduledNotification); err != nil {
			facades.Log().Error("Failed to schedule next recurrence", map[string]interface{}{
				"schedule_id": scheduledNotification.ID,
				"error":       err.Error(),
			})
		}
	}

	if err := facades.Orm().Query().Save(scheduledNotification); err != nil {
		return fmt.Errorf("failed to mark notification as sent: %w", err)
	}

	facades.Log().Info("Scheduled notification sent", map[string]interface{}{
		"schedule_id": scheduledNotification.ID,
		"attempts":    scheduledNotification.Attempts,
	})

	return nil
}

// markNotificationFailed marks a notification as failed
func (s *NotificationSchedulerService) markNotificationFailed(scheduledNotification *ScheduledNotificationModel, reason string) error {
	scheduledNotification.Status = "failed"
	scheduledNotification.FailureReason = &reason
	now := time.Now()
	scheduledNotification.ProcessedAt = &now

	if err := facades.Orm().Query().Save(scheduledNotification); err != nil {
		return fmt.Errorf("failed to mark notification as failed: %w", err)
	}

	facades.Log().Error("Scheduled notification failed", map[string]interface{}{
		"schedule_id":    scheduledNotification.ID,
		"failure_reason": reason,
		"attempts":       scheduledNotification.Attempts,
	})

	return nil
}

// scheduleRetry schedules a notification for retry
func (s *NotificationSchedulerService) scheduleRetry(scheduledNotification *ScheduledNotificationModel, lastError error) error {
	// Calculate retry delay (exponential backoff)
	delay := time.Duration(scheduledNotification.Attempts*scheduledNotification.Attempts) * 5 * time.Minute
	if delay > 30*time.Minute {
		delay = 30 * time.Minute
	}

	scheduledNotification.ScheduledAt = time.Now().Add(delay)

	if err := facades.Orm().Query().Save(scheduledNotification); err != nil {
		return fmt.Errorf("failed to schedule retry: %w", err)
	}

	facades.Log().Info("Scheduled notification retry", map[string]interface{}{
		"schedule_id": scheduledNotification.ID,
		"retry_at":    scheduledNotification.ScheduledAt,
		"attempt":     scheduledNotification.Attempts,
		"last_error":  lastError.Error(),
	})

	return nil
}

// scheduleNextRecurrence schedules the next occurrence of a recurring notification
func (s *NotificationSchedulerService) scheduleNextRecurrence(scheduledNotification *ScheduledNotificationModel) error {
	if scheduledNotification.NextScheduledAt == nil {
		return nil // No next occurrence
	}

	nextScheduledAt := *scheduledNotification.NextScheduledAt

	// Check if we've reached the end date
	if scheduledNotification.RecurrenceEnd != nil && nextScheduledAt.After(*scheduledNotification.RecurrenceEnd) {
		return nil // Recurrence has ended
	}

	// Create new scheduled notification for the next occurrence
	nextNotification := &ScheduledNotificationModel{
		ID:                 scheduledNotification.ID + "_" + fmt.Sprintf("%d", nextScheduledAt.Unix()),
		NotificationType:   scheduledNotification.NotificationType,
		NotificationData:   scheduledNotification.NotificationData,
		NotifiableID:       scheduledNotification.NotifiableID,
		NotifiableType:     scheduledNotification.NotifiableType,
		ScheduledAt:        nextScheduledAt,
		Status:             "pending",
		MaxAttempts:        scheduledNotification.MaxAttempts,
		IsRecurring:        true,
		RecurrencePattern:  scheduledNotification.RecurrencePattern,
		RecurrenceInterval: scheduledNotification.RecurrenceInterval,
		RecurrenceEnd:      scheduledNotification.RecurrenceEnd,
		TimeZone:           scheduledNotification.TimeZone,
		Locale:             scheduledNotification.Locale,
		Metadata:           scheduledNotification.Metadata,
	}

	// Calculate the next occurrence after this one
	nextNotification.NextScheduledAt = s.calculateNextScheduledTime(
		nextScheduledAt,
		scheduledNotification.RecurrencePattern,
		scheduledNotification.RecurrenceInterval,
	)

	if err := facades.Orm().Query().Create(nextNotification); err != nil {
		return fmt.Errorf("failed to schedule next recurrence: %w", err)
	}

	facades.Log().Info("Next recurrence scheduled", map[string]interface{}{
		"original_id":       scheduledNotification.ID,
		"next_id":           nextNotification.ID,
		"next_scheduled_at": nextScheduledAt,
	})

	return nil
}

// calculateNextScheduledTime calculates the next scheduled time based on recurrence pattern
func (s *NotificationSchedulerService) calculateNextScheduledTime(currentTime time.Time, pattern string, interval int) *time.Time {
	var nextTime time.Time

	switch pattern {
	case "daily":
		nextTime = currentTime.AddDate(0, 0, interval)
	case "weekly":
		nextTime = currentTime.AddDate(0, 0, interval*7)
	case "monthly":
		nextTime = currentTime.AddDate(0, interval, 0)
	case "yearly":
		nextTime = currentTime.AddDate(interval, 0, 0)
	default:
		return nil // Unknown pattern
	}

	return &nextTime
}

// deserializeNotification deserializes notification data back to a notification object
func (s *NotificationSchedulerService) deserializeNotification(data map[string]interface{}) (notificationcore.Notification, error) {
	// This is a simplified implementation - you'd need to create the actual notification type
	// based on the notification_type field and populate it with the data

	// For now, we'll create a base notification
	notification := notifications.NewBaseNotification()

	if notificationType, ok := data["type"].(string); ok {
		notification.SetType(notificationType)
	}

	if notificationData, ok := data["data"].(map[string]interface{}); ok {
		notification.SetData(notificationData)
	}

	if template, ok := data["template"].(string); ok {
		notification.SetTemplate(template)
	}

	if subject, ok := data["subject"].(string); ok {
		notification.SetSubject(subject)
	}

	if title, ok := data["title"].(string); ok {
		notification.SetTitle(title)
	}

	if body, ok := data["body"].(string); ok {
		notification.SetBody(body)
	}

	if actionURL, ok := data["action_url"].(string); ok {
		notification.SetActionURL(actionURL)
	}

	if actionText, ok := data["action_text"].(string); ok {
		notification.SetActionText(actionText)
	}

	if channels, ok := data["channels"].([]string); ok {
		notification.SetChannels(channels)
	}

	return notification, nil
}

// createNotifiable creates a notifiable object based on the notifiable type and ID
func (s *NotificationSchedulerService) createNotifiable(notifiableID, notifiableType string) (notificationcore.Notifiable, error) {
	switch notifiableType {
	case "user", "users", "App\\Models\\User":
		// Get user from database
		var user models.User
		err := facades.Orm().Query().Where("id = ?", notifiableID).First(&user)
		if err != nil {
			return nil, fmt.Errorf("user not found with ID %s: %w", notifiableID, err)
		}
		return &user, nil

	case "organization", "organizations", "App\\Models\\Organization":
		// Get organization from database to populate generic notifiable
		var organization models.Organization
		err := facades.Orm().Query().Where("id = ?", notifiableID).First(&organization)
		if err != nil {
			return nil, fmt.Errorf("organization not found with ID %s: %w", notifiableID, err)
		}
		return &GenericNotifiable{
			ID:    organization.ID,
			Type:  "organization",
			Email: "", // Organization model doesn't have direct email field
			Phone: "", // Organization model doesn't have direct phone field
		}, nil

	default:
		// For unknown types, we can try to create a generic notifiable wrapper
		facades.Log().Warning("Unknown notifiable type, creating generic wrapper", map[string]interface{}{
			"type": notifiableType,
			"id":   notifiableID,
		})

		// Create a generic notifiable wrapper
		return &GenericNotifiable{
			ID:   notifiableID,
			Type: notifiableType,
		}, nil
	}
}

// GenericNotifiable is a fallback implementation for unknown notifiable types
type GenericNotifiable struct {
	ID    string
	Type  string
	Email string
	Phone string
}

// Implement the Notifiable interface for GenericNotifiable
func (g *GenericNotifiable) GetID() string {
	return g.ID
}

func (g *GenericNotifiable) GetType() string {
	return g.Type
}

func (g *GenericNotifiable) GetEmail() string {
	return g.Email
}

func (g *GenericNotifiable) GetPhone() string {
	return g.Phone
}

func (g *GenericNotifiable) GetPushTokens() []string {
	return []string{}
}

func (g *GenericNotifiable) GetWebhookURL() string {
	return ""
}

func (g *GenericNotifiable) GetTimezone() string {
	return "UTC"
}

func (g *GenericNotifiable) GetLocale() string {
	return "en"
}

func (g *GenericNotifiable) GetNotificationPreferences() map[string]interface{} {
	return map[string]interface{}{
		"email": true,
		"push":  false,
		"sms":   false,
	}
}

func (g *GenericNotifiable) GetChannelAddress(channel string) string {
	switch channel {
	case "email":
		return g.Email
	case "sms":
		return g.Phone
	default:
		return ""
	}
}

func (g *GenericNotifiable) IsChannelEnabled(channel string) bool {
	preferences := g.GetNotificationPreferences()
	if enabled, ok := preferences[channel].(bool); ok {
		return enabled
	}
	return false
}

func (g *GenericNotifiable) GetQuietHours() (start, end string) {
	return "22:00", "08:00"
}

func (g *GenericNotifiable) GetRateLimits() map[string]int {
	return map[string]int{
		"email": 10, // 10 emails per hour
		"sms":   5,  // 5 SMS per hour
		"push":  50, // 50 push notifications per hour
	}
}

// GetPendingCount returns the count of pending scheduled notifications
func (s *NotificationSchedulerService) GetPendingCount() (int64, error) {
	return facades.Orm().Query().Model(&ScheduledNotificationModel{}).
		Where("status = ?", "pending").
		Count()
}

// GetOverdueCount returns the count of overdue notifications
func (s *NotificationSchedulerService) GetOverdueCount() (int64, error) {
	return facades.Orm().Query().Model(&ScheduledNotificationModel{}).
		Where("status = ?", "pending").
		Where("scheduled_at < ?", time.Now()).
		Count()
}

// CleanupOldNotifications removes old processed notifications
func (s *NotificationSchedulerService) CleanupOldNotifications(olderThan time.Duration) error {
	cutoffTime := time.Now().Add(-olderThan)

	result, err := facades.Orm().Query().
		Where("status IN ?", []string{"sent", "failed", "cancelled"}).
		Where("processed_at < ?", cutoffTime).
		Delete(&ScheduledNotificationModel{})

	if err != nil {
		return fmt.Errorf("failed to cleanup old notifications: %w", err)
	}

	facades.Log().Info("Cleaned up old scheduled notifications", map[string]interface{}{
		"deleted_count": result.RowsAffected,
		"cutoff_time":   cutoffTime,
	})

	return nil
}
