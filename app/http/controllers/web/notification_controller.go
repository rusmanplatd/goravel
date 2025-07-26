package web

import (
	"strings"
	"time"

	"github.com/goravel/framework/contracts/http"
	"github.com/goravel/framework/facades"

	"goravel/app/models"
	"goravel/app/services"
)

type NotificationController struct {
	notificationService *services.NotificationService
}

func NewNotificationController() *NotificationController {
	return &NotificationController{
		notificationService: services.NewNotificationService(),
	}
}

// getCurrentUser gets the current authenticated user from context
func (c *NotificationController) getCurrentUser(ctx http.Context) *models.User {
	user := ctx.Value("user")
	if user == nil {
		return nil
	}

	if userPtr, ok := user.(*models.User); ok {
		return userPtr
	}

	return nil
}

// Index displays the notifications management page with real-time updates
func (c *NotificationController) Index(ctx http.Context) http.Response {
	user := c.getCurrentUser(ctx)
	if user == nil {
		return ctx.Response().Redirect(302, "/login")
	}

	// Get pagination parameters
	page := ctx.Request().QueryInt("page", 1)
	perPage := ctx.Request().QueryInt("per_page", 20)
	filter := ctx.Request().Query("filter", "all") // all, unread, read
	search := ctx.Request().Query("search", "")

	// Build query
	query := facades.Orm().Query().Model(&models.Notification{}).
		Where("notifiable_id = ?", user.ID).
		Where("notifiable_type = ?", "user")

	// Apply filters
	switch filter {
	case "unread":
		query = query.Where("read_at IS NULL")
	case "read":
		query = query.Where("read_at IS NOT NULL")
	}

	// Apply search
	if search != "" {
		query = query.Where("type LIKE ? OR data LIKE ?", "%"+search+"%", "%"+search+"%")
	}

	// Get total count
	totalCount, _ := query.Count()

	// Get notifications with pagination
	var notifications []models.Notification
	query.OrderBy("created_at DESC").
		Offset((page - 1) * perPage).
		Limit(perPage).
		Find(&notifications)

	// Get statistics
	unreadCount, _ := facades.Orm().Query().Model(&models.Notification{}).
		Where("notifiable_id = ?", user.ID).
		Where("notifiable_type = ?", "user").
		Where("read_at IS NULL").
		Count()

	readCount, _ := facades.Orm().Query().Model(&models.Notification{}).
		Where("notifiable_id = ?", user.ID).
		Where("notifiable_type = ?", "user").
		Where("read_at IS NOT NULL").
		Count()

	// Calculate pagination
	totalPages := (int(totalCount) + perPage - 1) / perPage
	hasNext := page < totalPages
	hasPrev := page > 1

	return ctx.Response().View().Make("notifications/index.tmpl", map[string]interface{}{
		"title":         "Notifications",
		"user":          user,
		"notifications": notifications,
		"stats": map[string]interface{}{
			"total":  totalCount,
			"unread": unreadCount,
			"read":   readCount,
		},
		"pagination": map[string]interface{}{
			"current_page": page,
			"per_page":     perPage,
			"total_pages":  totalPages,
			"total_count":  totalCount,
			"has_next":     hasNext,
			"has_prev":     hasPrev,
		},
		"filters": map[string]interface{}{
			"current": filter,
			"search":  search,
		},
		"success": ctx.Request().Query("success", ""),
		"error":   ctx.Request().Query("error", ""),
	})
}

// MarkAsRead marks a notification as read
func (c *NotificationController) MarkAsRead(ctx http.Context) http.Response {
	user := c.getCurrentUser(ctx)
	if user == nil {
		return ctx.Response().Json(401, map[string]interface{}{
			"success": false,
			"message": "Unauthorized",
		})
	}

	notificationID := ctx.Request().Route("id")
	if notificationID == "" {
		return ctx.Response().Json(400, map[string]interface{}{
			"success": false,
			"message": "Notification ID is required",
		})
	}

	// Find and update notification
	var notification models.Notification
	err := facades.Orm().Query().
		Where("id = ?", notificationID).
		Where("notifiable_id = ?", user.ID).
		Where("notifiable_type = ?", "user").
		First(&notification)

	if err != nil {
		return ctx.Response().Json(404, map[string]interface{}{
			"success": false,
			"message": "Notification not found",
		})
	}

	// Mark as read if not already read
	if notification.ReadAt == nil {
		now := time.Now()
		notification.ReadAt = &now
		facades.Orm().Query().Save(&notification)
	}

	return ctx.Response().Json(200, map[string]interface{}{
		"success": true,
		"message": "Notification marked as read",
	})
}

// MarkAllAsRead marks all notifications as read for the current user
func (c *NotificationController) MarkAllAsRead(ctx http.Context) http.Response {
	user := c.getCurrentUser(ctx)
	if user == nil {
		return ctx.Response().Json(401, map[string]interface{}{
			"success": false,
			"message": "Unauthorized",
		})
	}

	// Update all unread notifications
	now := time.Now()
	result, err := facades.Orm().Query().Model(&models.Notification{}).
		Where("notifiable_id = ?", user.ID).
		Where("notifiable_type = ?", "user").
		Where("read_at IS NULL").
		Update("read_at", now)

	if err != nil {
		facades.Log().Error("Failed to mark all notifications as read: " + err.Error())
		return ctx.Response().Json(500, map[string]interface{}{
			"success": false,
			"message": "Failed to mark notifications as read",
		})
	}

	return ctx.Response().Json(200, map[string]interface{}{
		"success": true,
		"message": "All notifications marked as read",
		"count":   result.RowsAffected,
	})
}

// Delete removes a notification
func (c *NotificationController) Delete(ctx http.Context) http.Response {
	user := c.getCurrentUser(ctx)
	if user == nil {
		return ctx.Response().Json(401, map[string]interface{}{
			"success": false,
			"message": "Unauthorized",
		})
	}

	notificationID := ctx.Request().Route("id")
	if notificationID == "" {
		return ctx.Response().Json(400, map[string]interface{}{
			"success": false,
			"message": "Notification ID is required",
		})
	}

	// Delete notification
	result, err := facades.Orm().Query().
		Where("id = ?", notificationID).
		Where("notifiable_id = ?", user.ID).
		Where("notifiable_type = ?", "user").
		Delete(&models.Notification{})

	if err != nil {
		return ctx.Response().Json(500, map[string]interface{}{
			"success": false,
			"message": "Failed to delete notification",
		})
	}

	if result.RowsAffected == 0 {
		return ctx.Response().Json(404, map[string]interface{}{
			"success": false,
			"message": "Notification not found",
		})
	}

	return ctx.Response().Json(200, map[string]interface{}{
		"success": true,
		"message": "Notification deleted successfully",
	})
}

// BulkAction performs bulk operations on notifications
func (c *NotificationController) BulkAction(ctx http.Context) http.Response {
	user := c.getCurrentUser(ctx)
	if user == nil {
		return ctx.Response().Json(401, map[string]interface{}{
			"success": false,
			"message": "Unauthorized",
		})
	}

	action := ctx.Request().Input("action", "")
	notificationIDs := ctx.Request().Input("notification_ids", "")

	if action == "" || notificationIDs == "" {
		return ctx.Response().Json(400, map[string]interface{}{
			"success": false,
			"message": "Action and notification IDs are required",
		})
	}

	// Parse notification IDs (assuming comma-separated)
	ids := []string{}
	for _, id := range strings.Split(notificationIDs, ",") {
		if strings.TrimSpace(id) != "" {
			ids = append(ids, strings.TrimSpace(id))
		}
	}

	if len(ids) == 0 {
		return ctx.Response().Json(400, map[string]interface{}{
			"success": false,
			"message": "No valid notification IDs provided",
		})
	}

	var count int64
	var message string

	switch action {
	case "mark_read":
		now := time.Now()
		for _, id := range ids {
			_, updateErr := facades.Orm().Query().Model(&models.Notification{}).
				Where("id = ?", id).
				Where("notifiable_id = ?", user.ID).
				Where("notifiable_type = ?", "user").
				Where("read_at IS NULL").
				Update("read_at", now)
			if updateErr == nil {
				count++
			}
		}
		message = "Selected notifications marked as read"

	case "mark_unread":
		for _, id := range ids {
			_, updateErr := facades.Orm().Query().Model(&models.Notification{}).
				Where("id = ?", id).
				Where("notifiable_id = ?", user.ID).
				Where("notifiable_type = ?", "user").
				Update("read_at", nil)
			if updateErr == nil {
				count++
			}
		}
		message = "Selected notifications marked as unread"

	case "delete":
		for _, id := range ids {
			_, deleteErr := facades.Orm().Query().
				Where("id = ?", id).
				Where("notifiable_id = ?", user.ID).
				Where("notifiable_type = ?", "user").
				Delete(&models.Notification{})
			if deleteErr == nil {
				count++
			}
		}
		message = "Selected notifications deleted"

	default:
		return ctx.Response().Json(400, map[string]interface{}{
			"success": false,
			"message": "Invalid action",
		})
	}

	return ctx.Response().Json(200, map[string]interface{}{
		"success": true,
		"message": message,
		"count":   count,
	})
}

// GetUnreadCount returns the count of unread notifications for the current user
func (c *NotificationController) GetUnreadCount(ctx http.Context) http.Response {
	user := c.getCurrentUser(ctx)
	if user == nil {
		return ctx.Response().Json(401, map[string]interface{}{
			"success": false,
			"message": "Unauthorized",
		})
	}

	count, _ := facades.Orm().Query().Model(&models.Notification{}).
		Where("notifiable_id = ?", user.ID).
		Where("notifiable_type = ?", "user").
		Where("read_at IS NULL").
		Count()

	return ctx.Response().Json(200, map[string]interface{}{
		"success": true,
		"count":   count,
	})
}

// GetRecentNotifications returns recent notifications for real-time updates
func (c *NotificationController) GetRecentNotifications(ctx http.Context) http.Response {
	user := c.getCurrentUser(ctx)
	if user == nil {
		return ctx.Response().Json(401, map[string]interface{}{
			"success": false,
			"message": "Unauthorized",
		})
	}

	// Get notifications from the last 5 minutes
	since := time.Now().Add(-5 * time.Minute)
	var notifications []models.Notification

	facades.Orm().Query().Model(&models.Notification{}).
		Where("notifiable_id = ?", user.ID).
		Where("notifiable_type = ?", "user").
		Where("created_at > ?", since).
		OrderBy("created_at DESC").
		Limit(10).
		Find(&notifications)

	return ctx.Response().Json(200, map[string]interface{}{
		"success":       true,
		"notifications": notifications,
		"count":         len(notifications),
	})
}
