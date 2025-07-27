package v1

import (
	"context"
	"time"

	"goravel/app/models"
	"goravel/app/notifications"
	"goravel/app/services"

	"github.com/goravel/framework/contracts/http"
	"github.com/goravel/framework/facades"
)

type NotificationController struct {
	notificationService *services.NotificationService
	auditService        *services.AuditService
	auditHelper         *services.AuditHelper
}

func NewNotificationController() *NotificationController {
	auditService := services.GetAuditService()
	return &NotificationController{
		notificationService: services.NewNotificationService(),
		auditService:        auditService,
		auditHelper:         services.NewAuditHelper(auditService),
	}
}

// @Summary Send a welcome notification to a user
// @Description Sends a welcome notification to a user by their ID.
// @Tags notifications
// @Accept json
// @Produce json
// @Param user_id path string true "User ID"
// @Success 200 {object} map[string]interface{}
// @Failure 400 {object} map[string]interface{}
// @Failure 404 {object} map[string]interface{}
// @Failure 500 {object} map[string]interface{}
// @Router /api/v1/notifications/welcome/{user_id} [post]
func (c *NotificationController) SendWelcomeNotification(ctx http.Context) http.Response {
	// Get user ID from request
	userID := ctx.Request().Route("user_id")
	if userID == "" {
		return ctx.Response().Status(400).Json(map[string]interface{}{
			"error": "User ID is required",
		})
	}

	// Find the user
	var user models.User
	if err := facades.Orm().Query().Where("id", userID).First(&user); err != nil {
		return ctx.Response().Status(404).Json(map[string]interface{}{
			"error": "User not found",
		})
	}

	// Create welcome notification
	notification := notifications.NewWelcomeNotification(user.Name)

	// Send notification
	context := context.Background()
	if err := c.notificationService.Send(context, notification, &user); err != nil {
		facades.Log().Error("Failed to send welcome notification", map[string]interface{}{
			"user_id": userID,
			"error":   err.Error(),
		})

		// Log failed notification send
		c.auditHelper.LogDataOperation(user.ID, "create", "notification", "", map[string]interface{}{
			"type":      "welcome",
			"recipient": user.Email,
			"status":    "failed",
			"error":     err.Error(),
		})

		return ctx.Response().Status(500).Json(map[string]interface{}{
			"error": "Failed to send notification",
		})
	}

	// Log successful notification send
	c.auditHelper.LogDataOperation(user.ID, "create", "notification", "", map[string]interface{}{
		"type":      "welcome",
		"recipient": user.Email,
		"status":    "success",
	})

	return ctx.Response().Success().Json(map[string]interface{}{
		"message": "Welcome notification sent successfully",
		"user_id": userID,
	})
}

// @Summary Send a password reset notification
// @Description Sends a password reset notification to a user by their email.
// @Tags notifications
// @Accept json
// @Produce json
// @Param email query string true "User Email"
// @Success 200 {object} map[string]interface{}
// @Failure 400 {object} map[string]interface{}
// @Failure 404 {object} map[string]interface{}
// @Failure 500 {object} map[string]interface{}
// @Router /api/v1/notifications/password-reset [post]
func (c *NotificationController) SendPasswordResetNotification(ctx http.Context) http.Response {
	// Get email from request
	email := ctx.Request().Input("email")
	if email == "" {
		return ctx.Response().Status(400).Json(map[string]interface{}{
			"error": "Email is required",
		})
	}

	// Find the user
	var user models.User
	if err := facades.Orm().Query().Where("email", email).First(&user); err != nil {
		return ctx.Response().Status(404).Json(map[string]interface{}{
			"error": "User not found",
		})
	}

	// Generate reset token (in a real app, you'd use a proper token service)
	resetToken := "reset_token_" + user.ID

	// Create password reset notification
	notification := notifications.NewPasswordResetNotification(user.Email, resetToken)

	// Send notification
	context := context.Background()
	if err := c.notificationService.Send(context, notification, &user); err != nil {
		facades.Log().Error("Failed to send password reset notification", map[string]interface{}{
			"email": email,
			"error": err.Error(),
		})

		return ctx.Response().Status(500).Json(map[string]interface{}{
			"error": "Failed to send notification",
		})
	}

	return ctx.Response().Success().Json(map[string]interface{}{
		"message": "Password reset notification sent successfully",
		"email":   email,
	})
}

// @Summary Get notifications for a user
// @Description Retrieves notifications for a user by their ID.
// @Tags notifications
// @Accept json
// @Produce json
// @Param user_id path string true "User ID"
// @Param limit query int false "Number of notifications to return"
// @Success 200 {object} map[string]interface{}
// @Failure 400 {object} map[string]interface{}
// @Failure 404 {object} map[string]interface{}
// @Failure 500 {object} map[string]interface{}
// @Router /api/v1/notifications/{user_id} [get]
func (c *NotificationController) GetUserNotifications(ctx http.Context) http.Response {
	// Get user ID from request
	userID := ctx.Request().Route("user_id")
	if userID == "" {
		return ctx.Response().Status(400).Json(map[string]interface{}{
			"error": "User ID is required",
		})
	}

	// Get pagination parameters
	limit := ctx.Request().InputInt("limit", 10)

	// Query notifications
	var notifications []models.Notification

	query := facades.Orm().Query().Where("notifiable_id", userID).Where("notifiable_type", "User")

	// Get results with limit
	if err := query.Order("created_at DESC").Limit(limit).Find(&notifications); err != nil {
		return ctx.Response().Status(500).Json(map[string]interface{}{
			"error": "Failed to retrieve notifications",
		})
	}

	return ctx.Response().Success().Json(map[string]interface{}{
		"notifications": notifications,
		"limit":         limit,
		"count":         len(notifications),
	})
}

// @Summary Mark a notification as read
// @Description Marks a notification as read by its ID.
// @Tags notifications
// @Accept json
// @Produce json
// @Param notification_id path string true "Notification ID"
// @Success 200 {object} map[string]interface{}
// @Failure 400 {object} map[string]interface{}
// @Failure 404 {object} map[string]interface{}
// @Failure 500 {object} map[string]interface{}
// @Router /api/v1/notifications/{notification_id}/read [put]
func (c *NotificationController) MarkNotificationAsRead(ctx http.Context) http.Response {
	// Get notification ID from request
	notificationID := ctx.Request().Route("notification_id")
	if notificationID == "" {
		return ctx.Response().Status(400).Json(map[string]interface{}{
			"error": "Notification ID is required",
		})
	}

	// Find the notification
	var notification models.Notification
	if err := facades.Orm().Query().Where("id", notificationID).First(&notification); err != nil {
		return ctx.Response().Status(404).Json(map[string]interface{}{
			"error": "Notification not found",
		})
	}

	// Mark as read
	notification.MarkAsRead()

	// Save to database
	if err := facades.Orm().Query().Save(&notification); err != nil {
		return ctx.Response().Status(500).Json(map[string]interface{}{
			"error": "Failed to update notification",
		})
	}

	return ctx.Response().Success().Json(map[string]interface{}{
		"message":         "Notification marked as read",
		"notification_id": notificationID,
	})
}

// @Summary Mark all notifications for a user as read
// @Description Marks all unread notifications for a user as read.
// @Tags notifications
// @Accept json
// @Produce json
// @Param user_id path string true "User ID"
// @Success 200 {object} map[string]interface{}
// @Failure 400 {object} map[string]interface{}
// @Failure 404 {object} map[string]interface{}
// @Failure 500 {object} map[string]interface{}
// @Router /api/v1/notifications/read-all/{user_id} [put]
func (c *NotificationController) MarkAllNotificationsAsRead(ctx http.Context) http.Response {
	// Get user ID from request
	userID := ctx.Request().Route("user_id")
	if userID == "" {
		return ctx.Response().Status(400).Json(map[string]interface{}{
			"error": "User ID is required",
		})
	}

	// Update all unread notifications for the user
	now := time.Now()
	_, err := facades.Orm().Query().Where("notifiable_id", userID).
		Where("notifiable_type", "User").
		Where("read_at IS NULL").
		Update("read_at", now)
	if err != nil {
		return ctx.Response().Status(500).Json(map[string]interface{}{
			"error": "Failed to update notifications",
		})
	}

	return ctx.Response().Success().Json(map[string]interface{}{
		"message": "All notifications marked as read",
		"user_id": userID,
	})
}

// @Summary Delete a notification
// @Description Deletes a notification by its ID.
// @Tags notifications
// @Accept json
// @Produce json
// @Param notification_id path string true "Notification ID"
// @Success 200 {object} map[string]interface{}
// @Failure 400 {object} map[string]interface{}
// @Failure 404 {object} map[string]interface{}
// @Failure 500 {object} map[string]interface{}
// @Router /api/v1/notifications/{notification_id} [delete]
func (c *NotificationController) DeleteNotification(ctx http.Context) http.Response {
	// Get notification ID from request
	notificationID := ctx.Request().Route("notification_id")
	if notificationID == "" {
		return ctx.Response().Status(400).Json(map[string]interface{}{
			"error": "Notification ID is required",
		})
	}

	// Delete the notification
	_, err := facades.Orm().Query().Where("id", notificationID).Delete(&models.Notification{})
	if err != nil {
		return ctx.Response().Status(500).Json(map[string]interface{}{
			"error": "Failed to delete notification",
		})
	}

	return ctx.Response().Success().Json(map[string]interface{}{
		"message":         "Notification deleted successfully",
		"notification_id": notificationID,
	})
}
