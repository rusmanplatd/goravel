package v1

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/goravel/framework/contracts/http"
	"github.com/goravel/framework/facades"

	"goravel/app/http/responses"
	"goravel/app/models"
	"goravel/app/services"
)

type ChannelsController struct {
	notificationService *services.NotificationService
	auditService        *services.AuditService
}

func NewChannelsController() *ChannelsController {
	return &ChannelsController{
		notificationService: services.NewNotificationService(),
		auditService:        services.GetAuditService(),
	}
}

// WatchCalendar sets up push notifications for calendar changes
// @Summary Watch calendar for changes
// @Description Sets up push notifications for calendar changes
// @Tags channels
// @Accept json
// @Produce json
// @Param calendarId path string true "Calendar ID"
// @Param watch body object{id=string,type=string,address=string,token=string,expiration=int64} true "Watch request"
// @Success 200 {object} responses.APIResponse
// @Failure 400 {object} responses.ErrorResponse
// @Router /calendars/{calendarId}/events/watch [post]
func (cc *ChannelsController) WatchCalendar(ctx http.Context) http.Response {
	calendarID := ctx.Request().Route("calendarId")
	userID := ctx.Value("user_id").(string)
	organizationId := ctx.Value("organization_id").(string)

	var request struct {
		ID         string `json:"id"`                         // Channel ID
		Type       string `json:"type" binding:"required"`    // "web_hook"
		Address    string `json:"address" binding:"required"` // Webhook URL
		Token      string `json:"token"`                      // Optional verification token
		Expiration int64  `json:"expiration"`                 // Unix timestamp
	}

	if err := ctx.Request().Bind(&request); err != nil {
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Invalid request data",
			Timestamp: time.Now(),
		})
	}

	// Validate calendar access
	var calendar models.UserCalendar
	err := facades.Orm().Query().
		Where("id = ? AND user_id = ? AND organization_id = ?", calendarID, userID, organizationId).
		First(&calendar)

	if err != nil {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Calendar not found",
			Timestamp: time.Now(),
		})
	}

	// Generate channel ID if not provided
	if request.ID == "" {
		request.ID = cc.generateChannelID()
	}

	// Set default expiration (24 hours from now)
	if request.Expiration == 0 {
		request.Expiration = time.Now().Add(24 * time.Hour).Unix()
	}

	// Validate webhook type
	if request.Type != "web_hook" {
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Only 'web_hook' type is supported",
			Timestamp: time.Now(),
		})
	}

	// Create webhook subscription record
	subscription := models.Notification{
		Type:           "webhook",
		NotifiableID:   userID,
		NotifiableType: "User",
		Channel:        "webhook",
		Data: map[string]interface{}{
			"channel_id":   request.ID,
			"calendar_id":  calendarID,
			"webhook_url":  request.Address,
			"token":        request.Token,
			"expiration":   request.Expiration,
			"resource_uri": fmt.Sprintf("/calendars/%s/events", calendarID),
			"title":        fmt.Sprintf("Calendar Watch: %s", calendar.Name),
			"message":      fmt.Sprintf("Webhook subscription for calendar %s", calendarID),
		},
		BaseModel: models.BaseModel{
			CreatedBy: &userID,
		},
	}

	if err := facades.Orm().Query().Create(&subscription); err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to create webhook subscription",
			Timestamp: time.Now(),
		})
	}

	// Return channel information
	channel := map[string]interface{}{
		"kind":        "api#channel",
		"id":          request.ID,
		"resourceId":  subscription.ID,
		"resourceUri": fmt.Sprintf("/calendars/%s/events", calendarID),
		"token":       request.Token,
		"expiration":  request.Expiration,
		"type":        request.Type,
		"address":     request.Address,
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Message:   "Webhook subscription created successfully",
		Data:      channel,
		Timestamp: time.Now(),
	})
}

// WatchEvents sets up push notifications for event changes
// @Summary Watch events for changes
// @Description Sets up push notifications for event changes
// @Tags channels
// @Accept json
// @Produce json
// @Param watch body object{id=string,type=string,address=string,token=string,expiration=int64} true "Watch request"
// @Success 200 {object} responses.APIResponse
// @Failure 400 {object} responses.ErrorResponse
// @Router /events/watch [post]
func (cc *ChannelsController) WatchEvents(ctx http.Context) http.Response {
	userID := ctx.Value("user_id").(string)

	var request struct {
		ID         string `json:"id"`
		Type       string `json:"type" binding:"required"`
		Address    string `json:"address" binding:"required"`
		Token      string `json:"token"`
		Expiration int64  `json:"expiration"`
	}

	if err := ctx.Request().Bind(&request); err != nil {
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Invalid request data",
			Timestamp: time.Now(),
		})
	}

	// Generate channel ID if not provided
	if request.ID == "" {
		request.ID = cc.generateChannelID()
	}

	// Set default expiration
	if request.Expiration == 0 {
		request.Expiration = time.Now().Add(24 * time.Hour).Unix()
	}

	// Create global events webhook subscription
	subscription := models.Notification{
		Type:           "webhook",
		NotifiableID:   userID,
		NotifiableType: "User",
		Channel:        "webhook",
		Data: map[string]interface{}{
			"channel_id":   request.ID,
			"webhook_url":  request.Address,
			"token":        request.Token,
			"expiration":   request.Expiration,
			"resource_uri": "/events",
			"scope":        "all_events",
			"title":        "Global Events Watch",
			"message":      "Webhook subscription for all user events",
		},
		BaseModel: models.BaseModel{
			CreatedBy: &userID,
		},
	}

	if err := facades.Orm().Query().Create(&subscription); err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to create webhook subscription",
			Timestamp: time.Now(),
		})
	}

	channel := map[string]interface{}{
		"kind":        "api#channel",
		"id":          request.ID,
		"resourceId":  subscription.ID,
		"resourceUri": "/events",
		"token":       request.Token,
		"expiration":  request.Expiration,
		"type":        request.Type,
		"address":     request.Address,
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Message:   "Global events webhook subscription created successfully",
		Data:      channel,
		Timestamp: time.Now(),
	})
}

// StopChannel stops a push notification channel
// @Summary Stop push notification channel
// @Description Stops a push notification channel
// @Tags channels
// @Accept json
// @Produce json
// @Param stop body object{id=string,resourceId=string} true "Stop request"
// @Success 204 "No Content"
// @Failure 404 {object} responses.ErrorResponse
// @Router /channels/stop [post]
func (cc *ChannelsController) StopChannel(ctx http.Context) http.Response {
	userID := ctx.Value("user_id").(string)

	var request struct {
		ID         string `json:"id" binding:"required"`
		ResourceID string `json:"resourceId" binding:"required"`
	}

	if err := ctx.Request().Bind(&request); err != nil {
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Invalid request data",
			Timestamp: time.Now(),
		})
	}

	// Find and delete the subscription
	var subscription models.Notification
	err := facades.Orm().Query().
		Where("id = ? AND user_id = ? AND type = ?", request.ResourceID, userID, "webhook").
		First(&subscription)

	if err != nil {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Channel not found",
			Timestamp: time.Now(),
		})
	}

	// Verify channel ID matches
	if channelID, exists := subscription.Data["channel_id"].(string); !exists || channelID != request.ID {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Channel ID mismatch",
			Timestamp: time.Now(),
		})
	}

	// Delete the subscription
	_, err = facades.Orm().Query().Delete(&subscription)
	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to stop channel",
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Status(204).Json(nil)
}

// ListChannels lists active push notification channels
// @Summary List active channels
// @Description Lists active push notification channels for the user
// @Tags channels
// @Accept json
// @Produce json
// @Success 200 {object} responses.APIResponse
// @Failure 500 {object} responses.ErrorResponse
// @Router /channels [get]
func (cc *ChannelsController) ListChannels(ctx http.Context) http.Response {
	userID := ctx.Value("user_id").(string)

	// Get all webhook subscriptions for the user
	var subscriptions []models.Notification
	err := facades.Orm().Query().
		Where("user_id = ? AND type = ?", userID, "webhook").
		Find(&subscriptions)

	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to retrieve channels",
			Timestamp: time.Now(),
		})
	}

	// Transform to channel format
	channels := make([]map[string]interface{}, 0)
	for _, sub := range subscriptions {
		// Check if channel is still valid (not expired)
		if expiration, exists := sub.Data["expiration"].(float64); exists {
			if time.Now().Unix() > int64(expiration) {
				// Channel expired, skip it
				continue
			}
		}

		channel := map[string]interface{}{
			"kind":        "api#channel",
			"id":          sub.Data["channel_id"],
			"resourceId":  sub.ID,
			"resourceUri": sub.Data["resource_uri"],
			"token":       sub.Data["token"],
			"expiration":  sub.Data["expiration"],
			"type":        "web_hook",
			"address":     sub.Data["webhook_url"],
			"created":     sub.CreatedAt.Unix(),
		}
		channels = append(channels, channel)
	}

	response := map[string]interface{}{
		"kind":  "api#channelList",
		"items": channels,
		"total": len(channels),
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Data:      response,
		Timestamp: time.Now(),
	})
}

// SendNotification sends a webhook notification (internal use)
func (cc *ChannelsController) SendNotification(resourceURI, eventType string, eventData map[string]interface{}, userID, organizationId string) error {
	// TODO: Implement webhook notification sending
	facades.Log().Info("Webhook notification triggered", map[string]interface{}{
		"resource_uri":    resourceURI,
		"event_type":      eventType,
		"user_id":         userID,
		"organization_id": organizationId,
	})
	return nil
}

// Helper function to generate unique channel ID
func (cc *ChannelsController) generateChannelID() string {
	bytes := make([]byte, 16)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}

// Helper function to trigger notifications on event changes
func (cc *ChannelsController) TriggerEventNotification(eventID, calendarID, eventType, userID, organizationId string) {
	// Get event data
	var event models.CalendarEvent
	err := facades.Orm().Query().
		Where("id = ?", eventID).
		With("Participants.User").
		First(&event)

	if err != nil {
		return
	}

	eventData := map[string]interface{}{
		"id":          event.ID,
		"summary":     event.Title,
		"description": event.Description,
		"location":    event.Location,
		"start":       event.StartTime.Format(time.RFC3339),
		"end":         event.EndTime.Format(time.RFC3339),
		"calendarId":  calendarID,
	}

	// Send notifications for both calendar-specific and global subscriptions
	cc.SendNotification(fmt.Sprintf("/calendars/%s/events", calendarID), eventType, eventData, userID, organizationId)
	cc.SendNotification("/events", eventType, eventData, userID, organizationId)
}
