package v1

import (
	"fmt"
	"strings"
	"time"

	"github.com/goravel/framework/contracts/http"
	"github.com/goravel/framework/facades"

	"goravel/app/http/responses"
	"goravel/app/models"
	"goravel/app/services"
)

type BatchController struct {
	calendarService *services.CalendarService
	auditService    *services.AuditService
}

func NewBatchController() *BatchController {
	return &BatchController{
		calendarService: services.NewCalendarService(),
		auditService:    services.GetAuditService(),
	}
}

// BatchRequest represents a batch operation request
type BatchRequest struct {
	Requests []BatchRequestItem `json:"requests" binding:"required"`
}

// BatchRequestItem represents a single request in a batch
type BatchRequestItem struct {
	ID     string                 `json:"id" binding:"required"`     // Unique request ID
	Method string                 `json:"method" binding:"required"` // HTTP method
	URI    string                 `json:"uri" binding:"required"`    // Request URI
	Body   map[string]interface{} `json:"body,omitempty"`            // Request body
}

// BatchResponse represents a batch operation response
type BatchResponse struct {
	Kind      string              `json:"kind"`
	Responses []BatchResponseItem `json:"responses"`
}

// BatchResponseItem represents a single response in a batch
type BatchResponseItem struct {
	ID     string                 `json:"id"`
	Status int                    `json:"status"`
	Body   map[string]interface{} `json:"body,omitempty"`
	Error  map[string]interface{} `json:"error,omitempty"`
}

// ProcessBatch processes a batch of calendar operations
// @Summary Process batch operations
// @Description Processes multiple calendar operations in a single request
// @Tags batch
// @Accept json
// @Produce json
// @Param batch body BatchRequest true "Batch request"
// @Success 200 {object} responses.APIResponse
// @Failure 400 {object} responses.ErrorResponse
// @Router /batch [post]
func (bc *BatchController) ProcessBatch(ctx http.Context) http.Response {
	userID := ctx.Value("user_id").(string)
	organizationId := ctx.Value("organization_id").(string)

	var batchRequest BatchRequest
	if err := ctx.Request().Bind(&batchRequest); err != nil {
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Invalid batch request format",
			Timestamp: time.Now(),
		})
	}

	// Limit batch size for performance
	if len(batchRequest.Requests) > 100 {
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Batch size cannot exceed 100 requests",
			Timestamp: time.Now(),
		})
	}

	batchResponses := make([]BatchResponseItem, len(batchRequest.Requests))

	// Process each request in the batch
	for i, req := range batchRequest.Requests {
		batchResponses[i] = bc.processBatchRequest(req, userID, organizationId)
	}

	batchResponse := BatchResponse{
		Kind:      "calendar#batchResponse",
		Responses: batchResponses,
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Message:   fmt.Sprintf("Batch processed. %d requests completed", len(batchResponses)),
		Data:      batchResponse,
		Timestamp: time.Now(),
	})
}

// processBatchRequest processes a single request within a batch
func (bc *BatchController) processBatchRequest(req BatchRequestItem, userID, organizationId string) BatchResponseItem {
	response := BatchResponseItem{
		ID: req.ID,
	}

	// Parse URI to determine operation type
	parts := strings.Split(strings.Trim(req.URI, "/"), "/")
	if len(parts) < 2 {
		response.Status = 400
		response.Error = map[string]interface{}{
			"message": "Invalid URI format",
		}
		return response
	}

	// Route to appropriate handler based on URI pattern
	switch {
	case strings.Contains(req.URI, "/calendars/") && strings.Contains(req.URI, "/events"):
		return bc.processEventBatchRequest(req, userID, organizationId)
	case strings.Contains(req.URI, "/calendars/"):
		return bc.processCalendarBatchRequest(req, userID, organizationId)
	case strings.Contains(req.URI, "/users/me/calendarList"):
		return bc.processCalendarListBatchRequest(req, userID, organizationId)
	default:
		response.Status = 400
		response.Error = map[string]interface{}{
			"message": "Unsupported batch operation URI",
		}
		return response
	}
}

// processEventBatchRequest handles event-related batch operations
func (bc *BatchController) processEventBatchRequest(req BatchRequestItem, userID, organizationId string) BatchResponseItem {
	response := BatchResponseItem{ID: req.ID}

	// Extract calendar ID and event ID from URI
	parts := strings.Split(strings.Trim(req.URI, "/"), "/")
	var calendarID, eventID string

	for i, part := range parts {
		if part == "calendars" && i+1 < len(parts) {
			calendarID = parts[i+1]
		}
		if part == "events" && i+1 < len(parts) {
			eventID = parts[i+1]
		}
	}

	if calendarID == "" {
		response.Status = 400
		response.Error = map[string]interface{}{"message": "Calendar ID required"}
		return response
	}

	// Validate calendar access
	var calendar models.UserCalendar
	err := facades.Orm().Query().
		Where("id = ? AND user_id = ? AND organization_id = ?", calendarID, userID, organizationId).
		First(&calendar)

	if err != nil {
		response.Status = 404
		response.Error = map[string]interface{}{"message": "Calendar not found"}
		return response
	}

	switch strings.ToUpper(req.Method) {
	case "GET":
		return bc.batchGetEvent(eventID, calendarID, response)
	case "POST":
		return bc.batchCreateEvent(req.Body, calendarID, userID, organizationId, response)
	case "PUT", "PATCH":
		return bc.batchUpdateEvent(eventID, req.Body, calendarID, response)
	case "DELETE":
		return bc.batchDeleteEvent(eventID, calendarID, response)
	default:
		response.Status = 405
		response.Error = map[string]interface{}{"message": "Method not allowed"}
		return response
	}
}

// processCalendarBatchRequest handles calendar-related batch operations
func (bc *BatchController) processCalendarBatchRequest(req BatchRequestItem, userID, organizationId string) BatchResponseItem {
	response := BatchResponseItem{ID: req.ID}

	// Extract calendar ID from URI
	parts := strings.Split(strings.Trim(req.URI, "/"), "/")
	var calendarID string

	for i, part := range parts {
		if part == "calendars" && i+1 < len(parts) {
			calendarID = parts[i+1]
		}
	}

	switch strings.ToUpper(req.Method) {
	case "GET":
		return bc.batchGetCalendar(calendarID, userID, organizationId, response)
	case "POST":
		return bc.batchCreateCalendar(req.Body, userID, organizationId, response)
	case "PUT", "PATCH":
		return bc.batchUpdateCalendar(calendarID, req.Body, userID, organizationId, response)
	case "DELETE":
		return bc.batchDeleteCalendar(calendarID, userID, organizationId, response)
	default:
		response.Status = 405
		response.Error = map[string]interface{}{"message": "Method not allowed"}
		return response
	}
}

// processCalendarListBatchRequest handles calendar list operations
func (bc *BatchController) processCalendarListBatchRequest(req BatchRequestItem, userID, organizationId string) BatchResponseItem {
	response := BatchResponseItem{ID: req.ID}

	switch strings.ToUpper(req.Method) {
	case "GET":
		return bc.batchGetCalendarList(userID, organizationId, response)
	default:
		response.Status = 405
		response.Error = map[string]interface{}{"message": "Method not allowed for calendar list"}
		return response
	}
}

// Batch operation implementations

func (bc *BatchController) batchGetEvent(eventID, calendarID string, response BatchResponseItem) BatchResponseItem {
	if eventID == "" {
		// List events
		var events []models.CalendarEvent
		err := facades.Orm().Query().
			Where("calendar_id = ?", calendarID).
			With("Participants.User").
			Limit(50). // Limit for batch operations
			Find(&events)

		if err != nil {
			response.Status = 500
			response.Error = map[string]interface{}{"message": "Failed to retrieve events"}
			return response
		}

		eventItems := make([]map[string]interface{}, len(events))
		for i, event := range events {
			eventItems[i] = transformEventToGoogleFormat(event)
		}

		response.Status = 200
		response.Body = map[string]interface{}{
			"kind":  "calendar#events",
			"items": eventItems,
		}
	} else {
		// Get specific event
		var event models.CalendarEvent
		err := facades.Orm().Query().
			Where("id = ? AND calendar_id = ?", eventID, calendarID).
			With("Participants.User").
			First(&event)

		if err != nil {
			response.Status = 404
			response.Error = map[string]interface{}{"message": "Event not found"}
			return response
		}

		response.Status = 200
		response.Body = transformEventToGoogleFormat(event)
	}

	return response
}

func (bc *BatchController) batchCreateEvent(body map[string]interface{}, calendarID, userID, organizationId string, response BatchResponseItem) BatchResponseItem {
	// Convert body to event data
	event := models.CalendarEvent{
		CalendarID:     &calendarID,
		OrganizationID: organizationId,
		BaseModel: models.BaseModel{
			CreatedBy: &userID,
		},
	}

	// Map basic fields
	if summary, ok := body["summary"].(string); ok {
		event.Title = summary
	}
	if description, ok := body["description"].(string); ok {
		event.Description = description
	}
	if location, ok := body["location"].(string); ok {
		event.Location = location
	}

	// Parse start/end times
	if start, ok := body["start"].(map[string]interface{}); ok {
		if dateTime, exists := start["dateTime"].(string); exists {
			if t, err := time.Parse(time.RFC3339, dateTime); err == nil {
				event.StartTime = t
			}
		}
	}

	if end, ok := body["end"].(map[string]interface{}); ok {
		if dateTime, exists := end["dateTime"].(string); exists {
			if t, err := time.Parse(time.RFC3339, dateTime); err == nil {
				event.EndTime = t
			}
		}
	}

	if err := facades.Orm().Query().Create(&event); err != nil {
		response.Status = 500
		response.Error = map[string]interface{}{"message": "Failed to create event"}
		return response
	}

	response.Status = 201
	response.Body = transformEventToGoogleFormat(event)
	return response
}

func (bc *BatchController) batchUpdateEvent(eventID string, body map[string]interface{}, calendarID string, response BatchResponseItem) BatchResponseItem {
	var event models.CalendarEvent
	err := facades.Orm().Query().
		Where("id = ? AND calendar_id = ?", eventID, calendarID).
		First(&event)

	if err != nil {
		response.Status = 404
		response.Error = map[string]interface{}{"message": "Event not found"}
		return response
	}

	// Update fields
	if summary, ok := body["summary"].(string); ok {
		event.Title = summary
	}
	if description, ok := body["description"].(string); ok {
		event.Description = description
	}
	if location, ok := body["location"].(string); ok {
		event.Location = location
	}

	if err := facades.Orm().Query().Save(&event); err != nil {
		response.Status = 500
		response.Error = map[string]interface{}{"message": "Failed to update event"}
		return response
	}

	response.Status = 200
	response.Body = transformEventToGoogleFormat(event)
	return response
}

func (bc *BatchController) batchDeleteEvent(eventID, calendarID string, response BatchResponseItem) BatchResponseItem {
	var event models.CalendarEvent
	err := facades.Orm().Query().
		Where("id = ? AND calendar_id = ?", eventID, calendarID).
		First(&event)

	if err != nil {
		response.Status = 404
		response.Error = map[string]interface{}{"message": "Event not found"}
		return response
	}

	_, err = facades.Orm().Query().Delete(&event)
	if err != nil {
		response.Status = 500
		response.Error = map[string]interface{}{"message": "Failed to delete event"}
		return response
	}

	response.Status = 204
	return response
}

func (bc *BatchController) batchGetCalendar(calendarID, userID, organizationId string, response BatchResponseItem) BatchResponseItem {
	var calendar models.UserCalendar
	err := facades.Orm().Query().
		Where("id = ? AND user_id = ? AND organization_id = ?", calendarID, userID, organizationId).
		First(&calendar)

	if err != nil {
		response.Status = 404
		response.Error = map[string]interface{}{"message": "Calendar not found"}
		return response
	}

	response.Status = 200
	response.Body = map[string]interface{}{
		"kind":        "calendar#calendar",
		"etag":        generateETag(&calendar.UpdatedAt),
		"id":          calendar.ID,
		"summary":     calendar.Name,
		"description": calendar.Description,
		"timeZone":    calendar.Timezone,
	}

	return response
}

func (bc *BatchController) batchCreateCalendar(body map[string]interface{}, userID, organizationId string, response BatchResponseItem) BatchResponseItem {
	calendar := models.UserCalendar{
		UserID:         userID,
		OrganizationID: organizationId,
		BaseModel: models.BaseModel{
			CreatedBy: &userID,
		},
	}

	if summary, ok := body["summary"].(string); ok {
		calendar.Name = summary
	}
	if description, ok := body["description"].(string); ok {
		calendar.Description = description
	}
	if timeZone, ok := body["timeZone"].(string); ok {
		calendar.Timezone = timeZone
	}

	if err := facades.Orm().Query().Create(&calendar); err != nil {
		response.Status = 500
		response.Error = map[string]interface{}{"message": "Failed to create calendar"}
		return response
	}

	response.Status = 201
	response.Body = map[string]interface{}{
		"kind":        "calendar#calendar",
		"etag":        generateETag(&calendar.UpdatedAt),
		"id":          calendar.ID,
		"summary":     calendar.Name,
		"description": calendar.Description,
		"timeZone":    calendar.Timezone,
	}

	return response
}

func (bc *BatchController) batchUpdateCalendar(calendarID string, body map[string]interface{}, userID, organizationId string, response BatchResponseItem) BatchResponseItem {
	var calendar models.UserCalendar
	err := facades.Orm().Query().
		Where("id = ? AND user_id = ? AND organization_id = ?", calendarID, userID, organizationId).
		First(&calendar)

	if err != nil {
		response.Status = 404
		response.Error = map[string]interface{}{"message": "Calendar not found"}
		return response
	}

	if summary, ok := body["summary"].(string); ok {
		calendar.Name = summary
	}
	if description, ok := body["description"].(string); ok {
		calendar.Description = description
	}

	if err := facades.Orm().Query().Save(&calendar); err != nil {
		response.Status = 500
		response.Error = map[string]interface{}{"message": "Failed to update calendar"}
		return response
	}

	response.Status = 200
	response.Body = map[string]interface{}{
		"kind":        "calendar#calendar",
		"etag":        generateETag(&calendar.UpdatedAt),
		"id":          calendar.ID,
		"summary":     calendar.Name,
		"description": calendar.Description,
		"timeZone":    calendar.Timezone,
	}

	return response
}

func (bc *BatchController) batchDeleteCalendar(calendarID, userID, organizationId string, response BatchResponseItem) BatchResponseItem {
	var calendar models.UserCalendar
	err := facades.Orm().Query().
		Where("id = ? AND user_id = ? AND organization_id = ?", calendarID, userID, organizationId).
		First(&calendar)

	if err != nil {
		response.Status = 404
		response.Error = map[string]interface{}{"message": "Calendar not found"}
		return response
	}

	_, err = facades.Orm().Query().Delete(&calendar)
	if err != nil {
		response.Status = 500
		response.Error = map[string]interface{}{"message": "Failed to delete calendar"}
		return response
	}

	response.Status = 204
	return response
}

func (bc *BatchController) batchGetCalendarList(userID, organizationId string, response BatchResponseItem) BatchResponseItem {
	var calendars []models.UserCalendar
	err := facades.Orm().Query().
		Where("user_id = ? AND organization_id = ?", userID, organizationId).
		Limit(50). // Limit for batch operations
		Find(&calendars)

	if err != nil {
		response.Status = 500
		response.Error = map[string]interface{}{"message": "Failed to retrieve calendar list"}
		return response
	}

	calendarItems := make([]map[string]interface{}, len(calendars))
	for i, calendar := range calendars {
		calendarItems[i] = map[string]interface{}{
			"kind":        "calendar#calendarListEntry",
			"etag":        generateETag(&calendar.UpdatedAt),
			"id":          calendar.ID,
			"summary":     calendar.Name,
			"description": calendar.Description,
			"timeZone":    calendar.Timezone,
			"accessRole":  "owner",
		}
	}

	response.Status = 200
	response.Body = map[string]interface{}{
		"kind":  "calendar#calendarList",
		"items": calendarItems,
	}

	return response
}
