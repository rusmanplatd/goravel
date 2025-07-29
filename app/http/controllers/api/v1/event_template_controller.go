package v1

import (
	"time"

	"github.com/goravel/framework/contracts/http"
	"github.com/goravel/framework/facades"

	"goravel/app/http/requests"
	"goravel/app/http/responses"
	"goravel/app/models"
	"goravel/app/querybuilder"
	"goravel/app/services"
)

type EventTemplateController struct {
	calendarService *services.CalendarService
}

func NewEventTemplateController() *EventTemplateController {
	return &EventTemplateController{
		calendarService: services.NewCalendarService(),
	}
}

// Index returns all event templates
// @Summary Get all event templates
// @Description Retrieve a list of all event templates with filtering and pagination
// @Tags event-templates
// @Accept json
// @Produce json
// @Param pagination_type query string false "Pagination type: offset or cursor" Enums(offset,cursor) default(offset)
// @Param page query int false "Page number for offset pagination" default(1)
// @Param cursor query string false "Cursor for cursor pagination"
// @Param limit query int false "Items per page" minimum(1) maximum(100) default(15)
// @Param filter[name] query string false "Filter by template name (partial match)"
// @Param filter[category] query string false "Filter by template category"
// @Param filter[type] query string false "Filter by template type"
// @Param filter[is_active] query bool false "Filter by active status"
// @Param filter[is_public] query bool false "Filter by public status"
// @Param filter[organization_id] query string false "Filter by organization ID"
// @Param sort query string false "Sort by field (prefix with - for desc)" default("-created_at")
// @Success 200 {object} responses.QueryBuilderResponse{data=[]models.EventTemplate}
// @Failure 400 {object} responses.ErrorResponse
// @Failure 500 {object} responses.ErrorResponse
// @Router /event-templates [get]
func (etc *EventTemplateController) Index(ctx http.Context) http.Response {
	var templates []models.EventTemplate

	// Create query builder with allowed filters, sorts, and includes
	qb := querybuilder.For(&models.EventTemplate{}).
		WithRequest(ctx).
		AllowedFilters(
			querybuilder.Partial("name"),
			querybuilder.Exact("category"),
			querybuilder.Exact("type"),
			querybuilder.Exact("is_active"),
			querybuilder.Exact("is_public"),
			querybuilder.Exact("organization_id"),
		).
		AllowedSorts("name", "category", "type", "usage_count", "last_used_at", "created_at", "updated_at").
		AllowedIncludes("creator", "organization").
		DefaultSort("-created_at")

	// Use AutoPaginate for unified pagination support
	result, err := qb.AutoPaginate(&templates)
	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to retrieve event templates: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	return responses.QueryBuilderSuccessResponse(ctx, "Event templates retrieved successfully", result)
}

// Show returns a specific event template
// @Summary Get event template by ID
// @Description Retrieve a specific event template by its ID
// @Tags event-templates
// @Accept json
// @Produce json
// @Param id path string true "Template ID"
// @Success 200 {object} responses.APIResponse{data=models.EventTemplate}
// @Failure 404 {object} responses.ErrorResponse
// @Router /event-templates/{id} [get]
func (etc *EventTemplateController) Show(ctx http.Context) http.Response {
	id := ctx.Request().Route("id")

	var template models.EventTemplate
	err := facades.Orm().Query().With("Creator").With("Organization").
		Where("id = ?", id).First(&template)
	if err != nil {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Event template not found",
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Data:      template,
		Timestamp: time.Now(),
	})
}

// Store creates a new event template
// @Summary Create event template
// @Description Create a new event template
// @Tags event-templates
// @Accept json
// @Produce json
// @Param template body requests.CreateEventTemplateRequest true "Template data"
// @Success 201 {object} responses.APIResponse{data=models.EventTemplate}
// @Failure 400 {object} responses.ErrorResponse
// @Failure 500 {object} responses.ErrorResponse
// @Router /event-templates [post]
func (etc *EventTemplateController) Store(ctx http.Context) http.Response {
	var request requests.CreateEventTemplateRequest
	if err := ctx.Request().Bind(&request); err != nil {
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Invalid request data",
			Timestamp: time.Now(),
		})
	}

	// Validate duration
	if request.DefaultDuration <= 0 {
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Default duration must be greater than 0",
			Timestamp: time.Now(),
		})
	}

	// Create template
	userID := ctx.Request().Input("user_id", "")
	template := models.EventTemplate{
		Name:                    request.Name,
		Description:             request.Description,
		Category:                request.Category,
		Type:                    request.Type,
		DefaultDuration:         request.DefaultDuration,
		DefaultColor:            request.DefaultColor,
		DefaultLocation:         request.DefaultLocation,
		Settings:                request.Settings,
		DefaultRecurrenceRule:   request.DefaultRecurrenceRule,
		DefaultReminderSettings: request.DefaultReminderSettings,
		DefaultParticipantRoles: request.DefaultParticipantRoles,
		Tags:                    request.Tags,
		IsActive:                request.IsActive,
		IsPublic:                request.IsPublic,
		OrganizationID:          request.OrganizationID,
		BaseModel: models.BaseModel{
			CreatedBy: &userID,
		},
	}

	if err := facades.Orm().Query().Create(&template); err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to create event template",
			Timestamp: time.Now(),
		})
	}

	// Reload with relationships
	facades.Orm().Query().With("Creator").With("Organization").
		Where("id = ?", template.ID).First(&template)

	return ctx.Response().Status(201).Json(responses.APIResponse{
		Status:    "success",
		Data:      template,
		Timestamp: time.Now(),
	})
}

// Update updates an existing event template
// @Summary Update event template
// @Description Update an existing event template
// @Tags event-templates
// @Accept json
// @Produce json
// @Param id path string true "Template ID"
// @Param template body requests.UpdateEventTemplateRequest true "Template data"
// @Success 200 {object} responses.APIResponse{data=models.EventTemplate}
// @Failure 400 {object} responses.ErrorResponse
// @Failure 404 {object} responses.ErrorResponse
// @Failure 500 {object} responses.ErrorResponse
// @Router /event-templates/{id} [put]
func (etc *EventTemplateController) Update(ctx http.Context) http.Response {
	id := ctx.Request().Route("id")

	var request requests.UpdateEventTemplateRequest
	if err := ctx.Request().Bind(&request); err != nil {
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Invalid request data",
			Timestamp: time.Now(),
		})
	}

	// Find existing template
	var template models.EventTemplate
	err := facades.Orm().Query().Where("id = ?", id).First(&template)
	if err != nil {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Event template not found",
			Timestamp: time.Now(),
		})
	}

	// Update fields
	if request.Name != "" {
		template.Name = request.Name
	}
	if request.Description != "" {
		template.Description = request.Description
	}
	if request.Category != "" {
		template.Category = request.Category
	}
	if request.Type != "" {
		template.Type = request.Type
	}
	if request.DefaultDuration > 0 {
		template.DefaultDuration = request.DefaultDuration
	}
	if request.DefaultColor != "" {
		template.DefaultColor = request.DefaultColor
	}
	if request.DefaultLocation != "" {
		template.DefaultLocation = request.DefaultLocation
	}
	if request.Settings != "" {
		template.Settings = request.Settings
	}
	if request.DefaultRecurrenceRule != "" {
		template.DefaultRecurrenceRule = request.DefaultRecurrenceRule
	}
	if request.DefaultReminderSettings != "" {
		template.DefaultReminderSettings = request.DefaultReminderSettings
	}
	if request.DefaultParticipantRoles != "" {
		template.DefaultParticipantRoles = request.DefaultParticipantRoles
	}
	if request.Tags != "" {
		template.Tags = request.Tags
	}
	template.IsActive = request.IsActive
	template.IsPublic = request.IsPublic

	if err := facades.Orm().Query().Save(&template); err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to update event template",
			Timestamp: time.Now(),
		})
	}

	// Reload with relationships
	facades.Orm().Query().With("Creator").With("Organization").
		Where("id = ?", template.ID).First(&template)

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Data:      template,
		Timestamp: time.Now(),
	})
}

// Delete deletes an event template
// @Summary Delete event template
// @Description Delete an event template (soft delete)
// @Tags event-templates
// @Accept json
// @Produce json
// @Param id path string true "Template ID"
// @Success 200 {object} responses.APIResponse
// @Failure 404 {object} responses.ErrorResponse
// @Failure 500 {object} responses.ErrorResponse
// @Router /event-templates/{id} [delete]
func (etc *EventTemplateController) Delete(ctx http.Context) http.Response {
	id := ctx.Request().Route("id")

	// Check if template exists
	var template models.EventTemplate
	err := facades.Orm().Query().Where("id = ?", id).First(&template)
	if err != nil {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Event template not found",
			Timestamp: time.Now(),
		})
	}

	// Soft delete template
	if _, err := facades.Orm().Query().Where("id = ?", id).Delete(&template); err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to delete event template",
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Message:   "Event template deleted successfully",
		Timestamp: time.Now(),
	})
}

// CreateEventFromTemplate creates a new event from a template
// @Summary Create event from template
// @Description Create a new calendar event using an existing template
// @Tags event-templates
// @Accept json
// @Produce json
// @Param id path string true "Template ID"
// @Param event body requests.CreateEventFromTemplateRequest true "Event data"
// @Success 201 {object} responses.APIResponse{data=models.CalendarEvent}
// @Failure 400 {object} responses.ErrorResponse
// @Failure 404 {object} responses.ErrorResponse
// @Failure 500 {object} responses.ErrorResponse
// @Router /event-templates/{id}/create-event [post]
func (etc *EventTemplateController) CreateEventFromTemplate(ctx http.Context) http.Response {
	templateID := ctx.Request().Route("id")

	var request requests.CreateEventFromTemplateRequest
	if err := ctx.Request().Bind(&request); err != nil {
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Invalid request data",
			Timestamp: time.Now(),
		})
	}

	// Find template
	var template models.EventTemplate
	err := facades.Orm().Query().Where("id = ? AND is_active = ?", templateID, true).First(&template)
	if err != nil {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Event template not found or inactive",
			Timestamp: time.Now(),
		})
	}

	// Create event from template
	event, err := etc.createEventFromTemplate(&template, &request)
	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to create event from template: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	// Update template usage
	now := time.Now()
	template.UsageCount++
	template.LastUsedAt = &now
	facades.Orm().Query().Save(&template)

	return ctx.Response().Status(201).Json(responses.APIResponse{
		Status:    "success",
		Data:      event,
		Timestamp: time.Now(),
	})
}

// GetTemplateUsage returns usage statistics for a template
// @Summary Get template usage statistics
// @Description Get detailed usage statistics for an event template
// @Tags event-templates
// @Accept json
// @Produce json
// @Param id path string true "Template ID"
// @Success 200 {object} responses.APIResponse{data=map[string]interface{}}
// @Failure 404 {object} responses.ErrorResponse
// @Router /event-templates/{id}/usage [get]
func (etc *EventTemplateController) GetTemplateUsage(ctx http.Context) http.Response {
	templateID := ctx.Request().Route("id")

	// Find template
	var template models.EventTemplate
	err := facades.Orm().Query().Where("id = ?", templateID).First(&template)
	if err != nil {
		return ctx.Response().Status(404).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Event template not found",
			Timestamp: time.Now(),
		})
	}

	// Get usage statistics
	stats, err := etc.getTemplateUsageStats(templateID)
	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to retrieve usage statistics",
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Data:      stats,
		Timestamp: time.Now(),
	})
}

// Helper methods

func (etc *EventTemplateController) createEventFromTemplate(template *models.EventTemplate, request *requests.CreateEventFromTemplateRequest) (*models.CalendarEvent, error) {
	// Calculate end time based on template duration
	endTime := request.StartTime.Add(time.Duration(template.DefaultDuration) * time.Minute)
	if request.EndTime != nil {
		endTime = *request.EndTime
	}

	// Use template defaults, but allow overrides from request
	title := request.Title
	if title == "" {
		title = template.Name
	}

	description := request.Description
	if description == "" {
		description = template.Description
	}

	location := request.Location
	if location == "" {
		location = template.DefaultLocation
	}

	color := request.Color
	if color == "" {
		color = template.DefaultColor
	}

	recurrenceRule := request.RecurrenceRule
	if recurrenceRule == "" && request.IsRecurring {
		recurrenceRule = template.DefaultRecurrenceRule
	}

	reminderSettings := request.ReminderSettings
	if reminderSettings == "" {
		reminderSettings = template.DefaultReminderSettings
	}

	// Create event
	userID := request.CreatedBy
	event := models.CalendarEvent{
		Title:            title,
		Description:      description,
		StartTime:        request.StartTime,
		EndTime:          endTime,
		Location:         location,
		Color:            color,
		Type:             template.Category,
		IsAllDay:         request.IsAllDay,
		IsRecurring:      request.IsRecurring,
		RecurrenceRule:   recurrenceRule,
		RecurrenceUntil:  request.RecurrenceUntil,
		Timezone:         request.Timezone,
		Status:           "scheduled",
		ReminderSettings: reminderSettings,
		OrganizationID:   template.OrganizationID,
		TemplateID:       &template.ID,
		BaseModel: models.BaseModel{
			CreatedBy: &userID,
		},
	}

	// Start transaction
	tx, err := facades.Orm().Query().Begin()
	if err != nil {
		return nil, err
	}

	// Save event
	if err := tx.Create(&event); err != nil {
		tx.Rollback()
		return nil, err
	}

	// Add participants if specified
	if len(request.ParticipantIDs) > 0 {
		for _, participantID := range request.ParticipantIDs {
			participant := models.EventParticipant{
				EventID:        event.ID,
				UserID:         participantID,
				Role:           "attendee",
				ResponseStatus: "pending",
				IsRequired:     true,
				SendReminder:   true,
			}
			if err := tx.Create(&participant); err != nil {
				tx.Rollback()
				return nil, err
			}
		}
	}

	// Generate recurring events if needed
	if event.IsRecurring && event.RecurrenceRule != "" {
		if err := etc.calendarService.GenerateRecurringEvents(&event); err != nil {
			facades.Log().Error("Failed to generate recurring events", map[string]interface{}{
				"event_id": event.ID,
				"error":    err.Error(),
			})
		}
	}

	// Commit transaction
	tx.Commit()

	// Reload with relationships
	facades.Orm().Query().With("Creator").With("Organization").
		With("Participants.User").With("Template").
		Where("id = ?", event.ID).First(&event)

	return &event, nil
}

func (etc *EventTemplateController) getTemplateUsageStats(templateID string) (map[string]interface{}, error) {
	// Get total events created from template
	totalEvents, err := facades.Orm().Query().Model(&models.CalendarEvent{}).
		Where("template_id = ?", templateID).Count()
	if err != nil {
		return nil, err
	}

	// Get events created in last 30 days
	thirtyDaysAgo := time.Now().AddDate(0, 0, -30)
	recentEvents, err := facades.Orm().Query().Model(&models.CalendarEvent{}).
		Where("template_id = ? AND created_at >= ?", templateID, thirtyDaysAgo).
		Count()
	if err != nil {
		return nil, err
	}

	// Get usage by month (last 12 months)
	monthlyUsage := make([]map[string]interface{}, 0)
	for i := 11; i >= 0; i-- {
		monthStart := time.Now().AddDate(0, -i, 0)
		monthStart = time.Date(monthStart.Year(), monthStart.Month(), 1, 0, 0, 0, 0, monthStart.Location())
		monthEnd := monthStart.AddDate(0, 1, 0).Add(-time.Nanosecond)

		monthlyCount, err := facades.Orm().Query().Model(&models.CalendarEvent{}).
			Where("template_id = ? AND created_at >= ? AND created_at <= ?", templateID, monthStart, monthEnd).
			Count()
		if err != nil {
			return nil, err
		}

		monthlyUsage = append(monthlyUsage, map[string]interface{}{
			"month": monthStart.Format("2006-01"),
			"count": monthlyCount,
		})
	}

	// Get most recent events
	var recentEventsList []models.CalendarEvent
	err = facades.Orm().Query().Model(&models.CalendarEvent{}).
		Where("template_id = ?", templateID).
		With("Creator").
		OrderBy("created_at DESC").
		Limit(5).
		Find(&recentEventsList)
	if err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"total_events":       totalEvents,
		"recent_events":      recentEvents,
		"monthly_usage":      monthlyUsage,
		"recent_events_list": recentEventsList,
	}, nil
}
