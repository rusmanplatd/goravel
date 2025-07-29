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

type SearchController struct {
	calendarService *services.CalendarService
	auditService    *services.AuditService
}

func NewSearchController() *SearchController {
	return &SearchController{
		calendarService: services.NewCalendarService(),
		auditService:    services.GetAuditService(),
	}
}

// SearchEvents performs advanced search across events
// @Summary Search events
// @Description Performs advanced search across user's events with full-text search and filters
// @Tags search
// @Accept json
// @Produce json
// @Param q query string true "Search query"
// @Param timeMin query string false "Start time for search range"
// @Param timeMax query string false "End time for search range"
// @Param calendarId query string false "Specific calendar ID to search in"
// @Param orderBy query string false "Sort order (startTime, updated, created)" default(startTime)
// @Param maxResults query int false "Maximum results to return" default(25)
// @Param showDeleted query bool false "Include deleted events" default(false)
// @Param eventTypes query string false "Comma-separated event types to include"
// @Success 200 {object} responses.APIResponse
// @Failure 400 {object} responses.ErrorResponse
// @Router /search/events [get]
func (sc *SearchController) SearchEvents(ctx http.Context) http.Response {
	userID := ctx.Value("user_id").(string)
	organizationId := ctx.Value("organization_id").(string)

	// Parse query parameters
	query := ctx.Request().Query("q", "")
	timeMin := ctx.Request().Query("timeMin", "")
	timeMax := ctx.Request().Query("timeMax", "")
	calendarID := ctx.Request().Query("calendarId", "")
	orderBy := ctx.Request().Query("orderBy", "startTime")
	maxResults := ctx.Request().QueryInt("maxResults", 25)
	showDeleted := ctx.Request().QueryBool("showDeleted", false)
	eventTypes := ctx.Request().Query("eventTypes", "")

	if query == "" {
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Search query parameter 'q' is required",
			Timestamp: time.Now(),
		})
	}

	// Limit results for performance
	if maxResults > 250 {
		maxResults = 250
	}

	// Build base query
	dbQuery := facades.Orm().Query().
		Where("organization_id = ?", organizationId).
		With("Participants.User").
		With("Calendar").
		Limit(maxResults)

	// Add calendar access filter
	if calendarID != "" {
		// Validate calendar access
		var calendar models.UserCalendar
		err := facades.Orm().Query().
			Where("id = ? AND user_id = ? AND organization_id = ?", calendarID, userID, organizationId).
			First(&calendar)

		if err != nil {
			return ctx.Response().Status(404).Json(responses.ErrorResponse{
				Status:    "error",
				Message:   "Calendar not found or access denied",
				Timestamp: time.Now(),
			})
		}

		dbQuery = dbQuery.Where("calendar_id = ?", calendarID)
	} else {
		// Filter by user's accessible calendars
		var userCalendars []models.UserCalendar
		facades.Orm().Query().
			Where("user_id = ? AND organization_id = ?", userID, organizationId).
			Find(&userCalendars)

		calendarIDs := make([]string, len(userCalendars))
		for i, cal := range userCalendars {
			calendarIDs[i] = cal.ID
		}

		if len(calendarIDs) > 0 {
			dbQuery = dbQuery.Where("calendar_id IN ?", calendarIDs)
		} else {
			// No accessible calendars
			return ctx.Response().Success().Json(responses.APIResponse{
				Status: "success",
				Data: map[string]interface{}{
					"kind":  "calendar#events",
					"items": []interface{}{},
					"query": query,
				},
				Timestamp: time.Now(),
			})
		}
	}

	// Add full-text search
	searchTerms := strings.Fields(strings.ToLower(query))
	for _, term := range searchTerms {
		dbQuery = dbQuery.Where(
			"(LOWER(title) LIKE ? OR LOWER(description) LIKE ? OR LOWER(location) LIKE ?)",
			"%"+term+"%", "%"+term+"%", "%"+term+"%",
		)
	}

	// Add time range filters
	if timeMin != "" {
		if minTime, err := time.Parse(time.RFC3339, timeMin); err == nil {
			dbQuery = dbQuery.Where("start_time >= ?", minTime)
		}
	}

	if timeMax != "" {
		if maxTime, err := time.Parse(time.RFC3339, timeMax); err == nil {
			dbQuery = dbQuery.Where("start_time < ?", maxTime)
		}
	}

	// Add event type filter
	if eventTypes != "" {
		types := strings.Split(eventTypes, ",")
		for i, t := range types {
			types[i] = strings.TrimSpace(t)
		}
		dbQuery = dbQuery.Where("type IN ?", types)
	}

	// Handle deleted events
	if !showDeleted {
		dbQuery = dbQuery.Where("deleted_at IS NULL")
	}

	// Add sorting
	switch orderBy {
	case "updated":
		dbQuery = dbQuery.Order("updated_at DESC")
	case "created":
		dbQuery = dbQuery.Order("created_at DESC")
	case "startTime":
		fallthrough
	default:
		dbQuery = dbQuery.Order("start_time ASC")
	}

	// Execute search
	var events []models.CalendarEvent
	err := dbQuery.Find(&events)

	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Search failed: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	// Transform results
	eventItems := make([]map[string]interface{}, len(events))
	for i, event := range events {
		eventData := transformEventToGoogleFormat(event)

		// Add search relevance score (simplified)
		relevanceScore := sc.calculateRelevanceScore(event, query)
		eventData["searchRelevance"] = relevanceScore

		eventItems[i] = eventData
	}

	response := map[string]interface{}{
		"kind":        "calendar#events",
		"etag":        generateListETag(),
		"summary":     fmt.Sprintf("Search results for: %s", query),
		"updated":     time.Now().Format(time.RFC3339),
		"timeZone":    "UTC",
		"accessRole":  "reader",
		"items":       eventItems,
		"query":       query,
		"resultCount": len(eventItems),
		"searchMeta": map[string]interface{}{
			"searchTerms": searchTerms,
			"timeRange":   map[string]string{"min": timeMin, "max": timeMax},
			"calendarId":  calendarID,
			"eventTypes":  eventTypes,
			"orderBy":     orderBy,
			"showDeleted": showDeleted,
		},
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Message:   fmt.Sprintf("Found %d events matching search criteria", len(eventItems)),
		Data:      response,
		Timestamp: time.Now(),
	})
}

// SearchCalendars performs search across user's calendars
// @Summary Search calendars
// @Description Searches across user's calendars by name and description
// @Tags search
// @Accept json
// @Produce json
// @Param q query string true "Search query"
// @Param maxResults query int false "Maximum results to return" default(25)
// @Success 200 {object} responses.APIResponse
// @Failure 400 {object} responses.ErrorResponse
// @Router /search/calendars [get]
func (sc *SearchController) SearchCalendars(ctx http.Context) http.Response {
	userID := ctx.Value("user_id").(string)
	organizationId := ctx.Value("organization_id").(string)

	query := ctx.Request().Query("q", "")
	maxResults := ctx.Request().QueryInt("maxResults", 25)

	if query == "" {
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Search query parameter 'q' is required",
			Timestamp: time.Now(),
		})
	}

	if maxResults > 100 {
		maxResults = 100
	}

	// Build search query
	dbQuery := facades.Orm().Query().
		Where("user_id = ? AND organization_id = ?", userID, organizationId).
		Limit(maxResults)

	// Add full-text search
	searchTerms := strings.Fields(strings.ToLower(query))
	for _, term := range searchTerms {
		dbQuery = dbQuery.Where(
			"(LOWER(name) LIKE ? OR LOWER(description) LIKE ?)",
			"%"+term+"%", "%"+term+"%",
		)
	}

	dbQuery = dbQuery.Order("name ASC")

	var calendars []models.UserCalendar
	err := dbQuery.Find(&calendars)

	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Calendar search failed: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	// Transform results
	calendarItems := make([]map[string]interface{}, len(calendars))
	for i, calendar := range calendars {
		calendarItems[i] = map[string]interface{}{
			"kind":            "calendar#calendarListEntry",
			"etag":            generateETag(&calendar.UpdatedAt),
			"id":              calendar.ID,
			"summary":         calendar.Name,
			"description":     calendar.Description,
			"timeZone":        calendar.Timezone,
			"accessRole":      "owner",
			"selected":        true,
			"primary":         calendar.IsDefault,
			"colorId":         calendar.Color,
			"searchRelevance": sc.calculateCalendarRelevanceScore(calendar, query),
		}
	}

	response := map[string]interface{}{
		"kind":        "calendar#calendarList",
		"etag":        generateListETag(),
		"items":       calendarItems,
		"query":       query,
		"resultCount": len(calendarItems),
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Message:   fmt.Sprintf("Found %d calendars matching search criteria", len(calendarItems)),
		Data:      response,
		Timestamp: time.Now(),
	})
}

// GlobalSearch performs search across all user's calendar data
// @Summary Global search
// @Description Performs search across events, calendars, and other calendar data
// @Tags search
// @Accept json
// @Produce json
// @Param q query string true "Search query"
// @Param types query string false "Comma-separated types to search (events,calendars)" default(events,calendars)
// @Param maxResults query int false "Maximum results per type" default(10)
// @Success 200 {object} responses.APIResponse
// @Failure 400 {object} responses.ErrorResponse
// @Router /search [get]
func (sc *SearchController) GlobalSearch(ctx http.Context) http.Response {
	userID := ctx.Value("user_id").(string)
	organizationId := ctx.Value("organization_id").(string)

	query := ctx.Request().Query("q", "")
	searchTypes := ctx.Request().Query("types", "events,calendars")
	maxResults := ctx.Request().QueryInt("maxResults", 10)

	if query == "" {
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Search query parameter 'q' is required",
			Timestamp: time.Now(),
		})
	}

	if maxResults > 50 {
		maxResults = 50
	}

	types := strings.Split(searchTypes, ",")
	results := make(map[string]interface{})

	// Search events
	if sc.containsType(types, "events") {
		eventResults := sc.searchEventsInternal(query, userID, organizationId, maxResults)
		results["events"] = eventResults
	}

	// Search calendars
	if sc.containsType(types, "calendars") {
		calendarResults := sc.searchCalendarsInternal(query, userID, organizationId, maxResults)
		results["calendars"] = calendarResults
	}

	response := map[string]interface{}{
		"kind":    "calendar#searchResults",
		"query":   query,
		"results": results,
		"searchMeta": map[string]interface{}{
			"searchTypes": types,
			"maxResults":  maxResults,
			"timestamp":   time.Now().Format(time.RFC3339),
		},
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Message:   "Global search completed",
		Data:      response,
		Timestamp: time.Now(),
	})
}

// Helper functions

func (sc *SearchController) calculateRelevanceScore(event models.CalendarEvent, query string) float64 {
	score := 0.0
	queryLower := strings.ToLower(query)

	// Title matches get highest score
	if strings.Contains(strings.ToLower(event.Title), queryLower) {
		score += 10.0
	}

	// Description matches get medium score
	if strings.Contains(strings.ToLower(event.Description), queryLower) {
		score += 5.0
	}

	// Location matches get lower score
	if strings.Contains(strings.ToLower(event.Location), queryLower) {
		score += 3.0
	}

	// Recent events get slight boost
	daysSinceCreated := time.Since(event.CreatedAt).Hours() / 24
	if daysSinceCreated < 30 {
		score += 1.0
	}

	return score
}

func (sc *SearchController) calculateCalendarRelevanceScore(calendar models.UserCalendar, query string) float64 {
	score := 0.0
	queryLower := strings.ToLower(query)

	// Name matches get highest score
	if strings.Contains(strings.ToLower(calendar.Name), queryLower) {
		score += 10.0
	}

	// Description matches get medium score
	if strings.Contains(strings.ToLower(calendar.Description), queryLower) {
		score += 5.0
	}

	// Primary calendar gets boost
	if calendar.IsDefault {
		score += 2.0
	}

	return score
}

func (sc *SearchController) containsType(types []string, searchType string) bool {
	for _, t := range types {
		if strings.TrimSpace(t) == searchType {
			return true
		}
	}
	return false
}

func (sc *SearchController) searchEventsInternal(query, userID, organizationId string, maxResults int) map[string]interface{} {
	// Get user's calendars
	var userCalendars []models.UserCalendar
	facades.Orm().Query().
		Where("user_id = ? AND organization_id = ?", userID, organizationId).
		Find(&userCalendars)

	calendarIDs := make([]string, len(userCalendars))
	for i, cal := range userCalendars {
		calendarIDs[i] = cal.ID
	}

	if len(calendarIDs) == 0 {
		return map[string]interface{}{
			"items": []interface{}{},
			"count": 0,
		}
	}

	// Search events
	dbQuery := facades.Orm().Query().
		Where("organization_id = ? AND calendar_id IN ?", organizationId, calendarIDs).
		With("Participants.User").
		Limit(maxResults)

	searchTerms := strings.Fields(strings.ToLower(query))
	for _, term := range searchTerms {
		dbQuery = dbQuery.Where(
			"(LOWER(title) LIKE ? OR LOWER(description) LIKE ? OR LOWER(location) LIKE ?)",
			"%"+term+"%", "%"+term+"%", "%"+term+"%",
		)
	}

	dbQuery = dbQuery.Order("start_time ASC")

	var events []models.CalendarEvent
	dbQuery.Find(&events)

	eventItems := make([]map[string]interface{}, len(events))
	for i, event := range events {
		eventData := transformEventToGoogleFormat(event)
		eventData["searchRelevance"] = sc.calculateRelevanceScore(event, query)
		eventItems[i] = eventData
	}

	return map[string]interface{}{
		"items": eventItems,
		"count": len(eventItems),
	}
}

func (sc *SearchController) searchCalendarsInternal(query, userID, organizationId string, maxResults int) map[string]interface{} {
	dbQuery := facades.Orm().Query().
		Where("user_id = ? AND organization_id = ?", userID, organizationId).
		Limit(maxResults)

	searchTerms := strings.Fields(strings.ToLower(query))
	for _, term := range searchTerms {
		dbQuery = dbQuery.Where(
			"(LOWER(name) LIKE ? OR LOWER(description) LIKE ?)",
			"%"+term+"%", "%"+term+"%",
		)
	}

	dbQuery = dbQuery.Order("name ASC")

	var calendars []models.UserCalendar
	dbQuery.Find(&calendars)

	calendarItems := make([]map[string]interface{}, len(calendars))
	for i, calendar := range calendars {
		calendarItems[i] = map[string]interface{}{
			"kind":            "calendar#calendarListEntry",
			"id":              calendar.ID,
			"summary":         calendar.Name,
			"description":     calendar.Description,
			"searchRelevance": sc.calculateCalendarRelevanceScore(calendar, query),
		}
	}

	return map[string]interface{}{
		"items": calendarItems,
		"count": len(calendarItems),
	}
}
