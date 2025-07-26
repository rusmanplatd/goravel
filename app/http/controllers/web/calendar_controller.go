package web

import (
	"github.com/goravel/framework/contracts/http"
)

type CalendarController struct {
	//Dependent services
}

func NewCalendarController() *CalendarController {
	return &CalendarController{}
}

// Index displays the calendar page
func (r *CalendarController) Index(ctx http.Context) http.Response {
	user := ctx.Value("user")
	if user == nil {
		return ctx.Response().Redirect(302, "/login")
	}

	// Get calendar events data
	data := map[string]interface{}{
		"title": "Calendar",
		"user":  user,
		"events": []map[string]interface{}{
			{
				"id":          1,
				"title":       "Team Meeting",
				"description": "Weekly team sync and planning session",
				"start_time":  "2024-01-15 10:00:00",
				"end_time":    "2024-01-15 11:00:00",
				"location":    "Conference Room A",
				"type":        "meeting",
				"attendees":   []string{"John Doe", "Jane Smith", "Mike Johnson"},
				"color":       "primary",
			},
			{
				"id":          2,
				"title":       "Project Deadline",
				"description": "Final submission for Project Alpha",
				"start_time":  "2024-01-18 17:00:00",
				"end_time":    "2024-01-18 17:00:00",
				"location":    "",
				"type":        "deadline",
				"attendees":   []string{},
				"color":       "danger",
			},
			{
				"id":          3,
				"title":       "Client Presentation",
				"description": "Quarterly review presentation to stakeholders",
				"start_time":  "2024-01-20 14:00:00",
				"end_time":    "2024-01-20 16:00:00",
				"location":    "Main Auditorium",
				"type":        "presentation",
				"attendees":   []string{"Sarah Wilson", "Tom Brown", "Lisa Davis"},
				"color":       "success",
			},
			{
				"id":          4,
				"title":       "Training Session",
				"description": "New technology training for development team",
				"start_time":  "2024-01-22 09:00:00",
				"end_time":    "2024-01-22 17:00:00",
				"location":    "Training Room B",
				"type":        "training",
				"attendees":   []string{"Development Team"},
				"color":       "info",
			},
		},
		"upcoming_events": []map[string]interface{}{
			{
				"id":    1,
				"title": "Team Meeting",
				"date":  "Today, 10:00 AM",
				"type":  "meeting",
			},
			{
				"id":    2,
				"title": "Project Deadline",
				"date":  "Thursday, 5:00 PM",
				"type":  "deadline",
			},
			{
				"id":    3,
				"title": "Client Presentation",
				"date":  "Saturday, 2:00 PM",
				"type":  "presentation",
			},
		},
	}

	return ctx.Response().View().Make("calendar/index.tmpl", data)
}

// Show displays a specific calendar event
func (r *CalendarController) Show(ctx http.Context) http.Response {
	user := ctx.Value("user")
	if user == nil {
		return ctx.Response().Redirect(302, "/login")
	}

	eventId := ctx.Request().Route("id")

	// Get specific event data
	data := map[string]interface{}{
		"title": "Event Details",
		"user":  user,
		"event": map[string]interface{}{
			"id":          eventId,
			"title":       "Team Meeting",
			"description": "Weekly team sync and planning session. We'll discuss current project status, upcoming deadlines, and any blockers.",
			"start_time":  "2024-01-15 10:00:00",
			"end_time":    "2024-01-15 11:00:00",
			"location":    "Conference Room A",
			"type":        "meeting",
			"organizer":   "John Doe",
			"attendees": []map[string]interface{}{
				{"name": "John Doe", "email": "john@example.com", "status": "accepted"},
				{"name": "Jane Smith", "email": "jane@example.com", "status": "pending"},
				{"name": "Mike Johnson", "email": "mike@example.com", "status": "accepted"},
			},
			"color": "primary",
		},
	}

	return ctx.Response().View().Make("calendar/show.tmpl", data)
}

// Create displays the form to create a new calendar event
func (r *CalendarController) Create(ctx http.Context) http.Response {
	user := ctx.Value("user")
	if user == nil {
		return ctx.Response().Redirect(302, "/login")
	}

	data := map[string]interface{}{
		"title": "Create Event",
		"user":  user,
	}

	return ctx.Response().View().Make("calendar/create.tmpl", data)
}

// Store handles the creation of a new calendar event
func (r *CalendarController) Store(ctx http.Context) http.Response {
	user := ctx.Value("user")
	if user == nil {
		return ctx.Response().Redirect(302, "/login")
	}

	// Validate and store the calendar event
	// For now, just redirect with success message
	ctx.Request().Session().Flash("success", "Event created successfully!")
	return ctx.Response().Redirect(302, "/calendar")
}
