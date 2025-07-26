package web

import (
	"github.com/goravel/framework/contracts/http"
)

type ChatController struct {
	//Dependent services
}

func NewChatController() *ChatController {
	return &ChatController{}
}

// Index displays the chat rooms page
func (r *ChatController) Index(ctx http.Context) http.Response {
	user := ctx.Value("user")
	if user == nil {
		return ctx.Response().Redirect(302, "/login")
	}

	// Get chat rooms data from API or service
	// For now, we'll create a basic template with demo data
	data := map[string]interface{}{
		"title": "Chat Rooms",
		"user":  user,
		"rooms": []map[string]interface{}{
			{
				"id":          1,
				"name":        "General Discussion",
				"description": "General team discussions and announcements",
				"members":     15,
				"unread":      3,
				"last_message": map[string]interface{}{
					"content": "Welcome to the team chat!",
					"time":    "2 minutes ago",
					"sender":  "John Doe",
				},
			},
			{
				"id":          2,
				"name":        "Development Team",
				"description": "Technical discussions and code reviews",
				"members":     8,
				"unread":      0,
				"last_message": map[string]interface{}{
					"content": "The new feature is ready for testing",
					"time":    "1 hour ago",
					"sender":  "Jane Smith",
				},
			},
			{
				"id":          3,
				"name":        "Project Alpha",
				"description": "Project-specific communications",
				"members":     5,
				"unread":      1,
				"last_message": map[string]interface{}{
					"content": "Meeting scheduled for tomorrow",
					"time":    "3 hours ago",
					"sender":  "Mike Johnson",
				},
			},
		},
	}

	return ctx.Response().View().Make("chat/index.tmpl", data)
}

// Show displays a specific chat room
func (r *ChatController) Show(ctx http.Context) http.Response {
	user := ctx.Value("user")
	if user == nil {
		return ctx.Response().Redirect(302, "/login")
	}

	roomId := ctx.Request().Route("id")

	// Get specific chat room data
	data := map[string]interface{}{
		"title": "Chat Room",
		"user":  user,
		"room": map[string]interface{}{
			"id":          roomId,
			"name":        "General Discussion",
			"description": "General team discussions and announcements",
			"members":     15,
		},
		"messages": []map[string]interface{}{
			{
				"id":      1,
				"sender":  "John Doe",
				"content": "Hello everyone! Welcome to our team chat.",
				"time":    "10:30 AM",
				"avatar":  "JD",
			},
			{
				"id":      2,
				"sender":  "Jane Smith",
				"content": "Thanks John! Excited to be working with the team.",
				"time":    "10:32 AM",
				"avatar":  "JS",
			},
			{
				"id":      3,
				"sender":  "Mike Johnson",
				"content": "Let's make this project a success!",
				"time":    "10:35 AM",
				"avatar":  "MJ",
			},
		},
	}

	return ctx.Response().View().Make("chat/show.tmpl", data)
}

// Create displays the form to create a new chat room
func (r *ChatController) Create(ctx http.Context) http.Response {
	user := ctx.Value("user")
	if user == nil {
		return ctx.Response().Redirect(302, "/login")
	}

	data := map[string]interface{}{
		"title": "Create Chat Room",
		"user":  user,
	}

	return ctx.Response().View().Make("chat/create.tmpl", data)
}

// Store handles the creation of a new chat room
func (r *ChatController) Store(ctx http.Context) http.Response {
	user := ctx.Value("user")
	if user == nil {
		return ctx.Response().Redirect(302, "/login")
	}

	// Validate and store the chat room
	// For now, just redirect with success message
	ctx.Request().Session().Flash("success", "Chat room created successfully!")
	return ctx.Response().Redirect(302, "/chat")
}
