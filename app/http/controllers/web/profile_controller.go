package web

import (
	"github.com/goravel/framework/contracts/http"
)

type ProfileController struct {
	//Dependent services
}

func NewProfileController() *ProfileController {
	return &ProfileController{}
}

// Index displays the user profile page
func (r *ProfileController) Index(ctx http.Context) http.Response {
	user := ctx.Value("user")
	if user == nil {
		return ctx.Response().Redirect(302, "/login")
	}

	// Get user profile data
	data := map[string]interface{}{
		"title": "User Profile",
		"user":  user,
		"profile": map[string]interface{}{
			"avatar":      "/images/default-avatar.png",
			"bio":         "Software developer passionate about creating innovative solutions.",
			"phone":       "+1 (555) 123-4567",
			"location":    "San Francisco, CA",
			"website":     "https://johndoe.dev",
			"joined_date": "January 15, 2023",
			"last_login":  "2024-01-16 10:30 AM",
			"timezone":    "Pacific Standard Time",
			"language":    "English (US)",
		},
		"stats": map[string]interface{}{
			"projects_created": 8,
			"tasks_completed":  156,
			"messages_sent":    892,
			"files_uploaded":   45,
		},
		"recent_activity": []map[string]interface{}{
			{
				"action":      "Created task",
				"description": "Implement user authentication",
				"time":        "2 hours ago",
				"icon":        "fas fa-tasks",
				"color":       "text-primary",
			},
			{
				"action":      "Uploaded file",
				"description": "project-proposal.pdf",
				"time":        "4 hours ago",
				"icon":        "fas fa-file-upload",
				"color":       "text-success",
			},
			{
				"action":      "Joined meeting",
				"description": "Weekly team sync",
				"time":        "1 day ago",
				"icon":        "fas fa-video",
				"color":       "text-info",
			},
		},
	}

	return ctx.Response().View().Make("profile/index.tmpl", data)
}

// Edit displays the profile edit form
func (r *ProfileController) Edit(ctx http.Context) http.Response {
	user := ctx.Value("user")
	if user == nil {
		return ctx.Response().Redirect(302, "/login")
	}

	data := map[string]interface{}{
		"title": "Edit Profile",
		"user":  user,
	}

	return ctx.Response().View().Make("profile/edit.tmpl", data)
}

// Update handles profile updates
func (r *ProfileController) Update(ctx http.Context) http.Response {
	user := ctx.Value("user")
	if user == nil {
		return ctx.Response().Redirect(302, "/login")
	}

	// Handle profile update logic here
	ctx.Request().Session().Flash("success", "Profile updated successfully!")
	return ctx.Response().Redirect(302, "/profile")
}

// Settings displays the user settings page
func (r *ProfileController) Settings(ctx http.Context) http.Response {
	user := ctx.Value("user")
	if user == nil {
		return ctx.Response().Redirect(302, "/login")
	}

	data := map[string]interface{}{
		"title": "User Settings",
		"user":  user,
		"settings": map[string]interface{}{
			"email_notifications": true,
			"push_notifications":  true,
			"weekly_digest":       false,
			"marketing_emails":    false,
			"two_factor_enabled":  true,
			"session_timeout":     30,
			"theme":               "light",
			"language":            "en",
			"timezone":            "America/Los_Angeles",
		},
	}

	return ctx.Response().View().Make("profile/settings.tmpl", data)
}

// UpdateSettings handles settings updates
func (r *ProfileController) UpdateSettings(ctx http.Context) http.Response {
	user := ctx.Value("user")
	if user == nil {
		return ctx.Response().Redirect(302, "/login")
	}

	// Handle settings update logic here
	ctx.Request().Session().Flash("success", "Settings updated successfully!")
	return ctx.Response().Redirect(302, "/profile/settings")
}
