package web

import (
	"fmt"
	"time"

	"github.com/goravel/framework/contracts/http"
	"github.com/goravel/framework/facades"

	"goravel/app/models"
)

type ProfileController struct {
	//Dependent services
}

func NewProfileController() *ProfileController {
	return &ProfileController{}
}

// Index displays the user profile page
func (r *ProfileController) Index(ctx http.Context) http.Response {
	user, ok := ctx.Value("user").(*models.User)
	if !ok {
		return ctx.Response().Redirect(302, "/login")
	}

	// Get user profile data from database
	var userProfile models.UserProfile
	err := facades.Orm().Query().Where("user_id = ?", user.ID).First(&userProfile)
	if err != nil {
		// Create default profile if none exists
		userProfile = models.UserProfile{
			UserID:   user.ID,
			Timezone: "UTC",
			Locale:   "en-US",
			Language: "en",
			Currency: "USD",
		}
		facades.Orm().Query().Create(&userProfile)
	}

	// Get user statistics from various tables
	stats := r.getUserStats(user.ID)

	// Get recent activity from activity logs
	recentActivity := r.getRecentActivity(user.ID)

	// Build profile data
	profileData := map[string]interface{}{
		"avatar":      r.getUserAvatar(user),
		"bio":         r.getStringValue(userProfile.Bio),
		"phone":       user.Phone,
		"location":    r.getFormattedLocation(&userProfile),
		"website":     r.getStringValue(userProfile.Website),
		"joined_date": user.CreatedAt.Format("January 2, 2006"),
		"last_login":  r.getFormattedLastLogin(user),
		"timezone":    userProfile.Timezone,
		"language":    r.getFormattedLanguage(userProfile.Language, userProfile.Locale),
		"company":     r.getStringValue(userProfile.Company),
		"job_title":   r.getStringValue(userProfile.JobTitle),
		"department":  r.getStringValue(userProfile.Department),
	}

	data := map[string]interface{}{
		"title":           "User Profile",
		"user":            user,
		"profile":         profileData,
		"stats":           stats,
		"recent_activity": recentActivity,
	}

	return ctx.Response().View().Make("profile/index.tmpl", data)
}

// getUserStats gets user statistics from database
func (r *ProfileController) getUserStats(userID string) map[string]interface{} {
	stats := make(map[string]interface{})

	// Get project count
	projectCount, _ := facades.Orm().Query().Table("projects").
		Where("created_by = ?", userID).Count()
	stats["projects_created"] = projectCount

	// Get completed tasks count
	tasksCompleted, _ := facades.Orm().Query().Table("tasks").
		Where("assignee_id = ? AND status = ?", userID, "done").Count()
	stats["tasks_completed"] = tasksCompleted

	// Get messages sent count
	messagesSent, _ := facades.Orm().Query().Table("chat_messages").
		Where("sender_id = ?", userID).Count()
	stats["messages_sent"] = messagesSent

	// Get files uploaded count
	filesUploaded, _ := facades.Orm().Query().Table("files").
		Where("created_by = ?", userID).Count()
	stats["files_uploaded"] = filesUploaded

	// Get meetings attended count
	meetingsAttended, _ := facades.Orm().Query().Table("meeting_participants").
		Where("user_id = ?", userID).Count()
	stats["meetings_attended"] = meetingsAttended

	// Get calendar events created count
	eventsCreated, _ := facades.Orm().Query().Table("calendar_events").
		Where("created_by = ?", userID).Count()
	stats["events_created"] = eventsCreated

	return stats
}

// getRecentActivity gets recent user activity from activity logs
func (r *ProfileController) getRecentActivity(userID string) []map[string]interface{} {
	var activities []models.ActivityLog

	err := facades.Orm().Query().
		Where("causer_id = ?", userID).
		Order("created_at DESC").
		Limit(10).
		Find(&activities)

	if err != nil {
		facades.Log().Warning("Failed to get recent activity", map[string]interface{}{
			"user_id": userID,
			"error":   err.Error(),
		})
		return []map[string]interface{}{}
	}

	var recentActivity []map[string]interface{}
	for _, activity := range activities {
		activityData := map[string]interface{}{
			"action":      r.getActivityAction(activity.Description),
			"description": activity.Description,
			"time":        r.getRelativeTime(activity.CreatedAt),
			"icon":        r.getActivityIcon(activity.LogName),
			"color":       r.getActivityColor(activity.Severity),
		}
		recentActivity = append(recentActivity, activityData)
	}

	return recentActivity
}

// Helper methods

func (r *ProfileController) getUserAvatar(user *models.User) string {
	if user.Avatar != "" {
		return user.Avatar
	}
	return "/images/default-avatar.png"
}

func (r *ProfileController) getStringValue(ptr *string) string {
	if ptr != nil {
		return *ptr
	}
	return ""
}

func (r *ProfileController) getFormattedLocation(profile *models.UserProfile) string {
	location := ""

	if profile.Locality != nil {
		location += *profile.Locality
	}

	if profile.Region != nil {
		if location != "" {
			location += ", "
		}
		location += *profile.Region
	}

	if profile.CountryCode != nil {
		if location != "" {
			location += ", "
		}
		location += *profile.CountryCode
	}

	if location == "" {
		return "Location not specified"
	}

	return location
}

func (r *ProfileController) getFormattedLastLogin(user *models.User) string {
	if user.LastLoginAt != nil {
		return user.LastLoginAt.Format("January 2, 2006 3:04 PM")
	}
	return "Never"
}

func (r *ProfileController) getFormattedLanguage(language, locale string) string {
	languageMap := map[string]string{
		"en": "English",
		"es": "Spanish",
		"fr": "French",
		"de": "German",
		"it": "Italian",
		"pt": "Portuguese",
		"ru": "Russian",
		"ja": "Japanese",
		"ko": "Korean",
		"zh": "Chinese",
	}

	if displayName, exists := languageMap[language]; exists {
		if locale != "" {
			return displayName + " (" + locale + ")"
		}
		return displayName
	}

	return language
}

func (r *ProfileController) getActivityAction(description string) string {
	actionMap := map[string]string{
		"user_login":             "Logged in",
		"user_logout":            "Logged out",
		"task_created":           "Created task",
		"task_completed":         "Completed task",
		"file_uploaded":          "Uploaded file",
		"meeting_joined":         "Joined meeting",
		"meeting_left":           "Left meeting",
		"message_sent":           "Sent message",
		"project_created":        "Created project",
		"calendar_event_created": "Created event",
		"profile_updated":        "Updated profile",
	}

	if action, exists := actionMap[description]; exists {
		return action
	}

	return description
}

func (r *ProfileController) getActivityIcon(logName string) string {
	iconMap := map[string]string{
		"user_login":             "fas fa-sign-in-alt",
		"user_logout":            "fas fa-sign-out-alt",
		"task_created":           "fas fa-tasks",
		"task_completed":         "fas fa-check-circle",
		"file_uploaded":          "fas fa-file-upload",
		"meeting_joined":         "fas fa-video",
		"meeting_left":           "fas fa-video-slash",
		"message_sent":           "fas fa-comment",
		"project_created":        "fas fa-project-diagram",
		"calendar_event_created": "fas fa-calendar-plus",
		"profile_updated":        "fas fa-user-edit",
	}

	if icon, exists := iconMap[logName]; exists {
		return icon
	}

	return "fas fa-info-circle"
}

func (r *ProfileController) getActivityColor(severity models.ActivityLogSeverity) string {
	colorMap := map[models.ActivityLogSeverity]string{
		models.SeverityInfo:     "text-info",
		models.SeverityLow:      "text-secondary",
		models.SeverityMedium:   "text-warning",
		models.SeverityHigh:     "text-danger",
		models.SeverityCritical: "text-danger",
	}

	if color, exists := colorMap[severity]; exists {
		return color
	}

	return "text-primary"
}

func (r *ProfileController) getRelativeTime(timestamp time.Time) string {
	now := time.Now()
	diff := now.Sub(timestamp)

	if diff < time.Minute {
		return "Just now"
	} else if diff < time.Hour {
		minutes := int(diff.Minutes())
		if minutes == 1 {
			return "1 minute ago"
		}
		return fmt.Sprintf("%d minutes ago", minutes)
	} else if diff < 24*time.Hour {
		hours := int(diff.Hours())
		if hours == 1 {
			return "1 hour ago"
		}
		return fmt.Sprintf("%d hours ago", hours)
	} else if diff < 7*24*time.Hour {
		days := int(diff.Hours() / 24)
		if days == 1 {
			return "1 day ago"
		}
		return fmt.Sprintf("%d days ago", days)
	} else {
		return timestamp.Format("January 2, 2006")
	}
}

// Edit displays the profile edit form
func (r *ProfileController) Edit(ctx http.Context) http.Response {
	user := ctx.Value("user")
	if user == nil {
		return ctx.Response().Redirect(302, "/login")
	}

	return ctx.Response().View().Make("profile/edit.tmpl", map[string]interface{}{
		"title": "Edit Profile",
		"user":  user,
	})
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
