package notifications

import (
	"goravel/app/notificationcore"
	"time"
)

// WelcomeNotification is sent to new users when they register
type WelcomeNotification struct {
	*BaseNotification
	userName string
}

// NewWelcomeNotification creates a new welcome notification
func NewWelcomeNotification(userName string) *WelcomeNotification {
	notification := &WelcomeNotification{
		BaseNotification: NewBaseNotification(),
		userName:         userName,
	}

	// Set notification properties using modern interface
	notification.SetType("WelcomeNotification").
		SetTemplate("welcome_email").
		SetTitle("Welcome to " + getAppName()).
		SetBody("Hi " + userName + ", welcome to our platform! We're excited to have you on board.").
		SetSubject("Welcome to " + getAppName()).
		SetChannels([]string{"database", "mail", "push"}).
		SetActionURL(getAppURL() + "/dashboard").
		SetActionText("Go to Dashboard").
		SetIcon("🎉").
		SetColor("#28a745").
		SetPriority(notificationcore.PriorityNormal).
		SetCategory("welcome").
		AddTag("welcome").
		AddTag("new-user")

	// Add custom data for template rendering
	notification.AddData("user_name", userName).
		AddData("welcome_date", time.Now().Format("2006-01-02")).
		AddData("app_name", getAppName()).
		AddData("dashboard_url", getAppURL()+"/dashboard")

	// Set analytics tracking
	notification.SetTrackOpens(true).
		SetTrackClicks(true).
		AddAnalyticsData("user_type", "new_user").
		AddAnalyticsData("registration_date", time.Now())

	return notification
}

// GetUserName returns the user name
func (n *WelcomeNotification) GetUserName() string {
	return n.userName
}

// SetUserName sets the user name and updates related data
func (n *WelcomeNotification) SetUserName(userName string) *WelcomeNotification {
	n.userName = userName
	n.AddData("user_name", userName)

	// Update the body with the new user name
	n.SetBody("Hi " + userName + ", welcome to our platform! We're excited to have you on board.")

	return n
}

// getAppName returns the application name
func getAppName() string {
	// In a real implementation, you'd get this from config
	return "Goravel"
}

// getAppURL returns the application URL
func getAppURL() string {
	// In a real implementation, you'd get this from config
	return "https://example.com"
}
