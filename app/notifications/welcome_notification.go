package notifications

import (
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

	// Set notification properties
	notification.SetType("WelcomeNotification")
	notification.SetTitle("Welcome to " + getAppName())
	notification.SetBody("Hi " + userName + ", welcome to our platform! We're excited to have you on board.")
	notification.SetMessage("Welcome to our platform!")
	notification.SetSubject("Welcome to " + getAppName())
	notification.SetChannels([]string{"database", "mail"})
	notification.SetActionURL(getAppURL() + "/dashboard")
	notification.SetActionText("Go to Dashboard")
	notification.SetIcon("🎉")
	notification.SetColor("success")
	notification.SetPriority("normal")
	notification.SetCategory("welcome")
	notification.AddTag("welcome")
	notification.AddTag("new-user")

	// Add custom data
	notification.AddData("user_name", userName)
	notification.AddData("welcome_date", time.Now().Format("2006-01-02"))

	return notification
}

// GetUserName returns the user name
func (n *WelcomeNotification) GetUserName() string {
	return n.userName
}

// SetUserName sets the user name
func (n *WelcomeNotification) SetUserName(userName string) {
	n.userName = userName
	n.AddData("user_name", userName)
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
