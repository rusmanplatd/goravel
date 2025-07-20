package notifications

import (
	"fmt"
	"goravel/app/notificationcore"
	"time"
)

// PasswordResetNotification is sent when a user requests a password reset
type PasswordResetNotification struct {
	*BaseNotification
	resetToken string
	userEmail  string
}

// NewPasswordResetNotification creates a new password reset notification
func NewPasswordResetNotification(userEmail, resetToken string) *PasswordResetNotification {
	notification := &PasswordResetNotification{
		BaseNotification: NewBaseNotification(),
		resetToken:       resetToken,
		userEmail:        userEmail,
	}

	// Set notification properties
	notification.SetType("PasswordResetNotification")
	notification.SetTitle("Password Reset Request")
	notification.SetBody("You requested a password reset. Click the button below to reset your password.")
	notification.SetMessage("Password reset requested")
	notification.SetSubject("Password Reset Request")
	notification.SetChannels([]string{"mail"}) // Only send via email for security
	notification.SetActionURL(fmt.Sprintf("%s/reset-password?token=%s&email=%s", getAppURL(), resetToken, userEmail))
	notification.SetActionText("Reset Password")
	notification.SetIcon("🔐")
	notification.SetColor("warning")
	notification.SetPriority("high")
	notification.SetCategory("security")
	notification.AddTag("password-reset")
	notification.AddTag("security")

	// Add custom data
	notification.AddData("reset_token", resetToken)
	notification.AddData("user_email", userEmail)
	notification.AddData("reset_url", notification.GetActionURL())
	notification.AddData("expires_at", time.Now().Add(1*time.Hour).Format(time.RFC3339))

	return notification
}

// GetResetToken returns the reset token
func (n *PasswordResetNotification) GetResetToken() string {
	return n.resetToken
}

// SetResetToken sets the reset token
func (n *PasswordResetNotification) SetResetToken(resetToken string) {
	n.resetToken = resetToken
	n.AddData("reset_token", resetToken)
}

// GetUserEmail returns the user email
func (n *PasswordResetNotification) GetUserEmail() string {
	return n.userEmail
}

// SetUserEmail sets the user email
func (n *PasswordResetNotification) SetUserEmail(userEmail string) {
	n.userEmail = userEmail
	n.AddData("user_email", userEmail)
}

// ShouldSend determines if the notification should be sent
func (n *PasswordResetNotification) ShouldSend(notifiable notificationcore.Notifiable) bool {
	// Only send if the notifiable has an email address
	return notifiable.GetEmail() != ""
}
