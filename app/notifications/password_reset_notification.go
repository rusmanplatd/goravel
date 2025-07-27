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

	resetURL := fmt.Sprintf("%s/reset-password?token=%s&email=%s", getAppURL(), resetToken, userEmail)
	expiresAt := time.Now().Add(1 * time.Hour)

	// Set notification properties using modern interface
	notification.SetType("PasswordResetNotification").
		SetTemplate("password_reset_email").
		SetTitle("Password Reset Request").
		SetBody("You requested a password reset. Click the button below to reset your password.").
		SetSubject("Password Reset Request").
		SetChannels([]string{"mail"}). // Only send via email for security
		SetActionURL(resetURL).
		SetActionText("Reset Password").
		SetIcon("🔐").
		SetColor("#ffc107").
		SetPriority(notificationcore.PriorityHigh).
		SetCategory("security").
		AddTag("password-reset").
		AddTag("security").
		SetExpiresAt(expiresAt)

	// Add custom data for template rendering
	notification.AddData("reset_token", resetToken).
		AddData("user_email", userEmail).
		AddData("reset_url", resetURL).
		AddData("expires_at", expiresAt.Format(time.RFC3339)).
		AddData("expires_in", "60"). // 60 minutes
		AddData("app_name", getAppName())

	// Set analytics tracking
	notification.SetTrackOpens(true).
		SetTrackClicks(true).
		AddAnalyticsData("reset_type", "email").
		AddAnalyticsData("requested_at", time.Now())

	// Add delivery conditions for security
	notification.AddDeliveryCondition(notificationcore.DeliveryCondition{
		Type:     "preference",
		Operator: "enabled",
		Value:    "security_notifications",
	})

	return notification
}

// GetResetToken returns the reset token
func (n *PasswordResetNotification) GetResetToken() string {
	return n.resetToken
}

// SetResetToken sets the reset token and updates related data
func (n *PasswordResetNotification) SetResetToken(resetToken string) *PasswordResetNotification {
	n.resetToken = resetToken
	n.AddData("reset_token", resetToken)

	// Update the reset URL
	resetURL := fmt.Sprintf("%s/reset-password?token=%s&email=%s", getAppURL(), resetToken, n.userEmail)
	n.SetActionURL(resetURL)
	n.AddData("reset_url", resetURL)

	return n
}

// GetUserEmail returns the user email
func (n *PasswordResetNotification) GetUserEmail() string {
	return n.userEmail
}

// SetUserEmail sets the user email and updates related data
func (n *PasswordResetNotification) SetUserEmail(userEmail string) *PasswordResetNotification {
	n.userEmail = userEmail
	n.AddData("user_email", userEmail)

	// Update the reset URL
	resetURL := fmt.Sprintf("%s/reset-password?token=%s&email=%s", getAppURL(), n.resetToken, userEmail)
	n.SetActionURL(resetURL)
	n.AddData("reset_url", resetURL)

	return n
}

// ShouldSend determines if the notification should be sent
func (n *PasswordResetNotification) ShouldSend(notifiable notificationcore.Notifiable) bool {
	// Only send if the notifiable has an email address
	if notifiable.GetEmail() == "" {
		return false
	}

	// Call parent ShouldSend to check other conditions (expiration, delivery conditions, etc.)
	return n.BaseNotification.ShouldSend(notifiable)
}
