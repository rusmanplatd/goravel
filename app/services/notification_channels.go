package services

import (
	"context"
	"encoding/json"
	"fmt"
	"html/template"
	"strings"
	"time"

	"goravel/app/models"
	"goravel/app/notificationcore"

	"bytes"
	"net/http"

	"github.com/SherClockHolmes/webpush-go"
	"github.com/goravel/framework/facades"
)

// DatabaseNotificationChannel handles storing notifications in the database
type DatabaseNotificationChannel struct{}

// NewDatabaseNotificationChannel creates a new database notification channel
func NewDatabaseNotificationChannel() *DatabaseNotificationChannel {
	return &DatabaseNotificationChannel{}
}

// GetName returns the channel name
func (c *DatabaseNotificationChannel) GetName() string {
	return "database"
}

// GetVersion returns the channel version
func (c *DatabaseNotificationChannel) GetVersion() string {
	return "2.0"
}

// IsEnabled checks if the channel is enabled
func (c *DatabaseNotificationChannel) IsEnabled() bool {
	return facades.Config().GetBool("notification.channels.database.enabled", true)
}

// Validate validates the channel configuration
func (c *DatabaseNotificationChannel) Validate() error {
	// Database channel is always valid if enabled
	return nil
}

// GetConfig returns the channel configuration
func (c *DatabaseNotificationChannel) GetConfig() map[string]interface{} {
	return map[string]interface{}{
		"enabled": c.IsEnabled(),
		"version": c.GetVersion(),
	}
}

// SupportsBatching returns whether the channel supports batching
func (c *DatabaseNotificationChannel) SupportsBatching() bool {
	return true
}

// SupportsScheduling returns whether the channel supports scheduling
func (c *DatabaseNotificationChannel) SupportsScheduling() bool {
	return true
}

// SupportsRichContent returns whether the channel supports rich content
func (c *DatabaseNotificationChannel) SupportsRichContent() bool {
	return true
}

// GetMaxBatchSize returns the maximum batch size
func (c *DatabaseNotificationChannel) GetMaxBatchSize() int {
	return 1000
}

// GetRateLimit returns the rate limit for this channel
func (c *DatabaseNotificationChannel) GetRateLimit() int {
	return facades.Config().GetInt("notification.channels.database.rate_limit", 1000)
}

// GetRateLimitWindow returns the rate limit window
func (c *DatabaseNotificationChannel) GetRateLimitWindow() time.Duration {
	return time.Hour
}

// SupportsDeliveryConfirmation returns whether the channel supports delivery confirmation
func (c *DatabaseNotificationChannel) SupportsDeliveryConfirmation() bool {
	return true
}

// SupportsReadReceipts returns whether the channel supports read receipts
func (c *DatabaseNotificationChannel) SupportsReadReceipts() bool {
	return true
}

// SupportsTemplates returns whether the channel supports templates
func (c *DatabaseNotificationChannel) SupportsTemplates() bool {
	return false
}

// RenderTemplate renders a template (not supported for database channel)
func (c *DatabaseNotificationChannel) RenderTemplate(template string, data map[string]interface{}) (string, error) {
	return "", fmt.Errorf("template rendering not supported for database channel")
}

// Send stores the notification in the database
func (c *DatabaseNotificationChannel) Send(ctx context.Context, notification notificationcore.Notification, notifiable notificationcore.Notifiable) error {
	// Create notification record
	notificationRecord := &models.Notification{
		Type:           notification.GetType(),
		Data:           notification.GetData(),
		NotifiableID:   notifiable.GetID(),
		NotifiableType: notifiable.GetType(),
		Channel:        c.GetName(),
		ReadAt:         nil,
		SentAt:         &time.Time{},
		FailedAt:       nil,
		Priority:       string(notification.GetPriority()),
		ExpiresAt:      notification.GetExpiresAt(),
		Metadata:       notification.GetMetadata(),
	}

	// Mark as sent
	notificationRecord.MarkAsSent()

	// Save to database
	if err := facades.Orm().Query().Create(notificationRecord); err != nil {
		return fmt.Errorf("failed to save notification to database: %w", err)
	}

	facades.Log().Info("Notification saved to database", map[string]interface{}{
		"notification_id": notificationRecord.ID,
		"type":            notification.GetType(),
		"notifiable_id":   notifiable.GetID(),
	})

	return nil
}

// MailNotificationChannel handles sending notifications via email
type MailNotificationChannel struct{}

// NewMailNotificationChannel creates a new mail notification channel
func NewMailNotificationChannel() *MailNotificationChannel {
	return &MailNotificationChannel{}
}

// GetName returns the channel name
func (c *MailNotificationChannel) GetName() string {
	return "mail"
}

// GetVersion returns the channel version
func (c *MailNotificationChannel) GetVersion() string {
	return "2.0"
}

// IsEnabled checks if the channel is enabled
func (c *MailNotificationChannel) IsEnabled() bool {
	return facades.Config().GetBool("notification.channels.mail.enabled", true)
}

// Validate validates the channel configuration
func (c *MailNotificationChannel) Validate() error {
	// Check if mail service is configured
	emailService := NewEmailService()
	if !emailService.IsMailConfigured() {
		return fmt.Errorf("mail service is not configured")
	}
	return nil
}

// GetConfig returns the channel configuration
func (c *MailNotificationChannel) GetConfig() map[string]interface{} {
	return map[string]interface{}{
		"enabled":            c.IsEnabled(),
		"version":            c.GetVersion(),
		"supports_html":      true,
		"supports_text":      true,
		"supports_templates": true,
	}
}

// SupportsBatching returns whether the channel supports batching
func (c *MailNotificationChannel) SupportsBatching() bool {
	return true
}

// SupportsScheduling returns whether the channel supports scheduling
func (c *MailNotificationChannel) SupportsScheduling() bool {
	return true
}

// SupportsRichContent returns whether the channel supports rich content
func (c *MailNotificationChannel) SupportsRichContent() bool {
	return true
}

// GetMaxBatchSize returns the maximum batch size
func (c *MailNotificationChannel) GetMaxBatchSize() int {
	return 100
}

// GetRateLimit returns the rate limit for this channel
func (c *MailNotificationChannel) GetRateLimit() int {
	return facades.Config().GetInt("notification.channels.mail.rate_limit", 50)
}

// GetRateLimitWindow returns the rate limit window
func (c *MailNotificationChannel) GetRateLimitWindow() time.Duration {
	return time.Hour
}

// SupportsDeliveryConfirmation returns whether the channel supports delivery confirmation
func (c *MailNotificationChannel) SupportsDeliveryConfirmation() bool {
	return true
}

// SupportsReadReceipts returns whether the channel supports read receipts
func (c *MailNotificationChannel) SupportsReadReceipts() bool {
	return true
}

// SupportsTemplates returns whether the channel supports templates
func (c *MailNotificationChannel) SupportsTemplates() bool {
	return true
}

// RenderTemplate renders an email template
func (c *MailNotificationChannel) RenderTemplate(templateStr string, data map[string]interface{}) (string, error) {
	tmpl, err := template.New("email").Parse(templateStr)
	if err != nil {
		return "", fmt.Errorf("failed to parse template: %w", err)
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return "", fmt.Errorf("failed to execute template: %w", err)
	}

	return buf.String(), nil
}

// Send sends the notification via email
func (c *MailNotificationChannel) Send(ctx context.Context, notification notificationcore.Notification, notifiable notificationcore.Notifiable) error {
	emailService := NewEmailService()

	// Check if mail is configured
	if !emailService.IsMailConfigured() {
		return fmt.Errorf("mail service is not configured")
	}

	// Get recipient email
	recipientEmail := notifiable.GetEmail()
	if recipientEmail == "" {
		return fmt.Errorf("notifiable does not have an email address")
	}

	// Generate email content
	subject := c.generateSubject(notification, notifiable)
	htmlContent := c.generateHTMLContent(notification, notifiable)
	textContent := c.generateTextContent(notification, notifiable)

	// Send email
	err := emailService.SendEmail(recipientEmail, subject, htmlContent, textContent)
	if err != nil {
		facades.Log().Error("Failed to send notification email", map[string]interface{}{
			"recipient":         recipientEmail,
			"notification_type": notification.GetType(),
			"error":             err.Error(),
		})
		return fmt.Errorf("failed to send email: %w", err)
	}

	facades.Log().Info("Notification email sent successfully", map[string]interface{}{
		"recipient":         recipientEmail,
		"notification_type": notification.GetType(),
		"subject":           subject,
	})

	return nil
}

// generateSubject generates the email subject
func (c *MailNotificationChannel) generateSubject(notification notificationcore.Notification, notifiable notificationcore.Notifiable) string {
	subject := notification.GetSubject()
	if subject == "" {
		subject = notification.GetTitle()
	}
	if subject == "" {
		subject = "New Notification"
	}
	return subject
}

// generateHTMLContent generates the HTML email content
func (c *MailNotificationChannel) generateHTMLContent(notification notificationcore.Notification, notifiable notificationcore.Notifiable) string {
	// Try to get HTML content from notification data
	if data := notification.GetData(); data != nil {
		if htmlContent, ok := data["html_content"].(string); ok && htmlContent != "" {
			return htmlContent
		}
	}

	// Fall back to default HTML template
	return c.renderDefaultHTMLTemplate(notification, notifiable)
}

// generateTextContent generates the plain text email content
func (c *MailNotificationChannel) generateTextContent(notification notificationcore.Notification, notifiable notificationcore.Notifiable) string {
	// Try to get text content from notification data
	if data := notification.GetData(); data != nil {
		if textContent, ok := data["text_content"].(string); ok && textContent != "" {
			return textContent
		}
	}

	// Fall back to default text template
	return c.renderDefaultTextTemplate(notification, notifiable)
}

// renderDefaultHTMLTemplate renders the default HTML email template
func (c *MailNotificationChannel) renderDefaultHTMLTemplate(notification notificationcore.Notification, notifiable notificationcore.Notifiable) string {
	// This is a simplified template rendering
	// In a real application, you'd load templates from files
	templateData := map[string]interface{}{
		"Title":        notification.GetTitle(),
		"Body":         notification.GetBody(),
		"ActionURL":    notification.GetActionURL(),
		"ActionText":   notification.GetActionText(),
		"NotifiableID": notifiable.GetID(),
		"Timestamp":    time.Now().Format("2006-01-02 15:04:05"),
	}

	// Simple HTML template
	htmlTemplate := `
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{.Title}}</title>
    <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
        .header { background-color: #f8f9fa; padding: 20px; text-align: center; }
        .content { padding: 30px 20px; }
        .footer { background-color: #f8f9fa; padding: 20px; text-align: center; font-size: 12px; color: #666; }
        .button { display: inline-block; padding: 12px 24px; background-color: #007bff; color: white; text-decoration: none; border-radius: 4px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>{{.Title}}</h1>
        </div>
        <div class="content">
            <p>{{.Body}}</p>
            {{if .ActionURL}}
            <p><a href="{{.ActionURL}}" class="button">{{.ActionText}}</a></p>
            {{end}}
        </div>
        <div class="footer">
            <p>Sent on {{.Timestamp}}</p>
        </div>
    </div>
</body>
</html>`

	tmpl, err := template.New("html").Parse(htmlTemplate)
	if err != nil {
		return notification.GetBody()
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, templateData); err != nil {
		return notification.GetBody()
	}

	return buf.String()
}

// renderDefaultTextTemplate renders the default text email template
func (c *MailNotificationChannel) renderDefaultTextTemplate(notification notificationcore.Notification, notifiable notificationcore.Notifiable) string {
	var content strings.Builder

	if title := notification.GetTitle(); title != "" {
		content.WriteString(title + "\n")
		content.WriteString(strings.Repeat("=", len(title)) + "\n\n")
	}

	if body := notification.GetBody(); body != "" {
		content.WriteString(body + "\n\n")
	}

	if actionURL := notification.GetActionURL(); actionURL != "" {
		actionText := notification.GetActionText()
		if actionText == "" {
			actionText = "Click here"
		}
		content.WriteString(actionText + ": " + actionURL + "\n\n")
	}

	content.WriteString("---\n")
	content.WriteString("Sent on " + time.Now().Format("2006-01-02 15:04:05"))

	return content.String()
}

// WebPushNotificationChannel handles sending web push notifications
type WebPushNotificationChannel struct{}

// NewWebPushNotificationChannel creates a new web push notification channel
func NewWebPushNotificationChannel() *WebPushNotificationChannel {
	return &WebPushNotificationChannel{}
}

// GetName returns the channel name
func (c *WebPushNotificationChannel) GetName() string {
	return "push"
}

// GetVersion returns the channel version
func (c *WebPushNotificationChannel) GetVersion() string {
	return "2.0"
}

// IsEnabled checks if the channel is enabled
func (c *WebPushNotificationChannel) IsEnabled() bool {
	return facades.Config().GetBool("notification.channels.push.enabled", true)
}

// Validate validates the channel configuration
func (c *WebPushNotificationChannel) Validate() error {
	vapidPublicKey := facades.Config().GetString("notification.channels.push.vapid_public_key")
	vapidPrivateKey := facades.Config().GetString("notification.channels.push.vapid_private_key")

	if vapidPublicKey == "" || vapidPrivateKey == "" {
		return fmt.Errorf("VAPID keys are not configured")
	}

	return nil
}

// GetConfig returns the channel configuration
func (c *WebPushNotificationChannel) GetConfig() map[string]interface{} {
	return map[string]interface{}{
		"enabled":          c.IsEnabled(),
		"version":          c.GetVersion(),
		"vapid_configured": facades.Config().GetString("notification.channels.push.vapid_public_key") != "",
	}
}

// SupportsBatching returns whether the channel supports batching
func (c *WebPushNotificationChannel) SupportsBatching() bool {
	return true
}

// SupportsScheduling returns whether the channel supports scheduling
func (c *WebPushNotificationChannel) SupportsScheduling() bool {
	return true
}

// SupportsRichContent returns whether the channel supports rich content
func (c *WebPushNotificationChannel) SupportsRichContent() bool {
	return true
}

// GetMaxBatchSize returns the maximum batch size
func (c *WebPushNotificationChannel) GetMaxBatchSize() int {
	return 100
}

// GetRateLimit returns the rate limit for this channel
func (c *WebPushNotificationChannel) GetRateLimit() int {
	return facades.Config().GetInt("notification.channels.push.rate_limit", 200)
}

// GetRateLimitWindow returns the rate limit window
func (c *WebPushNotificationChannel) GetRateLimitWindow() time.Duration {
	return time.Hour
}

// SupportsDeliveryConfirmation returns whether the channel supports delivery confirmation
func (c *WebPushNotificationChannel) SupportsDeliveryConfirmation() bool {
	return false
}

// SupportsReadReceipts returns whether the channel supports read receipts
func (c *WebPushNotificationChannel) SupportsReadReceipts() bool {
	return false
}

// SupportsTemplates returns whether the channel supports templates
func (c *WebPushNotificationChannel) SupportsTemplates() bool {
	return false
}

// RenderTemplate renders a template (not supported for push channel)
func (c *WebPushNotificationChannel) RenderTemplate(template string, data map[string]interface{}) (string, error) {
	return "", fmt.Errorf("template rendering not supported for push channel")
}

// Send sends the notification via web push
func (c *WebPushNotificationChannel) Send(ctx context.Context, notification notificationcore.Notification, notifiable notificationcore.Notifiable) error {
	// Get VAPID keys from config
	vapidPublicKey := facades.Config().GetString("notification.channels.push.vapid_public_key")
	vapidPrivateKey := facades.Config().GetString("notification.channels.push.vapid_private_key")
	vapidSubject := facades.Config().GetString("notification.channels.push.vapid_subject", "mailto:admin@example.com")

	if vapidPublicKey == "" || vapidPrivateKey == "" {
		return fmt.Errorf("VAPID keys are not configured")
	}

	// Get user's push subscriptions
	pushTokens := notifiable.GetPushTokens()
	if len(pushTokens) == 0 {
		return fmt.Errorf("notifiable does not have any push subscriptions")
	}

	// Create push notification payload
	payload := map[string]interface{}{
		"title": notification.GetTitle(),
		"body":  notification.GetBody(),
		"icon":  notification.GetIcon(),
		"badge": notification.GetIcon(),
		"data": map[string]interface{}{
			"url":    notification.GetActionURL(),
			"action": notification.GetActionText(),
			"type":   notification.GetType(),
		},
	}

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal push payload: %w", err)
	}

	// Send to all subscriptions
	var lastError error
	successCount := 0

	for _, token := range pushTokens {
		// Create subscription object (simplified - in real implementation, you'd parse the token)
		subscription := &webpush.Subscription{
			Endpoint: token,
			Keys: webpush.Keys{
				Auth:   "auth-key", // These would come from the token
				P256dh: "p256dh-key",
			},
		}

		// Send push notification
		resp, err := webpush.SendNotification(payloadBytes, subscription, &webpush.Options{
			VAPIDPublicKey:  vapidPublicKey,
			VAPIDPrivateKey: vapidPrivateKey,
			Subscriber:      vapidSubject,
		})

		if err != nil {
			facades.Log().Error("Failed to send push notification", map[string]interface{}{
				"endpoint": token,
				"error":    err.Error(),
			})
			lastError = err
			continue
		}

		resp.Body.Close()

		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			successCount++
		} else {
			facades.Log().Warning("Push notification returned non-success status", map[string]interface{}{
				"endpoint":    token,
				"status_code": resp.StatusCode,
			})
		}
	}

	if successCount == 0 && lastError != nil {
		return fmt.Errorf("failed to send push notification to any subscription: %w", lastError)
	}

	facades.Log().Info("Push notification sent", map[string]interface{}{
		"notification_type":   notification.GetType(),
		"success_count":       successCount,
		"total_subscriptions": len(pushTokens),
	})

	return nil
}

// WebSocketNotificationChannel handles sending notifications via WebSocket
type WebSocketNotificationChannel struct{}

// NewWebSocketNotificationChannel creates a new WebSocket notification channel
func NewWebSocketNotificationChannel() *WebSocketNotificationChannel {
	return &WebSocketNotificationChannel{}
}

// GetName returns the channel name
func (c *WebSocketNotificationChannel) GetName() string {
	return "websocket"
}

// GetVersion returns the channel version
func (c *WebSocketNotificationChannel) GetVersion() string {
	return "2.0"
}

// IsEnabled checks if the channel is enabled
func (c *WebSocketNotificationChannel) IsEnabled() bool {
	return facades.Config().GetBool("notification.channels.websocket.enabled", true)
}

// Validate validates the channel configuration
func (c *WebSocketNotificationChannel) Validate() error {
	// WebSocket channel is always valid if enabled
	return nil
}

// GetConfig returns the channel configuration
func (c *WebSocketNotificationChannel) GetConfig() map[string]interface{} {
	return map[string]interface{}{
		"enabled": c.IsEnabled(),
		"version": c.GetVersion(),
	}
}

// SupportsBatching returns whether the channel supports batching
func (c *WebSocketNotificationChannel) SupportsBatching() bool {
	return true
}

// SupportsScheduling returns whether the channel supports scheduling
func (c *WebSocketNotificationChannel) SupportsScheduling() bool {
	return false // Real-time only
}

// SupportsRichContent returns whether the channel supports rich content
func (c *WebSocketNotificationChannel) SupportsRichContent() bool {
	return true
}

// GetMaxBatchSize returns the maximum batch size
func (c *WebSocketNotificationChannel) GetMaxBatchSize() int {
	return 50
}

// GetRateLimit returns the rate limit for this channel
func (c *WebSocketNotificationChannel) GetRateLimit() int {
	return facades.Config().GetInt("notification.channels.websocket.rate_limit", 500)
}

// GetRateLimitWindow returns the rate limit window
func (c *WebSocketNotificationChannel) GetRateLimitWindow() time.Duration {
	return time.Minute
}

// SupportsDeliveryConfirmation returns whether the channel supports delivery confirmation
func (c *WebSocketNotificationChannel) SupportsDeliveryConfirmation() bool {
	return true
}

// SupportsReadReceipts returns whether the channel supports read receipts
func (c *WebSocketNotificationChannel) SupportsReadReceipts() bool {
	return true
}

// SupportsTemplates returns whether the channel supports templates
func (c *WebSocketNotificationChannel) SupportsTemplates() bool {
	return false
}

// RenderTemplate renders a template (not supported for WebSocket channel)
func (c *WebSocketNotificationChannel) RenderTemplate(template string, data map[string]interface{}) (string, error) {
	return "", fmt.Errorf("template rendering not supported for WebSocket channel")
}

// Send sends the notification via WebSocket
func (c *WebSocketNotificationChannel) Send(ctx context.Context, notification notificationcore.Notification, notifiable notificationcore.Notifiable) error {
	// Get the WebSocket hub
	hub := GetWebSocketHub()
	if hub == nil {
		return fmt.Errorf("WebSocket hub is not available")
	}

	// Create the notification message
	message := c.createWebSocketMessage(notification, notifiable)

	// Send to the specific user
	if err := hub.SendToUser(notifiable.GetID(), message); err != nil {
		facades.Log().Error("Failed to send WebSocket notification", map[string]interface{}{
			"notifiable_id":     notifiable.GetID(),
			"notification_type": notification.GetType(),
			"error":             err.Error(),
		})
		return fmt.Errorf("failed to send WebSocket notification: %w", err)
	}

	facades.Log().Info("WebSocket notification sent successfully", map[string]interface{}{
		"notifiable_id":     notifiable.GetID(),
		"notification_type": notification.GetType(),
	})

	return nil
}

// createWebSocketMessage creates the WebSocket notification message
func (c *WebSocketNotificationChannel) createWebSocketMessage(notification notificationcore.Notification, notifiable notificationcore.Notifiable) map[string]interface{} {
	return map[string]interface{}{
		"type": "notification",
		"data": map[string]interface{}{
			"id":          notification.GetID(),
			"title":       notification.GetTitle(),
			"body":        notification.GetBody(),
			"message":     notification.GetBody(),
			"action_url":  notification.GetActionURL(),
			"action_text": notification.GetActionText(),
			"icon":        notification.GetIcon(),
			"color":       notification.GetColor(),
			"priority":    notification.GetPriority(),
			"category":    notification.GetCategory(),
			"tags":        notification.GetTags(),
			"metadata":    notification.GetMetadata(),
			"timestamp":   time.Now().Unix(),
		},
	}
}

// SlackNotificationChannel handles sending notifications to Slack
// DiscordNotificationChannel handles sending notifications to Discord
// TelegramNotificationChannel handles sending notifications to Telegram
// SMSNotificationChannel handles sending notifications via SMS
// WebhookNotificationChannel handles sending notifications to a webhook
// LogNotificationChannel handles logging notifications

// SlackNotificationChannel
type SlackNotificationChannel struct{}

func NewSlackNotificationChannel() *SlackNotificationChannel {
	return &SlackNotificationChannel{}
}

func (c *SlackNotificationChannel) GetName() string    { return "slack" }
func (c *SlackNotificationChannel) GetVersion() string { return "2.0" }
func (c *SlackNotificationChannel) IsEnabled() bool {
	return facades.Config().GetBool("notification.channels.slack.enabled", true)
}
func (c *SlackNotificationChannel) Validate() error { return nil }
func (c *SlackNotificationChannel) GetConfig() map[string]interface{} {
	return map[string]interface{}{"enabled": c.IsEnabled(), "version": c.GetVersion()}
}
func (c *SlackNotificationChannel) SupportsBatching() bool             { return true }
func (c *SlackNotificationChannel) SupportsScheduling() bool           { return true }
func (c *SlackNotificationChannel) SupportsRichContent() bool          { return true }
func (c *SlackNotificationChannel) GetMaxBatchSize() int               { return 50 }
func (c *SlackNotificationChannel) GetRateLimit() int                  { return 100 }
func (c *SlackNotificationChannel) GetRateLimitWindow() time.Duration  { return time.Hour }
func (c *SlackNotificationChannel) SupportsDeliveryConfirmation() bool { return false }
func (c *SlackNotificationChannel) SupportsReadReceipts() bool         { return false }
func (c *SlackNotificationChannel) SupportsTemplates() bool            { return true }
func (c *SlackNotificationChannel) RenderTemplate(templateStr string, data map[string]interface{}) (string, error) {
	tmpl, err := template.New("slack").Parse(templateStr)
	if err != nil {
		return "", err
	}
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return "", err
	}
	return buf.String(), nil
}
func (c *SlackNotificationChannel) Send(ctx context.Context, notification notificationcore.Notification, notifiable notificationcore.Notifiable) error {
	webhookURL := facades.Config().GetString("notification.channels.slack.webhook_url")
	if webhookURL == "" {
		return fmt.Errorf("Slack webhook URL is not configured")
	}
	payload := map[string]interface{}{
		"channel":    facades.Config().GetString("notification.channels.slack.channel"),
		"username":   facades.Config().GetString("notification.channels.slack.username"),
		"icon_emoji": facades.Config().GetString("notification.channels.slack.icon"),
		"text":       notification.GetBody(),
	}
	b, _ := json.Marshal(payload)
	resp, err := http.Post(webhookURL, "application/json", bytes.NewBuffer(b))
	if err != nil {
		facades.Log().Error("Failed to send Slack notification", map[string]interface{}{"error": err.Error()})
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("Slack webhook returned status %d", resp.StatusCode)
	}
	facades.Log().Info("Slack notification sent", map[string]interface{}{"channel": payload["channel"]})
	return nil
}

// DiscordNotificationChannel
type DiscordNotificationChannel struct{}

func NewDiscordNotificationChannel() *DiscordNotificationChannel {
	return &DiscordNotificationChannel{}
}

func (c *DiscordNotificationChannel) GetName() string    { return "discord" }
func (c *DiscordNotificationChannel) GetVersion() string { return "2.0" }
func (c *DiscordNotificationChannel) IsEnabled() bool {
	return facades.Config().GetBool("notification.channels.discord.enabled", true)
}
func (c *DiscordNotificationChannel) Validate() error { return nil }
func (c *DiscordNotificationChannel) GetConfig() map[string]interface{} {
	return map[string]interface{}{"enabled": c.IsEnabled(), "version": c.GetVersion()}
}
func (c *DiscordNotificationChannel) SupportsBatching() bool             { return true }
func (c *DiscordNotificationChannel) SupportsScheduling() bool           { return true }
func (c *DiscordNotificationChannel) SupportsRichContent() bool          { return true }
func (c *DiscordNotificationChannel) GetMaxBatchSize() int               { return 50 }
func (c *DiscordNotificationChannel) GetRateLimit() int                  { return 100 }
func (c *DiscordNotificationChannel) GetRateLimitWindow() time.Duration  { return time.Hour }
func (c *DiscordNotificationChannel) SupportsDeliveryConfirmation() bool { return false }
func (c *DiscordNotificationChannel) SupportsReadReceipts() bool         { return false }
func (c *DiscordNotificationChannel) SupportsTemplates() bool            { return false }
func (c *DiscordNotificationChannel) RenderTemplate(templateStr string, data map[string]interface{}) (string, error) {
	return "", fmt.Errorf("template rendering not supported for Discord channel")
}
func (c *DiscordNotificationChannel) Send(ctx context.Context, notification notificationcore.Notification, notifiable notificationcore.Notifiable) error {
	webhookURL := facades.Config().GetString("notification.channels.discord.webhook_url")
	if webhookURL == "" {
		return fmt.Errorf("Discord webhook URL is not configured")
	}
	payload := map[string]interface{}{
		"username":   facades.Config().GetString("notification.channels.discord.username"),
		"avatar_url": facades.Config().GetString("notification.channels.discord.avatar_url"),
		"content":    notification.GetBody(),
	}
	b, _ := json.Marshal(payload)
	resp, err := http.Post(webhookURL, "application/json", bytes.NewBuffer(b))
	if err != nil {
		facades.Log().Error("Failed to send Discord notification", map[string]interface{}{"error": err.Error()})
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("Discord webhook returned status %d", resp.StatusCode)
	}
	facades.Log().Info("Discord notification sent", map[string]interface{}{"webhook_url": webhookURL})
	return nil
}

// TelegramNotificationChannel
type TelegramNotificationChannel struct{}

func NewTelegramNotificationChannel() *TelegramNotificationChannel {
	return &TelegramNotificationChannel{}
}

func (c *TelegramNotificationChannel) GetName() string    { return "telegram" }
func (c *TelegramNotificationChannel) GetVersion() string { return "2.0" }
func (c *TelegramNotificationChannel) IsEnabled() bool {
	return facades.Config().GetBool("notification.channels.telegram.enabled", true)
}
func (c *TelegramNotificationChannel) Validate() error { return nil }
func (c *TelegramNotificationChannel) GetConfig() map[string]interface{} {
	return map[string]interface{}{"enabled": c.IsEnabled(), "version": c.GetVersion()}
}
func (c *TelegramNotificationChannel) SupportsBatching() bool             { return true }
func (c *TelegramNotificationChannel) SupportsScheduling() bool           { return true }
func (c *TelegramNotificationChannel) SupportsRichContent() bool          { return true }
func (c *TelegramNotificationChannel) GetMaxBatchSize() int               { return 50 }
func (c *TelegramNotificationChannel) GetRateLimit() int                  { return 100 }
func (c *TelegramNotificationChannel) GetRateLimitWindow() time.Duration  { return time.Hour }
func (c *TelegramNotificationChannel) SupportsDeliveryConfirmation() bool { return false }
func (c *TelegramNotificationChannel) SupportsReadReceipts() bool         { return false }
func (c *TelegramNotificationChannel) SupportsTemplates() bool            { return false }
func (c *TelegramNotificationChannel) RenderTemplate(templateStr string, data map[string]interface{}) (string, error) {
	return "", fmt.Errorf("template rendering not supported for Telegram channel")
}
func (c *TelegramNotificationChannel) Send(ctx context.Context, notification notificationcore.Notification, notifiable notificationcore.Notifiable) error {
	botToken := facades.Config().GetString("notification.channels.telegram.bot_token")
	chatID := facades.Config().GetString("notification.channels.telegram.chat_id")
	if botToken == "" || chatID == "" {
		return fmt.Errorf("Telegram bot token or chat ID is not configured")
	}
	apiURL := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", botToken)
	payload := map[string]interface{}{
		"chat_id": chatID,
		"text":    notification.GetBody(),
	}
	b, _ := json.Marshal(payload)
	resp, err := http.Post(apiURL, "application/json", bytes.NewBuffer(b))
	if err != nil {
		facades.Log().Error("Failed to send Telegram notification", map[string]interface{}{"error": err.Error()})
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("Telegram API returned status %d", resp.StatusCode)
	}
	facades.Log().Info("Telegram notification sent", map[string]interface{}{"chat_id": chatID})
	return nil
}

// SMSNotificationChannel
type SMSNotificationChannel struct{}

func NewSMSNotificationChannel() *SMSNotificationChannel {
	return &SMSNotificationChannel{}
}

func (c *SMSNotificationChannel) GetName() string    { return "sms" }
func (c *SMSNotificationChannel) GetVersion() string { return "2.0" }
func (c *SMSNotificationChannel) IsEnabled() bool {
	return facades.Config().GetBool("notification.channels.sms.enabled", true)
}
func (c *SMSNotificationChannel) Validate() error { return nil }
func (c *SMSNotificationChannel) GetConfig() map[string]interface{} {
	return map[string]interface{}{"enabled": c.IsEnabled(), "version": c.GetVersion()}
}
func (c *SMSNotificationChannel) SupportsBatching() bool             { return true }
func (c *SMSNotificationChannel) SupportsScheduling() bool           { return true }
func (c *SMSNotificationChannel) SupportsRichContent() bool          { return false }
func (c *SMSNotificationChannel) GetMaxBatchSize() int               { return 20 }
func (c *SMSNotificationChannel) GetRateLimit() int                  { return 10 }
func (c *SMSNotificationChannel) GetRateLimitWindow() time.Duration  { return time.Hour }
func (c *SMSNotificationChannel) SupportsDeliveryConfirmation() bool { return true }
func (c *SMSNotificationChannel) SupportsReadReceipts() bool         { return false }
func (c *SMSNotificationChannel) SupportsTemplates() bool            { return true }
func (c *SMSNotificationChannel) RenderTemplate(templateStr string, data map[string]interface{}) (string, error) {
	return templateStr, nil // SMS templates are just text
}
func (c *SMSNotificationChannel) Send(ctx context.Context, notification notificationcore.Notification, notifiable notificationcore.Notifiable) error {
	provider := facades.Config().GetString("notification.channels.sms.provider")
	if provider != "twilio" {
		return fmt.Errorf("Only Twilio SMS provider is supported in this implementation")
	}
	twilio := facades.Config().Get("notification.channels.sms.twilio").(map[string]any)
	accountSID, _ := twilio["account_sid"].(string)
	authToken, _ := twilio["auth_token"].(string)
	fromNumber, _ := twilio["from_number"].(string)
	toNumber := notifiable.GetPhone()
	if accountSID == "" || authToken == "" || fromNumber == "" || toNumber == "" {
		return fmt.Errorf("Twilio SMS config or recipient phone is missing")
	}
	apiURL := fmt.Sprintf("https://api.twilio.com/2010-04-01/Accounts/%s/Messages.json", accountSID)
	msgData := fmt.Sprintf("From=%s&To=%s&Body=%s", fromNumber, toNumber, notification.GetBody())
	req, err := http.NewRequestWithContext(ctx, "POST", apiURL, strings.NewReader(msgData))
	if err != nil {
		return err
	}
	req.SetBasicAuth(accountSID, authToken)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		facades.Log().Error("Failed to send SMS notification", map[string]interface{}{"error": err.Error()})
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("Twilio API returned status %d", resp.StatusCode)
	}
	facades.Log().Info("SMS notification sent", map[string]interface{}{"to": toNumber})
	return nil
}

// WebhookNotificationChannel
type WebhookNotificationChannel struct{}

func NewWebhookNotificationChannel() *WebhookNotificationChannel {
	return &WebhookNotificationChannel{}
}

func (c *WebhookNotificationChannel) GetName() string    { return "webhook" }
func (c *WebhookNotificationChannel) GetVersion() string { return "2.0" }
func (c *WebhookNotificationChannel) IsEnabled() bool {
	return facades.Config().GetBool("notification.channels.webhook.enabled", true)
}
func (c *WebhookNotificationChannel) Validate() error { return nil }
func (c *WebhookNotificationChannel) GetConfig() map[string]interface{} {
	return map[string]interface{}{"enabled": c.IsEnabled(), "version": c.GetVersion()}
}
func (c *WebhookNotificationChannel) SupportsBatching() bool             { return true }
func (c *WebhookNotificationChannel) SupportsScheduling() bool           { return true }
func (c *WebhookNotificationChannel) SupportsRichContent() bool          { return true }
func (c *WebhookNotificationChannel) GetMaxBatchSize() int               { return 100 }
func (c *WebhookNotificationChannel) GetRateLimit() int                  { return 200 }
func (c *WebhookNotificationChannel) GetRateLimitWindow() time.Duration  { return time.Hour }
func (c *WebhookNotificationChannel) SupportsDeliveryConfirmation() bool { return true }
func (c *WebhookNotificationChannel) SupportsReadReceipts() bool         { return false }
func (c *WebhookNotificationChannel) SupportsTemplates() bool            { return false }
func (c *WebhookNotificationChannel) RenderTemplate(templateStr string, data map[string]interface{}) (string, error) {
	return "", fmt.Errorf("template rendering not supported for Webhook channel")
}
func (c *WebhookNotificationChannel) Send(ctx context.Context, notification notificationcore.Notification, notifiable notificationcore.Notifiable) error {
	url := facades.Config().GetString("notification.channels.webhook.url")
	method := facades.Config().GetString("notification.channels.webhook.method")
	if url == "" {
		return fmt.Errorf("Webhook URL is not configured")
	}
	if method == "" {
		method = "POST"
	}
	headers := facades.Config().Get("notification.channels.webhook.headers").(map[string]any)
	payload := map[string]interface{}{
		"type":            notification.GetType(),
		"data":            notification.GetData(),
		"notifiable_id":   notifiable.GetID(),
		"notifiable_type": notifiable.GetType(),
	}
	b, _ := json.Marshal(payload)
	req, err := http.NewRequestWithContext(ctx, method, url, bytes.NewBuffer(b))
	if err != nil {
		return err
	}
	for k, v := range headers {
		if vs, ok := v.(string); ok {
			req.Header.Set(k, vs)
		}
	}
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		facades.Log().Error("Failed to send Webhook notification", map[string]interface{}{"error": err.Error()})
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("Webhook returned status %d", resp.StatusCode)
	}
	facades.Log().Info("Webhook notification sent", map[string]interface{}{"url": url})
	return nil
}

// LogNotificationChannel
type LogNotificationChannel struct{}

func NewLogNotificationChannel() *LogNotificationChannel {
	return &LogNotificationChannel{}
}

func (c *LogNotificationChannel) GetName() string    { return "log" }
func (c *LogNotificationChannel) GetVersion() string { return "2.0" }
func (c *LogNotificationChannel) IsEnabled() bool {
	return facades.Config().GetBool("notification.channels.log.enabled", true)
}
func (c *LogNotificationChannel) Validate() error { return nil }
func (c *LogNotificationChannel) GetConfig() map[string]interface{} {
	return map[string]interface{}{"enabled": c.IsEnabled(), "version": c.GetVersion()}
}
func (c *LogNotificationChannel) SupportsBatching() bool             { return true }
func (c *LogNotificationChannel) SupportsScheduling() bool           { return true }
func (c *LogNotificationChannel) SupportsRichContent() bool          { return true }
func (c *LogNotificationChannel) GetMaxBatchSize() int               { return 1000 }
func (c *LogNotificationChannel) GetRateLimit() int                  { return 1000 }
func (c *LogNotificationChannel) GetRateLimitWindow() time.Duration  { return time.Hour }
func (c *LogNotificationChannel) SupportsDeliveryConfirmation() bool { return true }
func (c *LogNotificationChannel) SupportsReadReceipts() bool         { return false }
func (c *LogNotificationChannel) SupportsTemplates() bool            { return false }
func (c *LogNotificationChannel) RenderTemplate(templateStr string, data map[string]interface{}) (string, error) {
	return "", fmt.Errorf("template rendering not supported for Log channel")
}
func (c *LogNotificationChannel) Send(ctx context.Context, notification notificationcore.Notification, notifiable notificationcore.Notifiable) error {
	facades.Log().Info("Log notification", map[string]interface{}{
		"type":            notification.GetType(),
		"title":           notification.GetTitle(),
		"body":            notification.GetBody(),
		"notifiable_id":   notifiable.GetID(),
		"notifiable_type": notifiable.GetType(),
		"channels":        notification.GetChannels(),
		"data":            notification.GetData(),
	})
	return nil
}
