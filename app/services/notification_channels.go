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

// IsEnabled checks if the channel is enabled
func (c *DatabaseNotificationChannel) IsEnabled() bool {
	return facades.Config().GetBool("notification.channels.database.enabled", true)
}

// Validate validates the channel configuration
func (c *DatabaseNotificationChannel) Validate() error {
	// Database channel is always valid if enabled
	return nil
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
		"Message":      notification.GetMessage(),
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
    <meta charset="utf-8">
    <title>{{.Title}}</title>
    <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
        .header { background-color: #f8f9fa; padding: 20px; border-radius: 5px; }
        .content { padding: 20px; }
        .button { display: inline-block; padding: 10px 20px; background-color: #007bff; color: white; text-decoration: none; border-radius: 5px; }
        .footer { margin-top: 20px; padding-top: 20px; border-top: 1px solid #eee; font-size: 12px; color: #666; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>{{.Title}}</h1>
        </div>
        <div class="content">
            {{if .Body}}
                <p>{{.Body}}</p>
            {{end}}
            {{if .Message}}
                <p>{{.Message}}</p>
            {{end}}
            {{if .ActionURL}}
                <p><a href="{{.ActionURL}}" class="button">{{.ActionText}}</a></p>
            {{end}}
        </div>
        <div class="footer">
            <p>Sent at {{.Timestamp}}</p>
            <p>Notification ID: {{.NotifiableID}}</p>
        </div>
    </div>
</body>
</html>`

	// Parse and execute template
	tmpl, err := template.New("email").Parse(htmlTemplate)
	if err != nil {
		facades.Log().Error("Failed to parse HTML template", map[string]interface{}{
			"error": err.Error(),
		})
		return fmt.Sprintf("<h1>%s</h1><p>%s</p>", templateData["Title"], templateData["Body"])
	}

	var result strings.Builder
	if err := tmpl.Execute(&result, templateData); err != nil {
		facades.Log().Error("Failed to execute HTML template", map[string]interface{}{
			"error": err.Error(),
		})
		return fmt.Sprintf("<h1>%s</h1><p>%s</p>", templateData["Title"], templateData["Body"])
	}

	return result.String()
}

// renderDefaultTextTemplate renders the default plain text email template
func (c *MailNotificationChannel) renderDefaultTextTemplate(notification notificationcore.Notification, notifiable notificationcore.Notifiable) string {
	// This is a simplified template rendering
	// In a real application, you'd load templates from files
	templateData := map[string]interface{}{
		"Title":        notification.GetTitle(),
		"Body":         notification.GetBody(),
		"Message":      notification.GetMessage(),
		"ActionURL":    notification.GetActionURL(),
		"ActionText":   notification.GetActionText(),
		"NotifiableID": notifiable.GetID(),
		"Timestamp":    time.Now().Format("2006-01-02 15:04:05"),
	}

	// Simple text template
	textTemplate := `{{.Title}}

{{if .Body}}{{.Body}}{{end}}
{{if .Message}}{{.Message}}{{end}}

{{if .ActionURL}}{{.ActionText}}: {{.ActionURL}}{{end}}

---
Sent at {{.Timestamp}}
Notification ID: {{.NotifiableID}}`

	// Parse and execute template
	tmpl, err := template.New("text").Parse(textTemplate)
	if err != nil {
		facades.Log().Error("Failed to parse text template", map[string]interface{}{
			"error": err.Error(),
		})
		return fmt.Sprintf("%s\n\n%s", templateData["Title"], templateData["Body"])
	}

	var result strings.Builder
	if err := tmpl.Execute(&result, templateData); err != nil {
		facades.Log().Error("Failed to execute text template", map[string]interface{}{
			"error": err.Error(),
		})
		return fmt.Sprintf("%s\n\n%s", templateData["Title"], templateData["Body"])
	}

	return result.String()
}

// WebPushNotificationChannel handles sending notifications via web push
type WebPushNotificationChannel struct{}

// NewWebPushNotificationChannel creates a new web push notification channel
func NewWebPushNotificationChannel() *WebPushNotificationChannel {
	return &WebPushNotificationChannel{}
}

// GetName returns the channel name
func (c *WebPushNotificationChannel) GetName() string {
	return "web_push"
}

// IsEnabled checks if the channel is enabled
func (c *WebPushNotificationChannel) IsEnabled() bool {
	return facades.Config().GetBool("notification.channels.web_push.enabled", true)
}

// Validate validates the channel configuration
func (c *WebPushNotificationChannel) Validate() error {
	// Check if VAPID keys are configured
	vapidPublicKey := facades.Config().GetString("notification.channels.web_push.vapid.public_key")
	vapidPrivateKey := facades.Config().GetString("notification.channels.web_push.vapid.private_key")

	if vapidPublicKey == "" || vapidPrivateKey == "" {
		return fmt.Errorf("VAPID keys are not configured for web push notifications")
	}

	return nil
}

// Send sends the notification via web push
func (c *WebPushNotificationChannel) Send(ctx context.Context, notification notificationcore.Notification, notifiable notificationcore.Notifiable) error {
	// Get push tokens for the notifiable
	pushTokens := notifiable.GetPushTokens()
	if len(pushTokens) == 0 {
		return fmt.Errorf("notifiable does not have any push tokens")
	}

	// Get VAPID configuration
	vapidPublicKey := facades.Config().GetString("notification.channels.web_push.vapid.public_key")
	vapidPrivateKey := facades.Config().GetString("notification.channels.web_push.vapid.private_key")

	if vapidPublicKey == "" || vapidPrivateKey == "" {
		return fmt.Errorf("VAPID keys are not configured")
	}

	// Create push notification payload
	payload := c.createPushPayload(notification, notifiable)

	// Send to each push token
	var errors []error
	for _, token := range pushTokens {
		if err := c.sendToToken(ctx, token, payload, vapidPublicKey, vapidPrivateKey); err != nil {
			errors = append(errors, fmt.Errorf("failed to send to token %s: %w", token, err))
			facades.Log().Error("Failed to send web push notification", map[string]interface{}{
				"token":             token,
				"notification_type": notification.GetType(),
				"notifiable_id":     notifiable.GetID(),
				"error":             err.Error(),
			})
		} else {
			facades.Log().Info("Web push notification sent successfully", map[string]interface{}{
				"token":             token,
				"notification_type": notification.GetType(),
				"notifiable_id":     notifiable.GetID(),
			})
		}
	}

	// Return first error if any occurred
	if len(errors) > 0 {
		return errors[0]
	}

	return nil
}

// createPushPayload creates the push notification payload
func (c *WebPushNotificationChannel) createPushPayload(notification notificationcore.Notification, notifiable notificationcore.Notifiable) map[string]interface{} {
	payload := map[string]interface{}{
		"title":   notification.GetTitle(),
		"body":    notification.GetBody(),
		"icon":    notification.GetIcon(),
		"badge":   notification.GetIcon(),
		"tag":     notification.GetType(),
		"data":    notification.GetData(),
		"actions": []map[string]interface{}{},
	}

	// Add action if available
	if notification.GetActionURL() != "" {
		action := map[string]interface{}{
			"action": notification.GetActionText(),
			"title":  notification.GetActionText(),
			"icon":   notification.GetIcon(),
		}
		payload["actions"] = append(payload["actions"].([]map[string]interface{}), action)
	}

	// Add timestamp
	payload["timestamp"] = time.Now().Unix()

	return payload
}

// sendToToken sends a push notification to a specific token
func (c *WebPushNotificationChannel) sendToToken(ctx context.Context, token string, payload map[string]interface{}, vapidPublicKey, vapidPrivateKey string) error {
	// Use github.com/SherClockHolmes/webpush-go for real web push
	// The token is the endpoint; in a real app, you would also need the user's keys (p256dh, auth)
	// For this example, assume token is the endpoint and keys are stored/fetched elsewhere

	// Find the push subscription by endpoint
	var subscription models.PushSubscription
	err := facades.Orm().Query().Where("endpoint", token).Where("is_active", true).First(&subscription)
	if err != nil {
		return fmt.Errorf("push subscription not found for endpoint: %s", token)
	}

	// Prepare the webpush.Subscription struct
	webpushSub := &webpush.Subscription{
		Endpoint: subscription.Endpoint,
		Keys: webpush.Keys{
			P256dh: subscription.P256dhKey,
			Auth:   subscription.AuthToken,
		},
	}

	// Marshal the payload
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal push payload: %w", err)
	}

	// Prepare VAPID options
	vapidOpts := &webpush.Options{
		Subscriber:      facades.Config().GetString("notification.channels.web_push.vapid.subject"),
		VAPIDPublicKey:  vapidPublicKey,
		VAPIDPrivateKey: vapidPrivateKey,
		TTL:             60,
	}

	// Send the push notification
	resp, err := webpush.SendNotification(payloadBytes, webpushSub, vapidOpts)
	if err != nil {
		facades.Log().Error("Failed to send web push notification", map[string]interface{}{
			"endpoint":          token,
			"notification_type": payload["tag"],
			"error":             err.Error(),
		})
		return fmt.Errorf("failed to send web push notification: %w", err)
	}
	defer resp.Body.Close()

	facades.Log().Info("Web push notification sent", map[string]interface{}{
		"endpoint":          token,
		"status":            resp.StatusCode,
		"notification_type": payload["tag"],
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

// IsEnabled checks if the channel is enabled
func (c *WebSocketNotificationChannel) IsEnabled() bool {
	return facades.Config().GetBool("notification.channels.websocket.enabled", true)
}

// Validate validates the channel configuration
func (c *WebSocketNotificationChannel) Validate() error {
	// WebSocket channel is always valid if enabled
	return nil
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
			"id":          notification.GetType(),
			"title":       notification.GetTitle(),
			"body":        notification.GetBody(),
			"message":     notification.GetMessage(),
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

func (c *SlackNotificationChannel) GetName() string { return "slack" }
func (c *SlackNotificationChannel) IsEnabled() bool {
	return facades.Config().GetBool("notification.channels.slack.enabled", true)
}
func (c *SlackNotificationChannel) Validate() error { return nil }
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

func (c *DiscordNotificationChannel) GetName() string { return "discord" }
func (c *DiscordNotificationChannel) IsEnabled() bool {
	return facades.Config().GetBool("notification.channels.discord.enabled", true)
}
func (c *DiscordNotificationChannel) Validate() error { return nil }
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

func (c *TelegramNotificationChannel) GetName() string { return "telegram" }
func (c *TelegramNotificationChannel) IsEnabled() bool {
	return facades.Config().GetBool("notification.channels.telegram.enabled", true)
}
func (c *TelegramNotificationChannel) Validate() error { return nil }
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

func (c *SMSNotificationChannel) GetName() string { return "sms" }
func (c *SMSNotificationChannel) IsEnabled() bool {
	return facades.Config().GetBool("notification.channels.sms.enabled", true)
}
func (c *SMSNotificationChannel) Validate() error { return nil }
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

func (c *WebhookNotificationChannel) GetName() string { return "webhook" }
func (c *WebhookNotificationChannel) IsEnabled() bool {
	return facades.Config().GetBool("notification.channels.webhook.enabled", true)
}
func (c *WebhookNotificationChannel) Validate() error { return nil }
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

func (c *LogNotificationChannel) GetName() string { return "log" }
func (c *LogNotificationChannel) IsEnabled() bool {
	return facades.Config().GetBool("notification.channels.log.enabled", true)
}
func (c *LogNotificationChannel) Validate() error { return nil }
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
