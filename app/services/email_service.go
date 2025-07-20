package services

import (
	"crypto/tls"
	"fmt"
	"html/template"
	"net/smtp"
	"strconv"
	"strings"
	"time"

	"goravel/app/models"

	"github.com/goravel/framework/facades"
)

type EmailService struct{}

// NewEmailService creates a new email service
func NewEmailService() *EmailService {
	return &EmailService{}
}

// SendPasswordResetEmail sends a password reset email to the user
func (s *EmailService) SendPasswordResetEmail(user *models.User, token string) error {
	subject := "Password Reset Request"

	// Create reset URL
	resetURL := fmt.Sprintf("%s/reset-password?token=%s&email=%s",
		facades.Config().GetString("app.url"),
		token,
		user.Email)

	// Email content
	htmlContent := s.generatePasswordResetHTML(user, resetURL)
	textContent := s.generatePasswordResetText(user, resetURL)

	// Send email
	return s.SendEmail(user.Email, subject, htmlContent, textContent)
}

// SendWelcomeEmail sends a welcome email to new users
func (s *EmailService) SendWelcomeEmail(user *models.User) error {
	subject := "Welcome to " + facades.Config().GetString("app.name", "Goravel")

	htmlContent := s.generateWelcomeHTML(user)
	textContent := s.generateWelcomeText(user)

	return s.SendEmail(user.Email, subject, htmlContent, textContent)
}

// SendMfaEnabledEmail sends an email notification when MFA is enabled
func (s *EmailService) SendMfaEnabledEmail(user *models.User) error {
	subject := "Two-Factor Authentication Enabled"

	htmlContent := s.generateMfaEnabledHTML(user)
	textContent := s.generateMfaEnabledText(user)

	return s.SendEmail(user.Email, subject, htmlContent, textContent)
}

// SendSecurityAlertEmail sends security alert emails
func (s *EmailService) SendSecurityAlertEmail(user *models.User, alertType string, details map[string]interface{}) error {
	subject := fmt.Sprintf("Security Alert: %s", alertType)

	htmlContent := s.generateSecurityAlertHTML(user, alertType, details)
	textContent := s.generateSecurityAlertText(user, alertType, details)

	return s.SendEmail(user.Email, subject, htmlContent, textContent)
}

// SendMfaSetupEmail sends an email notification when MFA is being set up
func (s *EmailService) SendMfaSetupEmail(user *models.User) error {
	subject := "Two-Factor Authentication Setup"

	htmlContent := s.generateMfaSetupHTML(user)
	textContent := s.generateMfaSetupText(user)

	return s.SendEmail(user.Email, subject, htmlContent, textContent)
}

// SendEmail sends an email using the configured mail driver
func (s *EmailService) SendEmail(to, subject, htmlContent, textContent string) error {
	// Check if mail is configured
	if !s.IsMailConfigured() {
		facades.Log().Warning("Email not configured, skipping email send", map[string]interface{}{
			"to":      to,
			"subject": subject,
		})
		return nil
	}

	// Get mail configuration
	driver := facades.Config().GetString("mail.default")

	switch driver {
	case "smtp":
		return s.sendSMTPEmail(to, subject, htmlContent, textContent)
	case "log":
		// Log email instead of sending
		facades.Log().Info("Email would be sent", map[string]interface{}{
			"to":           to,
			"subject":      subject,
			"html_content": htmlContent,
			"text_content": textContent,
		})
		return nil
	default:
		facades.Log().Warning("Unsupported mail driver", map[string]interface{}{
			"driver": driver,
			"to":     to,
		})
		return nil
	}
}

// sendSMTPEmail sends email via SMTP
func (s *EmailService) sendSMTPEmail(to, subject, htmlContent, textContent string) error {
	// Get SMTP configuration
	host := facades.Config().GetString("mail.mailers.smtp.host")
	port := facades.Config().GetString("mail.mailers.smtp.port")
	username := facades.Config().GetString("mail.mailers.smtp.username")
	password := facades.Config().GetString("mail.mailers.smtp.password")
	encryption := facades.Config().GetString("mail.mailers.smtp.encryption")
	fromAddress := facades.Config().GetString("mail.from.address")

	if fromAddress == "" {
		fromAddress = username
	}

	// Build email message
	message := s.buildEmailMessage(fromAddress, to, subject, htmlContent, textContent)

	// Determine port and encryption
	portInt, err := strconv.Atoi(port)
	if err != nil {
		return fmt.Errorf("invalid SMTP port: %v", err)
	}

	// Send email based on encryption type
	switch encryption {
	case "tls":
		return s.sendTLS(host, portInt, username, password, fromAddress, to, message)
	case "ssl":
		return s.sendSSL(host, portInt, username, password, fromAddress, to, message)
	default:
		return s.sendPlain(host, portInt, username, password, fromAddress, to, message)
	}
}

// sendTLS sends email with TLS encryption
func (s *EmailService) sendTLS(host string, port int, username, password, from, to, message string) error {
	auth := smtp.PlainAuth("", username, password, host)

	// Create TLS config
	tlsConfig := &tls.Config{
		InsecureSkipVerify: false,
		ServerName:         host,
	}

	// Connect to server
	conn, err := tls.Dial("tcp", fmt.Sprintf("%s:%d", host, port), tlsConfig)
	if err != nil {
		return fmt.Errorf("failed to connect to SMTP server: %v", err)
	}
	defer conn.Close()

	client, err := smtp.NewClient(conn, host)
	if err != nil {
		return fmt.Errorf("failed to create SMTP client: %v", err)
	}
	defer client.Close()

	// Authenticate
	if err = client.Auth(auth); err != nil {
		return fmt.Errorf("SMTP authentication failed: %v", err)
	}

	// Send email
	if err = client.Mail(from); err != nil {
		return fmt.Errorf("failed to set sender: %v", err)
	}
	if err = client.Rcpt(to); err != nil {
		return fmt.Errorf("failed to set recipient: %v", err)
	}

	w, err := client.Data()
	if err != nil {
		return fmt.Errorf("failed to get data writer: %v", err)
	}
	defer w.Close()

	_, err = w.Write([]byte(message))
	if err != nil {
		return fmt.Errorf("failed to write email data: %v", err)
	}

	facades.Log().Info("Email sent successfully via TLS", map[string]interface{}{
		"to":      to,
		"subject": "Email Subject", // Extract subject from message
		"host":    host,
		"port":    port,
	})

	return nil
}

// sendSSL sends email with SSL encryption
func (s *EmailService) sendSSL(host string, port int, username, password, from, to, message string) error {
	// For SSL, we use the same approach as TLS
	return s.sendTLS(host, port, username, password, from, to, message)
}

// sendPlain sends email without encryption
func (s *EmailService) sendPlain(host string, port int, username, password, from, to, message string) error {
	auth := smtp.PlainAuth("", username, password, host)

	err := smtp.SendMail(fmt.Sprintf("%s:%d", host, port), auth, from, []string{to}, []byte(message))
	if err != nil {
		return fmt.Errorf("failed to send email: %v", err)
	}

	facades.Log().Info("Email sent successfully via plain SMTP", map[string]interface{}{
		"to":      to,
		"subject": "Email Subject", // Extract subject from message
		"host":    host,
		"port":    port,
	})

	return nil
}

// buildEmailMessage builds a complete email message with headers
func (s *EmailService) buildEmailMessage(from, to, subject, htmlContent, textContent string) string {
	boundary := "goravel-boundary-" + fmt.Sprintf("%d", time.Now().Unix())

	message := fmt.Sprintf("From: %s\r\n", from)
	message += fmt.Sprintf("To: %s\r\n", to)
	message += fmt.Sprintf("Subject: %s\r\n", subject)
	message += "MIME-Version: 1.0\r\n"
	message += fmt.Sprintf("Content-Type: multipart/alternative; boundary=\"%s\"\r\n", boundary)
	message += "\r\n"

	// Text part
	message += fmt.Sprintf("--%s\r\n", boundary)
	message += "Content-Type: text/plain; charset=UTF-8\r\n"
	message += "Content-Transfer-Encoding: 8bit\r\n"
	message += "\r\n"
	message += textContent
	message += "\r\n"

	// HTML part
	message += fmt.Sprintf("--%s\r\n", boundary)
	message += "Content-Type: text/html; charset=UTF-8\r\n"
	message += "Content-Transfer-Encoding: 8bit\r\n"
	message += "\r\n"
	message += htmlContent
	message += "\r\n"

	message += fmt.Sprintf("--%s--\r\n", boundary)

	return message
}

// IsMailConfigured checks if mail is properly configured
func (s *EmailService) IsMailConfigured() bool {
	// Check if mail driver is configured
	driver := facades.Config().GetString("mail.default")
	if driver == "" {
		return false
	}

	// Check if SMTP is configured (for smtp driver)
	if driver == "smtp" {
		host := facades.Config().GetString("mail.mailers.smtp.host")
		port := facades.Config().GetString("mail.mailers.smtp.port")
		username := facades.Config().GetString("mail.mailers.smtp.username")
		password := facades.Config().GetString("mail.mailers.smtp.password")

		return host != "" && port != "" && username != "" && password != ""
	}

	// For other drivers (log, array, etc.), assume they're configured
	return true
}

// EmailMessage represents an email message
type EmailMessage struct {
	Subject     string
	HTMLContent string
	TextContent string
}

// Template generation methods
func (s *EmailService) generatePasswordResetHTML(user *models.User, resetURL string) string {
	tmpl := `
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Password Reset</title>
    <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
        .header { background: #f8f9fa; padding: 20px; text-align: center; border-radius: 5px; }
        .content { padding: 20px; }
        .button { display: inline-block; padding: 12px 24px; background: #007bff; color: white; text-decoration: none; border-radius: 5px; }
        .footer { margin-top: 30px; padding: 20px; background: #f8f9fa; border-radius: 5px; font-size: 14px; color: #666; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Password Reset Request</h1>
        </div>
        <div class="content">
            <p>Hello {{.Name}},</p>
            <p>You recently requested to reset your password. Click the button below to reset it:</p>
            <p style="text-align: center;">
                <a href="{{.ResetURL}}" class="button">Reset Password</a>
            </p>
            <p>If the button doesn't work, copy and paste this link into your browser:</p>
            <p style="word-break: break-all; color: #007bff;">{{.ResetURL}}</p>
            <p>This password reset link will expire in 60 minutes.</p>
            <p>If you didn't request a password reset, please ignore this email or contact support if you have concerns.</p>
        </div>
        <div class="footer">
            <p>This email was sent to {{.Email}} at {{.Time}}.</p>
            <p>If you have any questions, please contact our support team.</p>
        </div>
    </div>
</body>
</html>`

	data := map[string]interface{}{
		"Name":     user.Name,
		"Email":    user.Email,
		"ResetURL": resetURL,
		"Time":     time.Now().Format("2006-01-02 15:04:05 UTC"),
	}

	return s.renderTemplate(tmpl, data)
}

func (s *EmailService) generatePasswordResetText(user *models.User, resetURL string) string {
	tmpl := `Password Reset Request

Hello {{.Name}},

You recently requested to reset your password. Click the link below to reset it:

{{.ResetURL}}

This password reset link will expire in 60 minutes.

If you didn't request a password reset, please ignore this email or contact support if you have concerns.

This email was sent to {{.Email}} at {{.Time}}.

If you have any questions, please contact our support team.`

	data := map[string]interface{}{
		"Name":     user.Name,
		"Email":    user.Email,
		"ResetURL": resetURL,
		"Time":     time.Now().Format("2006-01-02 15:04:05 UTC"),
	}

	return s.renderTemplate(tmpl, data)
}

func (s *EmailService) generateWelcomeHTML(user *models.User) string {
	tmpl := `
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Welcome to {{.AppName}}</title>
    <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
        .header { background: #28a745; padding: 20px; text-align: center; border-radius: 5px; color: white; }
        .content { padding: 20px; }
        .footer { margin-top: 30px; padding: 20px; background: #f8f9fa; border-radius: 5px; font-size: 14px; color: #666; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Welcome to {{.AppName}}!</h1>
        </div>
        <div class="content">
            <p>Hello {{.Name}},</p>
            <p>Welcome to {{.AppName}}! Your account has been successfully created.</p>
            <p>You can now log in to your account and start using our services.</p>
            <p>If you have any questions or need assistance, please don't hesitate to contact our support team.</p>
        </div>
        <div class="footer">
            <p>This email was sent to {{.Email}} at {{.Time}}.</p>
            <p>Thank you for choosing {{.AppName}}!</p>
        </div>
    </div>
</body>
</html>`

	data := map[string]interface{}{
		"Name":    user.Name,
		"Email":   user.Email,
		"AppName": facades.Config().GetString("app.name", "Goravel"),
		"Time":    time.Now().Format("2006-01-02 15:04:05 UTC"),
	}

	return s.renderTemplate(tmpl, data)
}

func (s *EmailService) generateWelcomeText(user *models.User) string {
	tmpl := `Welcome to {{.AppName}}!

Hello {{.Name}},

Welcome to {{.AppName}}! Your account has been successfully created.

You can now log in to your account and start using our services.

If you have any questions or need assistance, please don't hesitate to contact our support team.

This email was sent to {{.Email}} at {{.Time}}.

Thank you for choosing {{.AppName}}!`

	data := map[string]interface{}{
		"Name":    user.Name,
		"Email":   user.Email,
		"AppName": facades.Config().GetString("app.name", "Goravel"),
		"Time":    time.Now().Format("2006-01-02 15:04:05 UTC"),
	}

	return s.renderTemplate(tmpl, data)
}

func (s *EmailService) generateMfaEnabledHTML(user *models.User) string {
	tmpl := `
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Two-Factor Authentication Enabled</title>
    <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
        .header { background: #17a2b8; padding: 20px; text-align: center; border-radius: 5px; color: white; }
        .content { padding: 20px; }
        .footer { margin-top: 30px; padding: 20px; background: #f8f9fa; border-radius: 5px; font-size: 14px; color: #666; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Two-Factor Authentication Enabled</h1>
        </div>
        <div class="content">
            <p>Hello {{.Name}},</p>
            <p>Two-factor authentication has been successfully enabled for your account.</p>
            <p>This additional security measure will help protect your account from unauthorized access.</p>
            <p>If you did not enable two-factor authentication, please contact our support team immediately.</p>
        </div>
        <div class="footer">
            <p>This email was sent to {{.Email}} at {{.Time}}.</p>
            <p>If you have any questions, please contact our support team.</p>
        </div>
    </div>
</body>
</html>`

	data := map[string]interface{}{
		"Name":  user.Name,
		"Email": user.Email,
		"Time":  time.Now().Format("2006-01-02 15:04:05 UTC"),
	}

	return s.renderTemplate(tmpl, data)
}

func (s *EmailService) generateMfaEnabledText(user *models.User) string {
	tmpl := `Two-Factor Authentication Enabled

Hello {{.Name}},

Two-factor authentication has been successfully enabled for your account.

This additional security measure will help protect your account from unauthorized access.

If you did not enable two-factor authentication, please contact our support team immediately.

This email was sent to {{.Email}} at {{.Time}}.

If you have any questions, please contact our support team.`

	data := map[string]interface{}{
		"Name":  user.Name,
		"Email": user.Email,
		"Time":  time.Now().Format("2006-01-02 15:04:05 UTC"),
	}

	return s.renderTemplate(tmpl, data)
}

func (s *EmailService) generateSecurityAlertHTML(user *models.User, alertType string, details map[string]interface{}) string {
	tmpl := `
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Security Alert: {{.AlertType}}</title>
    <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
        .header { background: #dc3545; padding: 20px; text-align: center; border-radius: 5px; color: white; }
        .content { padding: 20px; }
        .details { background: #f8f9fa; padding: 15px; border-radius: 5px; margin: 15px 0; }
        .footer { margin-top: 30px; padding: 20px; background: #f8f9fa; border-radius: 5px; font-size: 14px; color: #666; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Security Alert: {{.AlertType}}</h1>
        </div>
        <div class="content">
            <p>Hello {{.Name}},</p>
            <p>We detected a security event on your account that requires your attention.</p>
            <div class="details">
                <h3>Event Details:</h3>
                <p><strong>Type:</strong> {{.AlertType}}</p>
                <p><strong>Time:</strong> {{.Time}}</p>
                <p><strong>IP Address:</strong> {{.IPAddress}}</p>
                <p><strong>User Agent:</strong> {{.UserAgent}}</p>
            </div>
            <p>If this activity was not performed by you, please contact our support team immediately.</p>
        </div>
        <div class="footer">
            <p>This email was sent to {{.Email}} at {{.Time}}.</p>
            <p>If you have any questions, please contact our support team.</p>
        </div>
    </div>
</body>
</html>`

	data := map[string]interface{}{
		"Name":      user.Name,
		"Email":     user.Email,
		"AlertType": alertType,
		"Time":      time.Now().Format("2006-01-02 15:04:05 UTC"),
		"IPAddress": details["ip_address"],
		"UserAgent": details["user_agent"],
	}

	return s.renderTemplate(tmpl, data)
}

func (s *EmailService) generateSecurityAlertText(user *models.User, alertType string, details map[string]interface{}) string {
	tmpl := `Security Alert: {{.AlertType}}

Hello {{.Name}},

We detected a security event on your account that requires your attention.

Event Details:
- Type: {{.AlertType}}
- Time: {{.Time}}
- IP Address: {{.IPAddress}}
- User Agent: {{.UserAgent}}

If this activity was not performed by you, please contact our support team immediately.

This email was sent to {{.Email}} at {{.Time}}.

If you have any questions, please contact our support team.`

	data := map[string]interface{}{
		"Name":      user.Name,
		"Email":     user.Email,
		"AlertType": alertType,
		"Time":      time.Now().Format("2006-01-02 15:04:05 UTC"),
		"IPAddress": details["ip_address"],
		"UserAgent": details["user_agent"],
	}

	return s.renderTemplate(tmpl, data)
}

func (s *EmailService) generateMfaSetupHTML(user *models.User) string {
	tmpl := `
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Two-Factor Authentication Setup</title>
    <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
        .header { background: #17a2b8; padding: 20px; text-align: center; border-radius: 5px; color: white; }
        .content { padding: 20px; }
        .footer { margin-top: 30px; padding: 20px; background: #f8f9fa; border-radius: 5px; font-size: 14px; color: #666; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Two-Factor Authentication Setup</h1>
        </div>
        <div class="content">
            <p>Hello {{.Name}},</p>
            <p>You have initiated the setup of two-factor authentication for your account.</p>
            <p>To complete the setup, please scan the QR code provided in your account settings with your authenticator app.</p>
            <p>If you did not initiate this setup, please contact our support team immediately.</p>
        </div>
        <div class="footer">
            <p>This email was sent to {{.Email}} at {{.Time}}.</p>
            <p>If you have any questions, please contact our support team.</p>
        </div>
    </div>
</body>
</html>`

	data := map[string]interface{}{
		"Name":  user.Name,
		"Email": user.Email,
		"Time":  time.Now().Format("2006-01-02 15:04:05 UTC"),
	}

	return s.renderTemplate(tmpl, data)
}

func (s *EmailService) generateMfaSetupText(user *models.User) string {
	tmpl := `Two-Factor Authentication Setup

Hello {{.Name}},

You have initiated the setup of two-factor authentication for your account.

To complete the setup, please scan the QR code provided in your account settings with your authenticator app.

If you did not initiate this setup, please contact our support team immediately.

This email was sent to {{.Email}} at {{.Time}}.

If you have any questions, please contact our support team.`

	data := map[string]interface{}{
		"Name":  user.Name,
		"Email": user.Email,
		"Time":  time.Now().Format("2006-01-02 15:04:05 UTC"),
	}

	return s.renderTemplate(tmpl, data)
}

func (s *EmailService) renderTemplate(tmpl string, data map[string]interface{}) string {
	t, err := template.New("email").Parse(tmpl)
	if err != nil {
		facades.Log().Error("Failed to parse email template", map[string]interface{}{
			"error": err.Error(),
		})
		return ""
	}

	var result strings.Builder
	err = t.Execute(&result, data)
	if err != nil {
		facades.Log().Error("Failed to execute email template", map[string]interface{}{
			"error": err.Error(),
		})
		return ""
	}

	return result.String()
}
