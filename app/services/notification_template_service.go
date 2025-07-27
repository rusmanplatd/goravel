package services

import (
	"bytes"
	"fmt"
	htmlTemplate "html/template"
	"os"
	"path/filepath"
	"strings"
	textTemplate "text/template"

	"goravel/app/notificationcore"

	"github.com/goravel/framework/facades"
)

// NotificationTemplateService handles notification template management
type NotificationTemplateService struct {
	templates map[string]notificationcore.Template
	basePath  string
}

// NewNotificationTemplateService creates a new template service
func NewNotificationTemplateService() *NotificationTemplateService {
	service := &NotificationTemplateService{
		templates: make(map[string]notificationcore.Template),
		basePath:  facades.Config().GetString("notification.templates.path", "resources/views/notifications"),
	}

	// Load default templates
	service.loadDefaultTemplates()

	return service
}

// NotificationTemplate represents a notification template
type NotificationTemplate struct {
	name      string
	type_     string
	subject   string
	body      string
	htmlBody  string
	variables []string
	locale    string
	parent    string
	metadata  map[string]interface{}
}

// NewNotificationTemplate creates a new notification template
func NewNotificationTemplate(name, templateType string) *NotificationTemplate {
	return &NotificationTemplate{
		name:      name,
		type_:     templateType,
		variables: []string{},
		locale:    "en",
		metadata:  make(map[string]interface{}),
	}
}

// Template interface implementation
func (t *NotificationTemplate) GetName() string {
	return t.name
}

func (t *NotificationTemplate) GetType() string {
	return t.type_
}

func (t *NotificationTemplate) GetSubject() string {
	return t.subject
}

func (t *NotificationTemplate) GetBody() string {
	return t.body
}

func (t *NotificationTemplate) GetVariables() []string {
	return t.variables
}

func (t *NotificationTemplate) Validate() error {
	if t.name == "" {
		return fmt.Errorf("template name is required")
	}
	if t.type_ == "" {
		return fmt.Errorf("template type is required")
	}
	if t.subject == "" && t.body == "" {
		return fmt.Errorf("template must have either subject or body")
	}
	return nil
}

func (t *NotificationTemplate) Render(data map[string]interface{}) (notificationcore.RenderedTemplate, error) {
	rendered := notificationcore.RenderedTemplate{}

	// Render subject
	if t.subject != "" {
		subjectTemplate, err := textTemplate.New("subject").Parse(t.subject)
		if err != nil {
			return rendered, fmt.Errorf("failed to parse subject template: %w", err)
		}

		var subjectBuf bytes.Buffer
		if err := subjectTemplate.Execute(&subjectBuf, data); err != nil {
			return rendered, fmt.Errorf("failed to render subject: %w", err)
		}
		rendered.Subject = subjectBuf.String()
	}

	// Render text body
	if t.body != "" {
		bodyTemplate, err := textTemplate.New("body").Parse(t.body)
		if err != nil {
			return rendered, fmt.Errorf("failed to parse body template: %w", err)
		}

		var bodyBuf bytes.Buffer
		if err := bodyTemplate.Execute(&bodyBuf, data); err != nil {
			return rendered, fmt.Errorf("failed to render body: %w", err)
		}
		rendered.Body = bodyBuf.String()
		rendered.Text = bodyBuf.String()
	}

	// Render HTML body if available
	if t.htmlBody != "" {
		htmlTemplateObj, err := htmlTemplate.New("html").Parse(t.htmlBody)
		if err != nil {
			return rendered, fmt.Errorf("failed to parse HTML template: %w", err)
		}

		var htmlBuf bytes.Buffer
		if err := htmlTemplateObj.Execute(&htmlBuf, data); err != nil {
			return rendered, fmt.Errorf("failed to render HTML: %w", err)
		}
		rendered.HTML = htmlBuf.String()
	}

	return rendered, nil
}

// Builder methods for NotificationTemplate
func (t *NotificationTemplate) SetSubject(subject string) *NotificationTemplate {
	t.subject = subject
	return t
}

func (t *NotificationTemplate) SetBody(body string) *NotificationTemplate {
	t.body = body
	return t
}

func (t *NotificationTemplate) SetHTMLBody(htmlBody string) *NotificationTemplate {
	t.htmlBody = htmlBody
	return t
}

func (t *NotificationTemplate) SetVariables(variables []string) *NotificationTemplate {
	t.variables = variables
	return t
}

func (t *NotificationTemplate) AddVariable(variable string) *NotificationTemplate {
	t.variables = append(t.variables, variable)
	return t
}

func (t *NotificationTemplate) SetLocale(locale string) *NotificationTemplate {
	t.locale = locale
	return t
}

func (t *NotificationTemplate) SetParent(parent string) *NotificationTemplate {
	t.parent = parent
	return t
}

func (t *NotificationTemplate) SetMetadata(metadata map[string]interface{}) *NotificationTemplate {
	t.metadata = metadata
	return t
}

// Service methods
func (s *NotificationTemplateService) RegisterTemplate(template notificationcore.Template) error {
	if err := template.Validate(); err != nil {
		return fmt.Errorf("invalid template: %w", err)
	}

	s.templates[template.GetName()] = template
	return nil
}

func (s *NotificationTemplateService) GetTemplate(name string) (notificationcore.Template, error) {
	template, exists := s.templates[name]
	if !exists {
		return nil, fmt.Errorf("template '%s' not found", name)
	}
	return template, nil
}

func (s *NotificationTemplateService) GetTemplatesByType(templateType string) []notificationcore.Template {
	var templates []notificationcore.Template
	for _, template := range s.templates {
		if template.GetType() == templateType {
			templates = append(templates, template)
		}
	}
	return templates
}

func (s *NotificationTemplateService) ListTemplates() map[string]notificationcore.Template {
	return s.templates
}

func (s *NotificationTemplateService) DeleteTemplate(name string) error {
	if _, exists := s.templates[name]; !exists {
		return fmt.Errorf("template '%s' not found", name)
	}
	delete(s.templates, name)
	return nil
}

func (s *NotificationTemplateService) RenderTemplate(templateName string, data map[string]interface{}) (notificationcore.RenderedTemplate, error) {
	template, err := s.GetTemplate(templateName)
	if err != nil {
		return notificationcore.RenderedTemplate{}, err
	}

	return template.Render(data)
}

func (s *NotificationTemplateService) CreateTemplate(name, templateType, subject, body string) *NotificationTemplate {
	template := NewNotificationTemplate(name, templateType)
	template.SetSubject(subject).SetBody(body)
	return template
}

func (s *NotificationTemplateService) CreateEmailTemplate(name, subject, textBody, htmlBody string) *NotificationTemplate {
	template := NewNotificationTemplate(name, "email")
	return template.SetSubject(subject).SetBody(textBody).SetHTMLBody(htmlBody)
}

func (s *NotificationTemplateService) CreatePushTemplate(name, title, body string) *NotificationTemplate {
	template := NewNotificationTemplate(name, "push")
	return template.SetSubject(title).SetBody(body)
}

func (s *NotificationTemplateService) CreateSMSTemplate(name, message string) *NotificationTemplate {
	template := NewNotificationTemplate(name, "sms")
	return template.SetBody(message)
}

func (s *NotificationTemplateService) CreateSlackTemplate(name, text string) *NotificationTemplate {
	template := NewNotificationTemplate(name, "slack")
	return template.SetBody(text)
}

func (s *NotificationTemplateService) loadDefaultTemplates() {
	// Welcome notification templates
	s.RegisterTemplate(s.CreateEmailTemplate(
		"welcome_email",
		"Welcome to {{.AppName}}!",
		"Hi {{.UserName}},\n\nWelcome to {{.AppName}}! We're excited to have you on board.\n\nGet started by visiting your dashboard: {{.DashboardURL}}\n\nBest regards,\nThe {{.AppName}} Team",
		`<h1>Welcome to {{.AppName}}!</h1>
		<p>Hi {{.UserName}},</p>
		<p>Welcome to {{.AppName}}! We're excited to have you on board.</p>
		<p><a href="{{.DashboardURL}}" style="background-color: #007bff; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">Go to Dashboard</a></p>
		<p>Best regards,<br>The {{.AppName}} Team</p>`,
	))

	s.RegisterTemplate(s.CreatePushTemplate(
		"welcome_push",
		"Welcome to {{.AppName}}!",
		"Hi {{.UserName}}, welcome to our platform! Tap to get started.",
	))

	// Password reset templates
	s.RegisterTemplate(s.CreateEmailTemplate(
		"password_reset_email",
		"Reset Your Password",
		"Hi {{.UserName}},\n\nYou requested a password reset. Click the link below to reset your password:\n\n{{.ResetURL}}\n\nThis link will expire in {{.ExpiresIn}} minutes.\n\nIf you didn't request this, please ignore this email.\n\nBest regards,\nThe {{.AppName}} Team",
		`<h1>Reset Your Password</h1>
		<p>Hi {{.UserName}},</p>
		<p>You requested a password reset. Click the button below to reset your password:</p>
		<p><a href="{{.ResetURL}}" style="background-color: #dc3545; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">Reset Password</a></p>
		<p>This link will expire in {{.ExpiresIn}} minutes.</p>
		<p>If you didn't request this, please ignore this email.</p>
		<p>Best regards,<br>The {{.AppName}} Team</p>`,
	))

	// Security alert templates
	s.RegisterTemplate(s.CreateEmailTemplate(
		"security_alert_email",
		"Security Alert - {{.AlertType}}",
		"Hi {{.UserName}},\n\nWe detected a security event on your account:\n\n{{.AlertMessage}}\n\nTime: {{.Timestamp}}\nLocation: {{.Location}}\nIP Address: {{.IPAddress}}\n\nIf this was you, no action is needed. If not, please secure your account immediately.\n\nBest regards,\nThe {{.AppName}} Security Team",
		`<h1>Security Alert</h1>
		<p>Hi {{.UserName}},</p>
		<p>We detected a security event on your account:</p>
		<div style="background-color: #f8f9fa; padding: 15px; border-left: 4px solid #dc3545; margin: 20px 0;">
			<strong>{{.AlertType}}</strong><br>
			{{.AlertMessage}}
		</div>
		<ul>
			<li><strong>Time:</strong> {{.Timestamp}}</li>
			<li><strong>Location:</strong> {{.Location}}</li>
			<li><strong>IP Address:</strong> {{.IPAddress}}</li>
		</ul>
		<p>If this was you, no action is needed. If not, please secure your account immediately.</p>
		<p>Best regards,<br>The {{.AppName}} Security Team</p>`,
	))

	s.RegisterTemplate(s.CreatePushTemplate(
		"security_alert_push",
		"Security Alert",
		"{{.AlertType}} detected on your account. Tap for details.",
	))

	// Meeting invite templates
	s.RegisterTemplate(s.CreateEmailTemplate(
		"meeting_invite_email",
		"Meeting Invitation: {{.MeetingTitle}}",
		"Hi {{.UserName}},\n\nYou're invited to a meeting:\n\nTitle: {{.MeetingTitle}}\nDate: {{.MeetingDate}}\nTime: {{.MeetingTime}}\nDuration: {{.Duration}}\n\nJoin the meeting: {{.JoinURL}}\n\nMeeting ID: {{.MeetingID}}\nPasscode: {{.Passcode}}\n\nAgenda:\n{{.Agenda}}\n\nBest regards,\n{{.OrganizerName}}",
		`<h1>Meeting Invitation</h1>
		<p>Hi {{.UserName}},</p>
		<p>You're invited to a meeting:</p>
		<div style="background-color: #f8f9fa; padding: 20px; border-radius: 5px; margin: 20px 0;">
			<h2>{{.MeetingTitle}}</h2>
			<p><strong>Date:</strong> {{.MeetingDate}}</p>
			<p><strong>Time:</strong> {{.MeetingTime}}</p>
			<p><strong>Duration:</strong> {{.Duration}}</p>
			<p><a href="{{.JoinURL}}" style="background-color: #28a745; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">Join Meeting</a></p>
			<p><strong>Meeting ID:</strong> {{.MeetingID}}<br>
			<strong>Passcode:</strong> {{.Passcode}}</p>
		</div>
		<h3>Agenda:</h3>
		<p>{{.Agenda}}</p>
		<p>Best regards,<br>{{.OrganizerName}}</p>`,
	))

	// Calendar event templates
	s.RegisterTemplate(s.CreatePushTemplate(
		"calendar_reminder_push",
		"Event Reminder",
		"{{.EventTitle}} starts in {{.TimeUntil}}. Tap for details.",
	))

	// Chat message templates
	s.RegisterTemplate(s.CreatePushTemplate(
		"chat_message_push",
		"New message from {{.SenderName}}",
		"{{.MessagePreview}}",
	))

	// System notification templates
	s.RegisterTemplate(s.CreateEmailTemplate(
		"system_maintenance_email",
		"Scheduled Maintenance - {{.MaintenanceDate}}",
		"Hi {{.UserName}},\n\nWe have scheduled maintenance for {{.AppName}}:\n\nDate: {{.MaintenanceDate}}\nTime: {{.MaintenanceTime}}\nDuration: {{.Duration}}\n\nDuring this time, the service may be temporarily unavailable.\n\n{{.MaintenanceDetails}}\n\nWe apologize for any inconvenience.\n\nBest regards,\nThe {{.AppName}} Team",
		`<h1>Scheduled Maintenance</h1>
		<p>Hi {{.UserName}},</p>
		<p>We have scheduled maintenance for {{.AppName}}:</p>
		<div style="background-color: #fff3cd; padding: 15px; border-left: 4px solid #ffc107; margin: 20px 0;">
			<p><strong>Date:</strong> {{.MaintenanceDate}}</p>
			<p><strong>Time:</strong> {{.MaintenanceTime}}</p>
			<p><strong>Duration:</strong> {{.Duration}}</p>
		</div>
		<p>During this time, the service may be temporarily unavailable.</p>
		<p>{{.MaintenanceDetails}}</p>
		<p>We apologize for any inconvenience.</p>
		<p>Best regards,<br>The {{.AppName}} Team</p>`,
	))

	// SMS templates
	s.RegisterTemplate(s.CreateSMSTemplate(
		"verification_code_sms",
		"Your {{.AppName}} verification code: {{.Code}}. Valid for {{.ExpiresIn}} minutes.",
	))

	s.RegisterTemplate(s.CreateSMSTemplate(
		"login_alert_sms",
		"{{.AppName}} Security: New login from {{.Location}} at {{.Time}}. If this wasn't you, secure your account immediately.",
	))

	// Slack templates
	s.RegisterTemplate(s.CreateSlackTemplate(
		"deployment_notification_slack",
		"🚀 *Deployment Complete*\n\n*Environment:* {{.Environment}}\n*Version:* {{.Version}}\n*Status:* {{.Status}}\n*Duration:* {{.Duration}}\n\n{{.Changes}}",
	))

	s.RegisterTemplate(s.CreateSlackTemplate(
		"error_alert_slack",
		"🚨 *Error Alert*\n\n*Service:* {{.Service}}\n*Error:* {{.ErrorMessage}}\n*Count:* {{.ErrorCount}}\n*Time:* {{.Timestamp}}\n\n<{{.LogsURL}}|View Logs>",
	))
}

func (s *NotificationTemplateService) LoadTemplatesFromFiles() error {
	templateDir := s.basePath

	// Walk through template directory
	return filepath.Walk(templateDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if info.IsDir() {
			return nil
		}

		// Only process .tmpl files
		if !strings.HasSuffix(path, ".tmpl") {
			return nil
		}

		// Read template file
		content, err := os.ReadFile(path)
		if err != nil {
			facades.Log().Warning("Failed to read template file", map[string]interface{}{
				"file":  path,
				"error": err.Error(),
			})
			return nil // Continue processing other files
		}

		// Extract template name from file path
		relativePath, _ := filepath.Rel(templateDir, path)
		templateName := strings.TrimSuffix(relativePath, ".tmpl")
		templateName = strings.ReplaceAll(templateName, string(filepath.Separator), "_")

		// Determine template type from directory structure
		templateType := "email" // default
		if strings.Contains(relativePath, "push") {
			templateType = "push"
		} else if strings.Contains(relativePath, "sms") {
			templateType = "sms"
		} else if strings.Contains(relativePath, "slack") {
			templateType = "slack"
		}

		// Create and register template
		template := NewNotificationTemplate(templateName, templateType)
		template.SetBody(string(content))

		s.RegisterTemplate(template)

		facades.Log().Info("Loaded template from file", map[string]interface{}{
			"template": templateName,
			"type":     templateType,
			"file":     path,
		})

		return nil
	})
}

func (s *NotificationTemplateService) GetTemplateVariables(templateName string) ([]string, error) {
	template, err := s.GetTemplate(templateName)
	if err != nil {
		return nil, err
	}

	return template.GetVariables(), nil
}

func (s *NotificationTemplateService) ValidateTemplateData(templateName string, data map[string]interface{}) error {
	variables, err := s.GetTemplateVariables(templateName)
	if err != nil {
		return err
	}

	// Check if all required variables are provided
	for _, variable := range variables {
		if _, exists := data[variable]; !exists {
			return fmt.Errorf("missing required variable: %s", variable)
		}
	}

	return nil
}
