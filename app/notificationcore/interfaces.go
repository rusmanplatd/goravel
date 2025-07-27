package notificationcore

import (
	"context"
	"time"
)

// Notifiable interface defines entities that can receive notifications
type Notifiable interface {
	GetID() string
	GetType() string
	GetEmail() string
	GetPhone() string
	GetPushTokens() []string
	GetWebhookURL() string
	GetTimezone() string
	GetLocale() string
	GetNotificationPreferences() map[string]interface{}

	// Modern methods - no backward compatibility
	GetChannelAddress(channel string) string
	IsChannelEnabled(channel string) bool
	GetQuietHours() (start, end string)
	GetRateLimits() map[string]int
}

// Notification interface defines the contract for notification classes
type Notification interface {
	// Core identification
	GetID() string
	GetType() string
	GetVersion() string // For notification versioning

	// Content and presentation
	GetData() map[string]interface{}
	GetTemplate() string
	GetSubject() string
	GetTitle() string
	GetBody() string
	GetActionURL() string
	GetActionText() string
	GetIcon() string
	GetColor() string
	GetImageURL() string
	GetSound() string

	// Delivery configuration
	GetChannels() []string
	GetPriority() Priority
	GetCategory() string
	GetTags() []string
	GetMetadata() map[string]interface{}

	// Scheduling and timing
	GetScheduledAt() *time.Time
	GetDelay() time.Duration
	GetExpiresAt() *time.Time
	GetRetryPolicy() RetryPolicy

	// Queue configuration
	ShouldQueue() bool
	GetQueueConnection() string
	GetQueueName() string

	// Conditional delivery
	ShouldSend(notifiable Notifiable) bool
	GetDeliveryConditions() []DeliveryCondition

	// Batching and grouping
	SupportsBatching() bool
	GetBatchKey() string
	GetBatchDelay() time.Duration

	// Localization
	GetLocale() string
	GetLocalizedContent(locale string) map[string]string

	// Tracking and analytics
	GetTrackingID() string
	GetAnalyticsData() map[string]interface{}
	ShouldTrackOpens() bool
	ShouldTrackClicks() bool
}

// Channel interface defines the contract for notification channels
type Channel interface {
	// Core functionality
	Send(ctx context.Context, notification Notification, notifiable Notifiable) error
	GetName() string
	GetVersion() string

	// Configuration and validation
	IsEnabled() bool
	Validate() error
	GetConfig() map[string]interface{}

	// Capabilities
	SupportsBatching() bool
	SupportsScheduling() bool
	SupportsRichContent() bool
	GetMaxBatchSize() int

	// Rate limiting
	GetRateLimit() int
	GetRateLimitWindow() time.Duration

	// Delivery confirmation
	SupportsDeliveryConfirmation() bool
	SupportsReadReceipts() bool

	// Template support
	SupportsTemplates() bool
	RenderTemplate(template string, data map[string]interface{}) (string, error)
}

// Manager interface defines the contract for the notification manager
type Manager interface {
	// Core sending methods
	Send(ctx context.Context, notification Notification, notifiable Notifiable) error
	SendNow(ctx context.Context, notification Notification, notifiable Notifiable) error
	SendToMany(ctx context.Context, notification Notification, notifiables []Notifiable) error
	SendBatch(ctx context.Context, notifications []Notification, notifiable Notifiable) error

	// Scheduling
	Schedule(ctx context.Context, notification Notification, notifiable Notifiable, scheduledAt time.Time) error
	CancelScheduled(notificationID string) error

	// Channel management
	GetChannel(name string) (Channel, error)
	GetChannels() map[string]Channel
	RegisterChannel(channel Channel) error
	UnregisterChannel(name string) error

	// Validation and testing
	ValidateChannel(name string) error
	TestChannel(name string, testData map[string]interface{}) error

	// Batch processing
	ProcessBatch(ctx context.Context, batchKey string) error
	GetPendingBatches() []string

	// Analytics and monitoring
	GetMetrics(startDate, endDate time.Time) (map[string]interface{}, error)
	GetChannelHealth() map[string]ChannelHealth
}

// Priority represents notification priority levels
type Priority string

const (
	PriorityLow      Priority = "low"
	PriorityNormal   Priority = "normal"
	PriorityHigh     Priority = "high"
	PriorityUrgent   Priority = "urgent"
	PriorityCritical Priority = "critical"
)

// RetryPolicy defines how notifications should be retried
type RetryPolicy struct {
	MaxAttempts   int           `json:"max_attempts"`
	BaseDelay     time.Duration `json:"base_delay"`
	MaxDelay      time.Duration `json:"max_delay"`
	BackoffFactor float64       `json:"backoff_factor"`
	JitterEnabled bool          `json:"jitter_enabled"`
	RetryOn       []string      `json:"retry_on"` // Error types to retry on
	StopOn        []string      `json:"stop_on"`  // Error types to stop retrying on
}

// DeliveryCondition defines conditions for notification delivery
type DeliveryCondition struct {
	Type     string                 `json:"type"`     // "time", "user_status", "preference", etc.
	Operator string                 `json:"operator"` // "equals", "not_equals", "in", "not_in", etc.
	Value    interface{}            `json:"value"`
	Metadata map[string]interface{} `json:"metadata"`
}

// ChannelHealth represents the health status of a notification channel
type ChannelHealth struct {
	Status            string    `json:"status"` // "healthy", "degraded", "unhealthy"
	LastChecked       time.Time `json:"last_checked"`
	ResponseTime      float64   `json:"response_time_ms"`
	SuccessRate       float64   `json:"success_rate"`
	ErrorRate         float64   `json:"error_rate"`
	LastError         string    `json:"last_error,omitempty"`
	RecommendedAction string    `json:"recommended_action,omitempty"`
}

// Template interface for notification templates
type Template interface {
	GetName() string
	GetType() string // "email", "push", "sms", etc.
	GetSubject() string
	GetBody() string
	GetVariables() []string
	Render(data map[string]interface{}) (RenderedTemplate, error)
	Validate() error
}

// RenderedTemplate represents a rendered notification template
type RenderedTemplate struct {
	Subject string `json:"subject"`
	Body    string `json:"body"`
	HTML    string `json:"html,omitempty"`
	Text    string `json:"text,omitempty"`
}

// Scheduler interface for scheduling notifications
type Scheduler interface {
	Schedule(ctx context.Context, notification Notification, notifiable Notifiable, scheduledAt time.Time) (string, error)
	Cancel(scheduleID string) error
	Update(scheduleID string, scheduledAt time.Time) error
	GetScheduled(notifiableID string) ([]ScheduledNotification, error)
	ProcessDue(ctx context.Context) error
}

// ScheduledNotification represents a scheduled notification
type ScheduledNotification struct {
	ID           string       `json:"id"`
	Notification Notification `json:"notification"`
	Notifiable   Notifiable   `json:"notifiable"`
	ScheduledAt  time.Time    `json:"scheduled_at"`
	Status       string       `json:"status"` // "pending", "sent", "cancelled", "failed"
	CreatedAt    time.Time    `json:"created_at"`
	UpdatedAt    time.Time    `json:"updated_at"`
}

// Batcher interface for batching notifications
type Batcher interface {
	Add(ctx context.Context, notification Notification, notifiable Notifiable) error
	Process(ctx context.Context, batchKey string) error
	GetPending() ([]string, error)
	Clear(batchKey string) error
	GetBatchSize(batchKey string) (int, error)
}

// Middleware interface for notification processing middleware
type Middleware interface {
	Handle(ctx context.Context, notification Notification, notifiable Notifiable, next func() error) error
	GetName() string
	GetPriority() int
}

// Filter interface for notification filtering
type Filter interface {
	ShouldSend(ctx context.Context, notification Notification, notifiable Notifiable) (bool, string)
	GetName() string
}

// Transformer interface for notification transformation
type Transformer interface {
	Transform(ctx context.Context, notification Notification, notifiable Notifiable) (Notification, error)
	GetName() string
	GetSupportedTypes() []string
}

// Analytics interface for notification analytics
type Analytics interface {
	Track(event string, notificationID string, data map[string]interface{}) error
	GetMetrics(startDate, endDate time.Time) (map[string]interface{}, error)
	GetChannelMetrics(channel string, startDate, endDate time.Time) (map[string]interface{}, error)
	GetUserMetrics(userID string, startDate, endDate time.Time) (map[string]interface{}, error)
}
