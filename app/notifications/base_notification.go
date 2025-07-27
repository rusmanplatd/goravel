package notifications

import (
	"crypto/rand"
	"encoding/hex"
	"goravel/app/notificationcore"
	"time"
)

// BaseNotification provides modern implementations for notification classes
type BaseNotification struct {
	// Core identification
	id      string
	version string

	// Content and presentation
	notificationType string
	data             map[string]interface{}
	template         string
	subject          string
	title            string
	body             string
	actionURL        string
	actionText       string
	icon             string
	color            string
	imageURL         string
	sound            string

	// Delivery configuration
	channels []string
	priority notificationcore.Priority
	category string
	tags     []string
	metadata map[string]interface{}

	// Scheduling and timing
	scheduledAt *time.Time
	delay       time.Duration
	expiresAt   *time.Time
	retryPolicy notificationcore.RetryPolicy

	// Queue configuration
	shouldQueue     bool
	queueConnection string
	queueName       string

	// Conditional delivery
	deliveryConditions []notificationcore.DeliveryCondition

	// Batching and grouping
	supportsBatching bool
	batchKey         string
	batchDelay       time.Duration

	// Localization
	locale           string
	localizedContent map[string]map[string]string

	// Tracking and analytics
	trackingID    string
	analyticsData map[string]interface{}
	trackOpens    bool
	trackClicks   bool
}

// NewBaseNotification creates a new modern base notification
func NewBaseNotification() *BaseNotification {
	id := generateID()
	return &BaseNotification{
		id:      id,
		version: "2.0",

		// Default values
		notificationType: "BaseNotification",
		data:             make(map[string]interface{}),
		template:         "",
		subject:          "",
		title:            "",
		body:             "",
		actionURL:        "",
		actionText:       "",
		icon:             "",
		color:            "#000000",
		imageURL:         "",
		sound:            "default",

		// Delivery defaults
		channels: []string{"database"},
		priority: notificationcore.PriorityNormal,
		category: "general",
		tags:     []string{},
		metadata: make(map[string]interface{}),

		// Scheduling defaults
		delay: 0,
		retryPolicy: notificationcore.RetryPolicy{
			MaxAttempts:   3,
			BaseDelay:     5 * time.Second,
			MaxDelay:      5 * time.Minute,
			BackoffFactor: 2.0,
			JitterEnabled: true,
			RetryOn:       []string{"network_error", "timeout", "rate_limit"},
			StopOn:        []string{"invalid_token", "permission_denied"},
		},

		// Queue defaults
		shouldQueue:     false,
		queueConnection: "default",
		queueName:       "notifications",

		// Batching defaults
		supportsBatching: false,
		batchKey:         "",
		batchDelay:       5 * time.Minute,

		// Localization defaults
		locale:           "en",
		localizedContent: make(map[string]map[string]string),

		// Analytics defaults
		trackingID:    id,
		analyticsData: make(map[string]interface{}),
		trackOpens:    true,
		trackClicks:   true,
	}
}

// Core identification methods
func (n *BaseNotification) GetID() string {
	return n.id
}

func (n *BaseNotification) GetType() string {
	return n.notificationType
}

func (n *BaseNotification) GetVersion() string {
	return n.version
}

func (n *BaseNotification) SetType(notificationType string) *BaseNotification {
	n.notificationType = notificationType
	return n
}

// Content and presentation methods
func (n *BaseNotification) GetData() map[string]interface{} {
	return n.data
}

func (n *BaseNotification) SetData(data map[string]interface{}) *BaseNotification {
	n.data = data
	return n
}

func (n *BaseNotification) AddData(key string, value interface{}) *BaseNotification {
	if n.data == nil {
		n.data = make(map[string]interface{})
	}
	n.data[key] = value
	return n
}

func (n *BaseNotification) GetTemplate() string {
	return n.template
}

func (n *BaseNotification) SetTemplate(template string) *BaseNotification {
	n.template = template
	return n
}

func (n *BaseNotification) GetSubject() string {
	return n.subject
}

func (n *BaseNotification) SetSubject(subject string) *BaseNotification {
	n.subject = subject
	return n
}

func (n *BaseNotification) GetTitle() string {
	return n.title
}

func (n *BaseNotification) SetTitle(title string) *BaseNotification {
	n.title = title
	return n
}

func (n *BaseNotification) GetBody() string {
	return n.body
}

func (n *BaseNotification) SetBody(body string) *BaseNotification {
	n.body = body
	return n
}

func (n *BaseNotification) GetActionURL() string {
	return n.actionURL
}

func (n *BaseNotification) SetActionURL(url string) *BaseNotification {
	n.actionURL = url
	return n
}

func (n *BaseNotification) GetActionText() string {
	return n.actionText
}

func (n *BaseNotification) SetActionText(text string) *BaseNotification {
	n.actionText = text
	return n
}

func (n *BaseNotification) GetIcon() string {
	return n.icon
}

func (n *BaseNotification) SetIcon(icon string) *BaseNotification {
	n.icon = icon
	return n
}

func (n *BaseNotification) GetColor() string {
	return n.color
}

func (n *BaseNotification) SetColor(color string) *BaseNotification {
	n.color = color
	return n
}

func (n *BaseNotification) GetImageURL() string {
	return n.imageURL
}

func (n *BaseNotification) SetImageURL(url string) *BaseNotification {
	n.imageURL = url
	return n
}

func (n *BaseNotification) GetSound() string {
	return n.sound
}

func (n *BaseNotification) SetSound(sound string) *BaseNotification {
	n.sound = sound
	return n
}

// Delivery configuration methods
func (n *BaseNotification) GetChannels() []string {
	return n.channels
}

func (n *BaseNotification) SetChannels(channels []string) *BaseNotification {
	n.channels = channels
	return n
}

func (n *BaseNotification) AddChannel(channel string) *BaseNotification {
	for _, existing := range n.channels {
		if existing == channel {
			return n // Already exists
		}
	}
	n.channels = append(n.channels, channel)
	return n
}

func (n *BaseNotification) GetPriority() notificationcore.Priority {
	return n.priority
}

func (n *BaseNotification) SetPriority(priority notificationcore.Priority) *BaseNotification {
	n.priority = priority
	return n
}

func (n *BaseNotification) GetCategory() string {
	return n.category
}

func (n *BaseNotification) SetCategory(category string) *BaseNotification {
	n.category = category
	return n
}

func (n *BaseNotification) GetTags() []string {
	return n.tags
}

func (n *BaseNotification) SetTags(tags []string) *BaseNotification {
	n.tags = tags
	return n
}

func (n *BaseNotification) AddTag(tag string) *BaseNotification {
	for _, existing := range n.tags {
		if existing == tag {
			return n // Already exists
		}
	}
	n.tags = append(n.tags, tag)
	return n
}

func (n *BaseNotification) GetMetadata() map[string]interface{} {
	return n.metadata
}

func (n *BaseNotification) SetMetadata(metadata map[string]interface{}) *BaseNotification {
	n.metadata = metadata
	return n
}

func (n *BaseNotification) AddMetadata(key string, value interface{}) *BaseNotification {
	if n.metadata == nil {
		n.metadata = make(map[string]interface{})
	}
	n.metadata[key] = value
	return n
}

// Scheduling and timing methods
func (n *BaseNotification) GetScheduledAt() *time.Time {
	return n.scheduledAt
}

func (n *BaseNotification) SetScheduledAt(scheduledAt time.Time) *BaseNotification {
	n.scheduledAt = &scheduledAt
	return n
}

func (n *BaseNotification) GetDelay() time.Duration {
	return n.delay
}

func (n *BaseNotification) SetDelay(delay time.Duration) *BaseNotification {
	n.delay = delay
	return n
}

func (n *BaseNotification) GetExpiresAt() *time.Time {
	return n.expiresAt
}

func (n *BaseNotification) SetExpiresAt(expiresAt time.Time) *BaseNotification {
	n.expiresAt = &expiresAt
	return n
}

func (n *BaseNotification) SetExpiresIn(duration time.Duration) *BaseNotification {
	expiresAt := time.Now().Add(duration)
	n.expiresAt = &expiresAt
	return n
}

func (n *BaseNotification) GetRetryPolicy() notificationcore.RetryPolicy {
	return n.retryPolicy
}

func (n *BaseNotification) SetRetryPolicy(policy notificationcore.RetryPolicy) *BaseNotification {
	n.retryPolicy = policy
	return n
}

// Queue configuration methods
func (n *BaseNotification) ShouldQueue() bool {
	return n.shouldQueue
}

func (n *BaseNotification) SetShouldQueue(shouldQueue bool) *BaseNotification {
	n.shouldQueue = shouldQueue
	return n
}

func (n *BaseNotification) GetQueueConnection() string {
	return n.queueConnection
}

func (n *BaseNotification) SetQueueConnection(connection string) *BaseNotification {
	n.queueConnection = connection
	return n
}

func (n *BaseNotification) GetQueueName() string {
	return n.queueName
}

func (n *BaseNotification) SetQueueName(queueName string) *BaseNotification {
	n.queueName = queueName
	return n
}

// Conditional delivery methods
func (n *BaseNotification) ShouldSend(notifiable notificationcore.Notifiable) bool {
	// Check delivery conditions
	for _, condition := range n.deliveryConditions {
		if !n.evaluateCondition(condition, notifiable) {
			return false
		}
	}

	// Check expiration
	if n.expiresAt != nil && time.Now().After(*n.expiresAt) {
		return false
	}

	return true
}

func (n *BaseNotification) GetDeliveryConditions() []notificationcore.DeliveryCondition {
	return n.deliveryConditions
}

func (n *BaseNotification) SetDeliveryConditions(conditions []notificationcore.DeliveryCondition) *BaseNotification {
	n.deliveryConditions = conditions
	return n
}

func (n *BaseNotification) AddDeliveryCondition(condition notificationcore.DeliveryCondition) *BaseNotification {
	n.deliveryConditions = append(n.deliveryConditions, condition)
	return n
}

// Batching and grouping methods
func (n *BaseNotification) SupportsBatching() bool {
	return n.supportsBatching
}

func (n *BaseNotification) SetSupportsBatching(supports bool) *BaseNotification {
	n.supportsBatching = supports
	return n
}

func (n *BaseNotification) GetBatchKey() string {
	return n.batchKey
}

func (n *BaseNotification) SetBatchKey(key string) *BaseNotification {
	n.batchKey = key
	n.supportsBatching = true
	return n
}

func (n *BaseNotification) GetBatchDelay() time.Duration {
	return n.batchDelay
}

func (n *BaseNotification) SetBatchDelay(delay time.Duration) *BaseNotification {
	n.batchDelay = delay
	return n
}

// Localization methods
func (n *BaseNotification) GetLocale() string {
	return n.locale
}

func (n *BaseNotification) SetLocale(locale string) *BaseNotification {
	n.locale = locale
	return n
}

func (n *BaseNotification) GetLocalizedContent(locale string) map[string]string {
	if content, exists := n.localizedContent[locale]; exists {
		return content
	}
	return map[string]string{}
}

func (n *BaseNotification) SetLocalizedContent(locale string, content map[string]string) *BaseNotification {
	if n.localizedContent == nil {
		n.localizedContent = make(map[string]map[string]string)
	}
	n.localizedContent[locale] = content
	return n
}

func (n *BaseNotification) AddLocalizedContent(locale, key, value string) *BaseNotification {
	if n.localizedContent == nil {
		n.localizedContent = make(map[string]map[string]string)
	}
	if n.localizedContent[locale] == nil {
		n.localizedContent[locale] = make(map[string]string)
	}
	n.localizedContent[locale][key] = value
	return n
}

// Tracking and analytics methods
func (n *BaseNotification) GetTrackingID() string {
	return n.trackingID
}

func (n *BaseNotification) SetTrackingID(id string) *BaseNotification {
	n.trackingID = id
	return n
}

func (n *BaseNotification) GetAnalyticsData() map[string]interface{} {
	return n.analyticsData
}

func (n *BaseNotification) SetAnalyticsData(data map[string]interface{}) *BaseNotification {
	n.analyticsData = data
	return n
}

func (n *BaseNotification) AddAnalyticsData(key string, value interface{}) *BaseNotification {
	if n.analyticsData == nil {
		n.analyticsData = make(map[string]interface{})
	}
	n.analyticsData[key] = value
	return n
}

func (n *BaseNotification) ShouldTrackOpens() bool {
	return n.trackOpens
}

func (n *BaseNotification) SetTrackOpens(track bool) *BaseNotification {
	n.trackOpens = track
	return n
}

func (n *BaseNotification) ShouldTrackClicks() bool {
	return n.trackClicks
}

func (n *BaseNotification) SetTrackClicks(track bool) *BaseNotification {
	n.trackClicks = track
	return n
}

// Helper methods
func (n *BaseNotification) evaluateCondition(condition notificationcore.DeliveryCondition, notifiable notificationcore.Notifiable) bool {
	switch condition.Type {
	case "time":
		return n.evaluateTimeCondition(condition)
	case "user_status":
		return n.evaluateUserStatusCondition(condition, notifiable)
	case "preference":
		return n.evaluatePreferenceCondition(condition, notifiable)
	default:
		return true // Unknown conditions are ignored
	}
}

func (n *BaseNotification) evaluateTimeCondition(condition notificationcore.DeliveryCondition) bool {
	now := time.Now()
	switch condition.Operator {
	case "after":
		if timeValue, ok := condition.Value.(time.Time); ok {
			return now.After(timeValue)
		}
	case "before":
		if timeValue, ok := condition.Value.(time.Time); ok {
			return now.Before(timeValue)
		}
	case "between":
		if timeRange, ok := condition.Value.([]time.Time); ok && len(timeRange) == 2 {
			return now.After(timeRange[0]) && now.Before(timeRange[1])
		}
	}
	return true
}

func (n *BaseNotification) evaluateUserStatusCondition(condition notificationcore.DeliveryCondition, notifiable notificationcore.Notifiable) bool {
	// This would need to be implemented based on your user model
	// For now, we'll just return true
	return true
}

func (n *BaseNotification) evaluatePreferenceCondition(condition notificationcore.DeliveryCondition, notifiable notificationcore.Notifiable) bool {
	preferences := notifiable.GetNotificationPreferences()
	if preferences == nil {
		return true
	}

	switch condition.Operator {
	case "enabled":
		if value, exists := preferences[condition.Value.(string)]; exists {
			if enabled, ok := value.(bool); ok {
				return enabled
			}
		}
	case "disabled":
		if value, exists := preferences[condition.Value.(string)]; exists {
			if enabled, ok := value.(bool); ok {
				return !enabled
			}
		}
	}
	return true
}

// generateID generates a unique ID for the notification
func generateID() string {
	bytes := make([]byte, 16)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}
