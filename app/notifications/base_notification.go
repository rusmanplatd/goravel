package notifications

import (
	"time"

	"goravel/app/notificationcore"
)

// BaseNotification provides default implementations for notification classes
type BaseNotification struct {
	notificationType string
	data             map[string]interface{}
	channels         []string
	shouldQueue      bool
	queueDelay       time.Duration
	queueConnection  string
	queueName        string
	retryAfter       time.Duration
	maxRetries       int
	subject          string
	message          string
	title            string
	body             string
	actionURL        string
	actionText       string
	icon             string
	color            string
	priority         string
	category         string
	tags             []string
	metadata         map[string]interface{}
}

// NewBaseNotification creates a new base notification with default values
func NewBaseNotification() *BaseNotification {
	return &BaseNotification{
		notificationType: "base",
		data:             make(map[string]interface{}),
		channels:         []string{"database"},
		shouldQueue:      false,
		queueDelay:       0,
		queueConnection:  "default",
		queueName:        "notifications",
		retryAfter:       5 * time.Minute,
		maxRetries:       3,
		subject:          "",
		message:          "",
		title:            "",
		body:             "",
		actionURL:        "",
		actionText:       "",
		icon:             "",
		color:            "",
		priority:         "normal",
		category:         "general",
		tags:             []string{},
		metadata:         make(map[string]interface{}),
	}
}

// GetType returns the notification type
func (n *BaseNotification) GetType() string {
	return n.notificationType
}

// SetType sets the notification type
func (n *BaseNotification) SetType(notificationType string) {
	n.notificationType = notificationType
}

// GetData returns the notification data
func (n *BaseNotification) GetData() map[string]interface{} {
	return n.data
}

// SetData sets the notification data
func (n *BaseNotification) SetData(data map[string]interface{}) {
	n.data = data
}

// GetChannels returns the channels to send through
func (n *BaseNotification) GetChannels() []string {
	return n.channels
}

// SetChannels sets the channels to send through
func (n *BaseNotification) SetChannels(channels []string) {
	n.channels = channels
}

// ShouldQueue returns whether the notification should be queued
func (n *BaseNotification) ShouldQueue() bool {
	return n.shouldQueue
}

// SetShouldQueue sets whether the notification should be queued
func (n *BaseNotification) SetShouldQueue(shouldQueue bool) {
	n.shouldQueue = shouldQueue
}

// GetQueueDelay returns the queue delay
func (n *BaseNotification) GetQueueDelay() time.Duration {
	return n.queueDelay
}

// SetQueueDelay sets the queue delay
func (n *BaseNotification) SetQueueDelay(delay time.Duration) {
	n.queueDelay = delay
}

// GetQueueConnection returns the queue connection
func (n *BaseNotification) GetQueueConnection() string {
	return n.queueConnection
}

// SetQueueConnection sets the queue connection
func (n *BaseNotification) SetQueueConnection(connection string) {
	n.queueConnection = connection
}

// GetQueueName returns the queue name
func (n *BaseNotification) GetQueueName() string {
	return n.queueName
}

// SetQueueName sets the queue name
func (n *BaseNotification) SetQueueName(name string) {
	n.queueName = name
}

// GetRetryAfter returns the retry delay
func (n *BaseNotification) GetRetryAfter() time.Duration {
	return n.retryAfter
}

// SetRetryAfter sets the retry delay
func (n *BaseNotification) SetRetryAfter(delay time.Duration) {
	n.retryAfter = delay
}

// GetMaxRetries returns the maximum number of retries
func (n *BaseNotification) GetMaxRetries() int {
	return n.maxRetries
}

// SetMaxRetries sets the maximum number of retries
func (n *BaseNotification) SetMaxRetries(max int) {
	n.maxRetries = max
}

// ShouldSend determines if the notification should be sent to the notifiable
func (n *BaseNotification) ShouldSend(notifiable notificationcore.Notifiable) bool {
	// Default implementation: always send
	// Override in specific notifications for custom logic
	return true
}

// GetSubject returns the notification subject
func (n *BaseNotification) GetSubject() string {
	return n.subject
}

// SetSubject sets the notification subject
func (n *BaseNotification) SetSubject(subject string) {
	n.subject = subject
}

// GetMessage returns the notification message
func (n *BaseNotification) GetMessage() string {
	return n.message
}

// SetMessage sets the notification message
func (n *BaseNotification) SetMessage(message string) {
	n.message = message
}

// GetTitle returns the notification title
func (n *BaseNotification) GetTitle() string {
	return n.title
}

// SetTitle sets the notification title
func (n *BaseNotification) SetTitle(title string) {
	n.title = title
}

// GetBody returns the notification body
func (n *BaseNotification) GetBody() string {
	return n.body
}

// SetBody sets the notification body
func (n *BaseNotification) SetBody(body string) {
	n.body = body
}

// GetActionURL returns the action URL
func (n *BaseNotification) GetActionURL() string {
	return n.actionURL
}

// SetActionURL sets the action URL
func (n *BaseNotification) SetActionURL(url string) {
	n.actionURL = url
}

// GetActionText returns the action text
func (n *BaseNotification) GetActionText() string {
	return n.actionText
}

// SetActionText sets the action text
func (n *BaseNotification) SetActionText(text string) {
	n.actionText = text
}

// GetIcon returns the notification icon
func (n *BaseNotification) GetIcon() string {
	return n.icon
}

// SetIcon sets the notification icon
func (n *BaseNotification) SetIcon(icon string) {
	n.icon = icon
}

// GetColor returns the notification color
func (n *BaseNotification) GetColor() string {
	return n.color
}

// SetColor sets the notification color
func (n *BaseNotification) SetColor(color string) {
	n.color = color
}

// GetPriority returns the notification priority
func (n *BaseNotification) GetPriority() string {
	return n.priority
}

// SetPriority sets the notification priority
func (n *BaseNotification) SetPriority(priority string) {
	n.priority = priority
}

// GetCategory returns the notification category
func (n *BaseNotification) GetCategory() string {
	return n.category
}

// SetCategory sets the notification category
func (n *BaseNotification) SetCategory(category string) {
	n.category = category
}

// GetTags returns the notification tags
func (n *BaseNotification) GetTags() []string {
	return n.tags
}

// SetTags sets the notification tags
func (n *BaseNotification) SetTags(tags []string) {
	n.tags = tags
}

// GetMetadata returns the notification metadata
func (n *BaseNotification) GetMetadata() map[string]interface{} {
	return n.metadata
}

// SetMetadata sets the notification metadata
func (n *BaseNotification) SetMetadata(metadata map[string]interface{}) {
	n.metadata = metadata
}

// AddData adds a key-value pair to the notification data
func (n *BaseNotification) AddData(key string, value interface{}) {
	if n.data == nil {
		n.data = make(map[string]interface{})
	}
	n.data[key] = value
}

// AddTag adds a tag to the notification
func (n *BaseNotification) AddTag(tag string) {
	n.tags = append(n.tags, tag)
}

// AddMetadata adds a key-value pair to the notification metadata
func (n *BaseNotification) AddMetadata(key string, value interface{}) {
	if n.metadata == nil {
		n.metadata = make(map[string]interface{})
	}
	n.metadata[key] = value
}

// SetChannel sets a single channel for the notification
func (n *BaseNotification) SetChannel(channel string) {
	n.channels = []string{channel}
}

// AddChannel adds a channel to the notification
func (n *BaseNotification) AddChannel(channel string) {
	n.channels = append(n.channels, channel)
}

// RemoveChannel removes a channel from the notification
func (n *BaseNotification) RemoveChannel(channel string) {
	for i, ch := range n.channels {
		if ch == channel {
			n.channels = append(n.channels[:i], n.channels[i+1:]...)
			break
		}
	}
}

// HasChannel checks if the notification has a specific channel
func (n *BaseNotification) HasChannel(channel string) bool {
	for _, ch := range n.channels {
		if ch == channel {
			return true
		}
	}
	return false
}

// ClearChannels removes all channels from the notification
func (n *BaseNotification) ClearChannels() {
	n.channels = []string{}
}

// SetQueue sets the notification to be queued
func (n *BaseNotification) SetQueue(shouldQueue bool, delay time.Duration) {
	n.shouldQueue = shouldQueue
	n.queueDelay = delay
}

// SetRetry sets the retry configuration
func (n *BaseNotification) SetRetry(retryAfter time.Duration, maxRetries int) {
	n.retryAfter = retryAfter
	n.maxRetries = maxRetries
}

// SetAction sets the action URL and text
func (n *BaseNotification) SetAction(url, text string) {
	n.actionURL = url
	n.actionText = text
}

// SetAppearance sets the visual appearance of the notification
func (n *BaseNotification) SetAppearance(icon, color string) {
	n.icon = icon
	n.color = color
}

// SetClassification sets the classification of the notification
func (n *BaseNotification) SetClassification(priority, category string) {
	n.priority = priority
	n.category = category
}
