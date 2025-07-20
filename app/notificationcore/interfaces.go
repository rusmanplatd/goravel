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
	GetSlackWebhook() string
	GetDiscordWebhook() string
	GetTelegramChatID() string
	GetPushTokens() []string
	GetWebhookURL() string
	GetPreferredChannels() []string
	ShouldReceiveNotification(notification Notification) bool
}

// Notification interface defines the contract for notification classes
type Notification interface {
	GetType() string
	GetData() map[string]interface{}
	GetChannels() []string
	ShouldQueue() bool
	GetQueueDelay() time.Duration
	GetQueueConnection() string
	GetQueueName() string
	GetRetryAfter() time.Duration
	GetMaxRetries() int
	ShouldSend(notifiable Notifiable) bool
	GetSubject() string
	GetMessage() string
	GetTitle() string
	GetBody() string
	GetActionURL() string
	GetActionText() string
	GetIcon() string
	GetColor() string
	GetPriority() string
	GetCategory() string
	GetTags() []string
	GetMetadata() map[string]interface{}
}

// Channel interface defines the contract for notification channels
type Channel interface {
	Send(ctx context.Context, notification Notification, notifiable Notifiable) error
	GetName() string
	IsEnabled() bool
	Validate() error
}

// Manager interface defines the contract for the notification manager
type Manager interface {
	Send(ctx context.Context, notification Notification, notifiable Notifiable) error
	SendNow(ctx context.Context, notification Notification, notifiable Notifiable) error
	SendToMany(ctx context.Context, notification Notification, notifiables []Notifiable) error
	SendToManyNow(ctx context.Context, notification Notification, notifiables []Notifiable) error
	GetChannel(name string) (Channel, error)
	GetChannels() map[string]Channel
	IsChannelEnabled(name string) bool
	ValidateChannel(name string) error
}
