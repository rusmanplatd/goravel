# Notification System

A comprehensive notification system for Goravel, similar to Laravel's notification system with support for multiple channels.

## Features

- **Multiple Channels**: Database, Email, Slack, Discord, Telegram, SMS, Push, Webhook, and Log
- **Queue Support**: Notifications can be queued for background processing
- **Rate Limiting**: Configurable rate limiting to prevent spam
- **Retry Logic**: Automatic retry for failed notifications
- **Template Support**: Customizable email templates
- **Notifiable Interface**: Easy integration with any entity
- **Channel Validation**: Built-in channel configuration validation

## Architecture

### Core Components

1. **Notification Interface**: Defines the contract for notification classes
2. **Notifiable Interface**: Defines the contract for entities that can receive notifications
3. **Channel Interface**: Defines the contract for notification channels
4. **Notification Service**: Main service for sending notifications
5. **Base Notification**: Provides default implementations for common methods

### Database Schema

The notification system uses a single `notifications` table:

```sql
CREATE TABLE notifications (
    id VARCHAR(26) PRIMARY KEY,
    type VARCHAR(255) NOT NULL,
    data JSON,
    notifiable_id VARCHAR(26) NOT NULL,
    notifiable_type VARCHAR(255) NOT NULL,
    channel VARCHAR(255) DEFAULT 'database',
    read_at TIMESTAMP NULL,
    sent_at TIMESTAMP NULL,
    failed_at TIMESTAMP NULL,
    failure_reason TEXT NULL,
    created_at TIMESTAMP NOT NULL,
    updated_at TIMESTAMP NOT NULL,
    deleted_at TIMESTAMP NULL
);
```

## Configuration

### Notification Configuration

The notification system is configured in `config/notification.go`:

```go
// Environment variables for configuration
NOTIFICATION_DRIVER=database
NOTIFICATION_QUEUE_ENABLED=false
NOTIFICATION_QUEUE_CONNECTION=default
NOTIFICATION_QUEUE_NAME=notifications
NOTIFICATION_QUEUE_DELAY=0

// Channel-specific configurations
NOTIFICATION_MAIL_MAILER=smtp
NOTIFICATION_SLACK_WEBHOOK_URL=
NOTIFICATION_DISCORD_WEBHOOK_URL=
NOTIFICATION_TELEGRAM_BOT_TOKEN=
NOTIFICATION_SMS_PROVIDER=twilio
NOTIFICATION_PUSH_PROVIDER=firebase
```

## Usage

### Creating Notifications

Create a notification by extending the `BaseNotification`:

```go
package notifications

import "time"

type WelcomeNotification struct {
    *BaseNotification
    userName string
}

func NewWelcomeNotification(userName string) *WelcomeNotification {
    notification := &WelcomeNotification{
        BaseNotification: NewBaseNotification(),
        userName:         userName,
    }

    // Set notification properties
    notification.SetType("WelcomeNotification")
    notification.SetTitle("Welcome to " + getAppName())
    notification.SetBody("Hi " + userName + ", welcome to our platform!")
    notification.SetSubject("Welcome to " + getAppName())
    notification.SetChannels([]string{"database", "mail"})
    notification.SetActionURL(getAppURL() + "/dashboard")
    notification.SetActionText("Go to Dashboard")
    notification.SetIcon("🎉")
    notification.SetColor("success")
    notification.SetPriority("normal")
    notification.SetCategory("welcome")
    notification.AddTag("welcome")
    notification.AddTag("new-user")

    // Add custom data
    notification.AddData("user_name", userName)
    notification.AddData("welcome_date", time.Now().Format("2006-01-02"))

    return notification
}
```

### Making Entities Notifiable

Implement the `Notifiable` interface for any entity that should receive notifications:

```go
// In your User model
func (u *User) GetID() string {
    return u.ID
}

func (u *User) GetType() string {
    return "User"
}

func (u *User) GetEmail() string {
    return u.Email
}

func (u *User) GetPreferredChannels() []string {
    if len(u.PreferredNotificationChannels) > 0 {
        return u.PreferredNotificationChannels
    }
    return []string{"database", "mail"}
}

func (u *User) ShouldReceiveNotification(notification interface{}) bool {
    // Check if user is active
    if !u.IsActive {
        return false
    }

    // Check if user is locked
    if u.LockedAt != nil && u.LockedUntil != nil && time.Now().Before(*u.LockedUntil) {
        return false
    }

    return true
}
```

### Sending Notifications

Use the notification service to send notifications:

```go
package main

import (
    "context"
    "goravel/app/notifications"
    "goravel/app/services"
)

func main() {
    // Create notification service
    notificationService := services.NewNotificationService()

    // Create a notification
    notification := notifications.NewWelcomeNotification("John Doe")

    // Create a notifiable user
    user := &models.User{
        ID:    "user_id",
        Name:  "John Doe",
        Email: "john@example.com",
    }

    // Send notification
    ctx := context.Background()
    err := notificationService.Send(ctx, notification, user)
    if err != nil {
        // Handle error
    }
}
```

### Using the Controller

The notification system includes a controller with common operations:

```go
// Send welcome notification
POST /api/v1/notifications/welcome/{user_id}

// Send password reset notification
POST /api/v1/notifications/password-reset
{
    "email": "user@example.com"
}

// Get user notifications
GET /api/v1/notifications/user/{user_id}?limit=10

// Mark notification as read
PUT /api/v1/notifications/{notification_id}/read

// Mark all notifications as read
PUT /api/v1/notifications/user/{user_id}/read-all

// Delete notification
DELETE /api/v1/notifications/{notification_id}
```

## Channels

### Database Channel

Stores notifications in the database for in-app display.

```go
// Configuration
"database": {
    "driver": "database",
    "table": "notifications"
}
```

### Mail Channel

Sends notifications via email with customizable templates.

```go
// Configuration
"mail": {
    "driver": "mail",
    "mailer": "smtp"
}
```

### Slack Channel

Sends notifications to Slack channels via webhooks.

```go
// Configuration
"slack": {
    "driver": "slack",
    "webhook_url": "https://hooks.slack.com/services/...",
    "channel": "#general",
    "username": "Goravel Bot",
    "icon": ":robot_face:"
}
```

### Discord Channel

Sends notifications to Discord channels via webhooks.

```go
// Configuration
"discord": {
    "driver": "discord",
    "webhook_url": "https://discord.com/api/webhooks/...",
    "username": "Goravel Bot",
    "avatar_url": "https://example.com/avatar.png"
}
```

### Telegram Channel

Sends notifications to Telegram chats via bot API.

```go
// Configuration
"telegram": {
    "driver": "telegram",
    "bot_token": "1234567890:ABCdefGHIjklMNOpqrsTUVwxyz",
    "chat_id": "123456789"
}
```

### SMS Channel

Sends notifications via SMS using providers like Twilio.

```go
// Configuration
"sms": {
    "driver": "sms",
    "provider": "twilio",
    "twilio": {
        "account_sid": "AC1234567890abcdef",
        "auth_token": "your_auth_token",
        "from_number": "+1234567890"
    }
}
```

### Push Channel

Sends push notifications using Firebase Cloud Messaging.

```go
// Configuration
"push": {
    "driver": "push",
    "provider": "firebase",
    "firebase": {
        "credentials_file": "/path/to/firebase-credentials.json",
        "project_id": "your-project-id"
    }
}
```

### Webhook Channel

Sends notifications to custom webhook endpoints.

```go
// Configuration
"webhook": {
    "driver": "webhook",
    "url": "https://api.example.com/webhook",
    "method": "POST",
    "headers": {
        "Content-Type": "application/json",
        "User-Agent": "Goravel-Notification/1.0"
    }
}
```

### Log Channel

Logs notifications for debugging purposes.

```go
// Configuration
"log": {
    "driver": "log",
    "channel": "notification"
}
```

## Advanced Features

### Queue Support

Enable queuing for notifications:

```go
// In your notification
notification.SetShouldQueue(true)
notification.SetQueueDelay(5 * time.Minute)
notification.SetQueueConnection("redis")
notification.SetQueueName("notifications")
```

### Rate Limiting

Configure rate limiting to prevent spam:

```go
// In config/notification.go
"rate_limiting": {
    "enabled": true,
    "max_per_minute": 60,
    "max_per_hour": 1000
}
```

### Retry Logic

Configure retry behavior for failed notifications:

```go
// In your notification
notification.SetRetryAfter(5 * time.Minute)
notification.SetMaxRetries(3)
```

### Custom Templates

Create custom email templates:

```html
<!-- resources/views/notifications/welcome.html -->
<!DOCTYPE html>
<html>
<head>
    <title>{{.Title}}</title>
</head>
<body>
    <h1>{{.Title}}</h1>
    <p>{{.Body}}</p>
    {{if .ActionURL}}
    <a href="{{.ActionURL}}">{{.ActionText}}</a>
    {{end}}
</body>
</html>
```

## Migration

Run the migration to create the notifications table:

```bash
go run artisan migrate
```

## Testing

The notification system includes comprehensive tests:

```bash
go test ./tests/feature/notification_test.go
```

## Best Practices

1. **Use Specific Channels**: Only send notifications through channels that make sense for the content
2. **Implement Rate Limiting**: Prevent notification spam
3. **Use Queues**: Queue notifications for better performance
4. **Handle Failures**: Implement proper error handling and retry logic
5. **Customize Templates**: Create beautiful, branded email templates
6. **Monitor Performance**: Track notification delivery rates and failures
7. **Respect User Preferences**: Allow users to choose their preferred channels

## Examples

### Welcome Notification

```go
notification := notifications.NewWelcomeNotification(user.Name)
notificationService.Send(ctx, notification, user)
```

### Password Reset Notification

```go
notification := notifications.NewPasswordResetNotification(user.Email, resetToken)
notificationService.Send(ctx, notification, user)
```

### Custom Notification

```go
type OrderShippedNotification struct {
    *BaseNotification
    orderID string
    trackingNumber string
}

func NewOrderShippedNotification(orderID, trackingNumber string) *OrderShippedNotification {
    notification := &OrderShippedNotification{
        BaseNotification: NewBaseNotification(),
        orderID:         orderID,
        trackingNumber:  trackingNumber,
    }

    notification.SetType("OrderShippedNotification")
    notification.SetTitle("Your order has been shipped!")
    notification.SetBody("Order #" + orderID + " has been shipped with tracking number: " + trackingNumber)
    notification.SetChannels([]string{"mail", "database"})
    notification.SetActionURL("/orders/" + orderID)
    notification.SetActionText("View Order")
    notification.SetIcon("📦")
    notification.SetColor("success")

    return notification
}
```

This notification system provides a robust, flexible foundation for handling all types of notifications in your Goravel application. 