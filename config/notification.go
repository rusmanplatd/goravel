package config

import "github.com/goravel/framework/facades"

func init() {
	config := facades.Config()
	config.Add("notification", map[string]any{
		// Default Notification Driver
		//
		// This option controls the default notification driver that is used to send
		// notifications when a driver is not explicitly specified.
		"default": config.Env("NOTIFICATION_DRIVER", "database"),

		// Notification Channel Configurations
		//
		// Here you may configure all of the notification channels used by your application
		// plus their respective settings. Several examples have been configured for
		// you and you are free to add your own as your application requires.
		"channels": map[string]any{
			"database": map[string]any{
				"driver": "database",
				"table":  "notifications",
			},
			"mail": map[string]any{
				"driver": "mail",
				"mailer": config.Env("NOTIFICATION_MAIL_MAILER", "smtp"),
			},
			"broadcast": map[string]any{
				"driver":     "broadcast",
				"connection": config.Env("NOTIFICATION_BROADCAST_CONNECTION", "pusher"),
			},
			"slack": map[string]any{
				"driver":      "slack",
				"webhook_url": config.Env("NOTIFICATION_SLACK_WEBHOOK_URL"),
				"channel":     config.Env("NOTIFICATION_SLACK_CHANNEL", "#general"),
				"username":    config.Env("NOTIFICATION_SLACK_USERNAME", "Goravel Bot"),
				"icon":        config.Env("NOTIFICATION_SLACK_ICON", ":robot_face:"),
			},
			"discord": map[string]any{
				"driver":      "discord",
				"webhook_url": config.Env("NOTIFICATION_DISCORD_WEBHOOK_URL"),
				"username":    config.Env("NOTIFICATION_DISCORD_USERNAME", "Goravel Bot"),
				"avatar_url":  config.Env("NOTIFICATION_DISCORD_AVATAR_URL"),
			},
			"telegram": map[string]any{
				"driver":    "telegram",
				"bot_token": config.Env("NOTIFICATION_TELEGRAM_BOT_TOKEN"),
				"chat_id":   config.Env("NOTIFICATION_TELEGRAM_CHAT_ID"),
			},
			"sms": map[string]any{
				"driver":   "sms",
				"provider": config.Env("NOTIFICATION_SMS_PROVIDER", "twilio"),
				"twilio": map[string]any{
					"account_sid": config.Env("NOTIFICATION_SMS_TWILIO_ACCOUNT_SID"),
					"auth_token":  config.Env("NOTIFICATION_SMS_TWILIO_AUTH_TOKEN"),
					"from_number": config.Env("NOTIFICATION_SMS_TWILIO_FROM_NUMBER"),
				},
			},
			"push": map[string]any{
				"driver":   "push",
				"provider": config.Env("NOTIFICATION_PUSH_PROVIDER", "firebase"),
				"firebase": map[string]any{
					"credentials_file": config.Env("NOTIFICATION_PUSH_FIREBASE_CREDENTIALS_FILE"),
					"project_id":       config.Env("NOTIFICATION_PUSH_FIREBASE_PROJECT_ID"),
				},
			},
			"webhook": map[string]any{
				"driver": "webhook",
				"url":    config.Env("NOTIFICATION_WEBHOOK_URL"),
				"method": config.Env("NOTIFICATION_WEBHOOK_METHOD", "POST"),
				"headers": map[string]any{
					"Content-Type": "application/json",
					"User-Agent":   "Goravel-Notification/1.0",
				},
			},
			"log": map[string]any{
				"driver":  "log",
				"channel": config.Env("NOTIFICATION_LOG_CHANNEL", "notification"),
			},
			"web_push": map[string]any{
				"enabled": config.Env("NOTIFICATION_WEB_PUSH_ENABLED", true),
				"vapid": map[string]any{
					"public_key":  config.Env("NOTIFICATION_WEB_PUSH_VAPID_PUBLIC_KEY", ""),
					"private_key": config.Env("NOTIFICATION_WEB_PUSH_VAPID_PRIVATE_KEY", ""),
					"subject":     config.Env("NOTIFICATION_WEB_PUSH_VAPID_SUBJECT", ""),
				},
			},
			"websocket": map[string]any{
				"enabled": config.Env("NOTIFICATION_WEBSOCKET_ENABLED", true),
			},
		},

		// Notification Queue Settings
		//
		// You may configure queue settings for notifications that should be queued.
		"queue": map[string]any{
			"enabled":    config.Env("NOTIFICATION_QUEUE_ENABLED", false),
			"connection": config.Env("NOTIFICATION_QUEUE_CONNECTION", "default"),
			"queue":      config.Env("NOTIFICATION_QUEUE_NAME", "notifications"),
			"delay":      config.Env("NOTIFICATION_QUEUE_DELAY", 0),
		},

		// Notification Rate Limiting
		//
		// You may configure rate limiting for notifications to prevent spam.
		"rate_limiting": map[string]any{
			"enabled":        config.Env("NOTIFICATION_RATE_LIMITING_ENABLED", false),
			"max_per_minute": config.Env("NOTIFICATION_RATE_LIMITING_MAX_PER_MINUTE", 60),
			"max_per_hour":   config.Env("NOTIFICATION_RATE_LIMITING_MAX_PER_HOUR", 1000),
		},

		// Notification Templates
		//
		// You may configure default templates for different notification types.
		"templates": map[string]any{
			"path": "resources/views/notifications",
			"defaults": map[string]any{
				"layout": "layouts/notification",
			},
		},
	})
}
