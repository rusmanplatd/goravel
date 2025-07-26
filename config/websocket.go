package config

import "github.com/goravel/framework/facades"

func init() {
	config := facades.Config()
	config.Add("websocket", map[string]any{
		// WebSocket Server Configuration
		"enabled": config.Env("WEBSOCKET_ENABLED", true),

		// Connection Settings
		"connection": map[string]any{
			// Maximum message size in bytes (default: 512 bytes)
			"max_message_size": config.Env("WEBSOCKET_MAX_MESSAGE_SIZE", 512),

			// Read timeout in seconds (default: 60 seconds)
			"read_timeout": config.Env("WEBSOCKET_READ_TIMEOUT", 60),

			// Write timeout in seconds (default: 10 seconds)
			"write_timeout": config.Env("WEBSOCKET_WRITE_TIMEOUT", 10),

			// Ping interval in seconds (default: 54 seconds)
			"ping_interval": config.Env("WEBSOCKET_PING_INTERVAL", 54),

			// Maximum connections per user (0 = unlimited)
			"max_connections_per_user": config.Env("WEBSOCKET_MAX_CONNECTIONS_PER_USER", 5),

			// Maximum total connections
			"max_total": config.Env("WEBSOCKET_MAX_TOTAL_CONNECTIONS", 10000),

			// Buffer size for send channel
			"send_buffer_size": config.Env("WEBSOCKET_SEND_BUFFER_SIZE", 256),

			// Read buffer size for WebSocket upgrader
			"read_buffer_size": config.Env("WEBSOCKET_READ_BUFFER_SIZE", 1024),

			// Write buffer size for WebSocket upgrader
			"write_buffer_size": config.Env("WEBSOCKET_WRITE_BUFFER_SIZE", 1024),

			// Enable compression
			"enable_compression": config.Env("WEBSOCKET_ENABLE_COMPRESSION", true),

			// Handshake timeout in seconds
			"handshake_timeout": config.Env("WEBSOCKET_HANDSHAKE_TIMEOUT", 10),
		},

		// Authentication Settings
		"auth": map[string]any{
			// Require authentication for websocket connections
			"required": config.Env("WEBSOCKET_AUTH_REQUIRED", true),

			// Authentication timeout in seconds
			"timeout": config.Env("WEBSOCKET_AUTH_TIMEOUT", 30),

			// JWT token validation
			"jwt_validation": config.Env("WEBSOCKET_JWT_VALIDATION", true),
		},

		// Rate Limiting
		"rate_limit": map[string]any{
			// Enable rate limiting
			"enabled": config.Env("WEBSOCKET_RATE_LIMIT_ENABLED", true),

			// Messages per minute per connection
			"messages_per_minute": config.Env("WEBSOCKET_RATE_LIMIT_MESSAGES", 60),

			// Burst limit
			"burst_limit": config.Env("WEBSOCKET_RATE_LIMIT_BURST", 10),

			// Rate limit window in seconds
			"window_seconds": config.Env("WEBSOCKET_RATE_LIMIT_WINDOW", 60),
		},

		// CORS Settings
		"cors": map[string]any{
			// Allowed origins for websocket connections
			"allowed_origins": []string{
				config.Env("APP_URL", "http://localhost").(string),
				"http://localhost:3000",
				"http://localhost:8080",
			},

			// Check origin function (strict = true, permissive = false)
			"check_origin": config.Env("WEBSOCKET_CHECK_ORIGIN", true),
		},

		// Message Types Configuration
		"message_types": map[string]any{
			// Allowed message types
			"allowed": []string{
				"ping",
				"pong",
				"subscribe",
				"unsubscribe",
				"notification",
				"chat_message",
				"user_status",
				"typing",
				"custom",
			},

			// Maximum payload size per message type (in bytes)
			"max_payload_size": map[string]int{
				"ping":         50,
				"pong":         50,
				"subscribe":    200,
				"unsubscribe":  200,
				"notification": 1024,
				"chat_message": 2048,
				"user_status":  100,
				"typing":       100,
				"custom":       512,
			},
		},

		// Broadcasting Configuration
		"broadcast": map[string]any{
			// Enable broadcasting to multiple connections
			"enabled": config.Env("WEBSOCKET_BROADCAST_ENABLED", true),

			// Broadcast channels
			"channels": map[string]any{
				// User-specific channels
				"user_notifications": config.Env("WEBSOCKET_USER_NOTIFICATIONS", true),
				"user_chat":          config.Env("WEBSOCKET_USER_CHAT", true),
				"user_status":        config.Env("WEBSOCKET_USER_STATUS", true),

				// Global channels
				"global_announcements": config.Env("WEBSOCKET_GLOBAL_ANNOUNCEMENTS", true),
				"system_status":        config.Env("WEBSOCKET_SYSTEM_STATUS", true),
			},

			// Channel permissions
			"channel_permissions": map[string]any{
				"require_auth": config.Env("WEBSOCKET_CHANNEL_AUTH_REQUIRED", true),
				"role_based":   config.Env("WEBSOCKET_ROLE_BASED_CHANNELS", false),
			},
		},

		// Monitoring and Logging
		"monitoring": map[string]any{
			// Enable connection monitoring
			"enabled": config.Env("WEBSOCKET_MONITORING_ENABLED", true),

			// Log connection events
			"log_connections": config.Env("WEBSOCKET_LOG_CONNECTIONS", true),

			// Log message events
			"log_messages": config.Env("WEBSOCKET_LOG_MESSAGES", false),

			// Connection statistics interval in seconds
			"stats_interval": config.Env("WEBSOCKET_STATS_INTERVAL", 300),

			// Enable performance metrics
			"metrics": config.Env("WEBSOCKET_METRICS_ENABLED", true),
		},

		// Security Settings
		"security": map[string]any{
			// Enable message validation
			"message_validation": config.Env("WEBSOCKET_MESSAGE_VALIDATION", true),

			// Enable connection throttling
			"connection_throttling": config.Env("WEBSOCKET_CONNECTION_THROTTLING", true),

			// Maximum connections per IP
			"max_connections_per_ip": config.Env("WEBSOCKET_MAX_CONNECTIONS_PER_IP", 10),

			// Enable anti-spam protection
			"anti_spam": config.Env("WEBSOCKET_ANTI_SPAM", true),

			// Spam detection threshold (messages per second)
			"spam_threshold": config.Env("WEBSOCKET_SPAM_THRESHOLD", 5),
		},

		// Cleanup and Maintenance
		"cleanup": map[string]any{
			// Enable automatic cleanup of stale connections
			"enabled": config.Env("WEBSOCKET_CLEANUP_ENABLED", true),

			// Cleanup interval in seconds
			"interval": config.Env("WEBSOCKET_CLEANUP_INTERVAL", 300),

			// Connection idle timeout in seconds
			"idle_timeout": config.Env("WEBSOCKET_IDLE_TIMEOUT", 3600),
		},

		// Development Settings
		"development": map[string]any{
			// Enable debug mode
			"debug": config.Env("WEBSOCKET_DEBUG", config.Env("APP_DEBUG", false)),

			// Enable test endpoints
			"test_endpoints": config.Env("WEBSOCKET_TEST_ENDPOINTS", config.Env("APP_DEBUG", false)),

			// Mock mode for testing
			"mock_mode": config.Env("WEBSOCKET_MOCK_MODE", false),
		},
	})
}
