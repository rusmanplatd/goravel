package config

import (
	"github.com/goravel/framework/facades"
)

func init() {
	config := facades.Config()
	config.Add("livekit", map[string]interface{}{
		// LiveKit Server Configuration
		"server": map[string]interface{}{
			// LiveKit server URL (e.g., wss://your-livekit-server.com)
			"url": config.Env("LIVEKIT_URL", "ws://localhost:7880"),

			// API Key for server authentication
			"api_key": config.Env("LIVEKIT_API_KEY", ""),

			// API Secret for server authentication
			"api_secret": config.Env("LIVEKIT_API_SECRET", ""),
		},

		// Room Configuration
		"room": map[string]interface{}{
			// Default room settings
			"empty_timeout":    config.Env("LIVEKIT_EMPTY_TIMEOUT", 300), // 5 minutes
			"max_participants": config.Env("LIVEKIT_MAX_PARTICIPANTS", 100),

			// Room creation settings
			"auto_create":           config.Env("LIVEKIT_AUTO_CREATE_ROOMS", true),
			"cleanup_after_meeting": config.Env("LIVEKIT_CLEANUP_ROOMS", true),
		},

		// Participant Configuration
		"participant": map[string]interface{}{
			// Default permissions for participants
			"can_publish":         true,
			"can_subscribe":       true,
			"can_publish_data":    true,
			"can_update_metadata": true,

			// Audio/Video settings
			"auto_subscribe":  true,
			"adaptive_stream": true,

			// Recording consent
			"recording_consent_required": config.Env("LIVEKIT_RECORDING_CONSENT", true),
		},

		// Recording Configuration
		"recording": map[string]interface{}{
			// Enable cloud recording
			"enabled": config.Env("LIVEKIT_RECORDING_ENABLED", false),

			// Recording templates
			"templates": map[string]interface{}{
				"default": map[string]interface{}{
					"layout":     "grid",
					"audio_only": false,
					"video_only": false,
					"preset":     "HD_30",
				},
				"audio_only": map[string]interface{}{
					"layout":     "speaker",
					"audio_only": true,
					"video_only": false,
					"preset":     "TELEPHONE",
				},
			},

			// Storage configuration
			"storage": map[string]interface{}{
				"type":       config.Env("LIVEKIT_STORAGE_TYPE", "s3"), // s3, gcp, azure
				"bucket":     config.Env("LIVEKIT_STORAGE_BUCKET", ""),
				"region":     config.Env("LIVEKIT_STORAGE_REGION", ""),
				"access_key": config.Env("LIVEKIT_STORAGE_ACCESS_KEY", ""),
				"secret_key": config.Env("LIVEKIT_STORAGE_SECRET_KEY", ""),
			},

			// Recording output formats
			"outputs": []string{"mp4", "mp3"}, // mp4 for video, mp3 for audio-only
		},

		// Ingress Configuration (for streaming/broadcasting)
		"ingress": map[string]interface{}{
			"enabled":       config.Env("LIVEKIT_INGRESS_ENABLED", false),
			"rtmp_base_url": config.Env("LIVEKIT_RTMP_BASE_URL", ""),
		},

		// Egress Configuration (for streaming out)
		"egress": map[string]interface{}{
			"enabled": config.Env("LIVEKIT_EGRESS_ENABLED", false),
		},

		// Webhook Configuration
		"webhooks": map[string]interface{}{
			"enabled":  config.Env("LIVEKIT_WEBHOOKS_ENABLED", true),
			"endpoint": config.Env("LIVEKIT_WEBHOOK_ENDPOINT", "/api/v1/livekit/webhooks"),
			"secret":   config.Env("LIVEKIT_WEBHOOK_SECRET", ""),

			// Events to listen for
			"events": []string{
				"room_started",
				"room_finished",
				"participant_joined",
				"participant_left",
				"track_published",
				"track_unpublished",
				"recording_started",
				"recording_finished",
			},
		},

		// Quality and Performance Settings
		"quality": map[string]interface{}{
			// Video quality presets
			"video_presets": map[string]interface{}{
				"low": map[string]interface{}{
					"width":     320,
					"height":    240,
					"framerate": 15,
					"bitrate":   200000, // 200 kbps
				},
				"medium": map[string]interface{}{
					"width":     640,
					"height":    480,
					"framerate": 24,
					"bitrate":   500000, // 500 kbps
				},
				"high": map[string]interface{}{
					"width":     1280,
					"height":    720,
					"framerate": 30,
					"bitrate":   1500000, // 1.5 Mbps
				},
				"ultra": map[string]interface{}{
					"width":     1920,
					"height":    1080,
					"framerate": 30,
					"bitrate":   3000000, // 3 Mbps
				},
			},

			// Audio quality settings
			"audio_presets": map[string]interface{}{
				"telephone": map[string]interface{}{
					"bitrate":     16000,
					"sample_rate": 16000,
				},
				"music": map[string]interface{}{
					"bitrate":     128000,
					"sample_rate": 48000,
				},
			},

			// Adaptive streaming
			"adaptive_stream": config.Env("LIVEKIT_ADAPTIVE_STREAM", true),
			"simulcast":       config.Env("LIVEKIT_SIMULCAST", true),
		},

		// Security Settings
		"security": map[string]interface{}{
			// Token expiration (in seconds)
			"token_ttl": config.Env("LIVEKIT_TOKEN_TTL", 3600), // 1 hour

			// Room access control
			"require_token":      config.Env("LIVEKIT_REQUIRE_TOKEN", true),
			"validate_room_join": config.Env("LIVEKIT_VALIDATE_ROOM_JOIN", true),

			// Rate limiting
			"rate_limit": map[string]interface{}{
				"enabled":             config.Env("LIVEKIT_RATE_LIMIT", true),
				"requests_per_minute": config.Env("LIVEKIT_RATE_LIMIT_RPM", 100),
			},
		},

		// Analytics and Monitoring
		"analytics": map[string]interface{}{
			"enabled": config.Env("LIVEKIT_ANALYTICS_ENABLED", true),

			// Metrics to collect
			"metrics": []string{
				"participant_count",
				"room_duration",
				"audio_quality",
				"video_quality",
				"network_quality",
				"cpu_usage",
				"memory_usage",
			},

			// Export to external services
			"export": map[string]interface{}{
				"prometheus": config.Env("LIVEKIT_PROMETHEUS_ENABLED", false),
				"datadog":    config.Env("LIVEKIT_DATADOG_ENABLED", false),
			},
		},

		// Development and Testing
		"development": map[string]interface{}{
			"debug":     config.Env("LIVEKIT_DEBUG", false),
			"log_level": config.Env("LIVEKIT_LOG_LEVEL", "info"),

			// Test room settings
			"test_rooms":        config.Env("LIVEKIT_TEST_ROOMS", false),
			"mock_participants": config.Env("LIVEKIT_MOCK_PARTICIPANTS", false),
		},

		// Feature Flags
		"features": map[string]interface{}{
			"screen_share":       config.Env("LIVEKIT_SCREEN_SHARE", true),
			"recording":          config.Env("LIVEKIT_RECORDING_FEATURE", true),
			"transcription":      config.Env("LIVEKIT_TRANSCRIPTION", false),
			"noise_cancellation": config.Env("LIVEKIT_NOISE_CANCELLATION", true),
			"virtual_background": config.Env("LIVEKIT_VIRTUAL_BACKGROUND", false),
			"breakout_rooms":     config.Env("LIVEKIT_BREAKOUT_ROOMS", true),
		},
	})
}
