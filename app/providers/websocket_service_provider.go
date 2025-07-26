package providers

import (
	"fmt"
	"time"

	"github.com/goravel/framework/contracts/foundation"
	"github.com/goravel/framework/facades"

	"goravel/app/services"
)

type WebSocketServiceProvider struct{}

func (receiver *WebSocketServiceProvider) Register(app foundation.Application) {
	// Register WebSocket services as singletons
	app.Singleton("websocket.hub", func(app foundation.Application) (any, error) {
		return services.GetWebSocketHub(), nil
	})

	app.Singleton("websocket.events", func(app foundation.Application) (any, error) {
		return services.GetWebSocketEventService(), nil
	})
}

func (receiver *WebSocketServiceProvider) Boot(app foundation.Application) {
	// Check if WebSocket is enabled
	if !facades.Config().GetBool("websocket.enabled", true) {
		facades.Log().Info("WebSocket service is disabled")
		return
	}

	facades.Log().Info("WebSocket service provider booting...")

	// Initialize WebSocket services
	hub := services.GetWebSocketHub()
	eventService := services.GetWebSocketEventService()

	// Register default event handlers
	receiver.registerDefaultEventHandlers(eventService)

	// Start monitoring and cleanup services
	receiver.startMonitoringService(hub, eventService)
	receiver.startCleanupService(hub)

	// Initialize WebSocket notification channel if not already registered
	receiver.initializeNotificationChannel()

	facades.Log().Info("WebSocket service provider booted successfully", map[string]interface{}{
		"hub_initialized":    hub != nil,
		"events_initialized": eventService != nil,
	})
}

// registerDefaultEventHandlers registers default event handlers
func (receiver *WebSocketServiceProvider) registerDefaultEventHandlers(eventService *services.WebSocketEventService) {
	// Register notification event handler
	eventService.RegisterHandler("notification", func(event *services.WebSocketEvent) error {
		facades.Log().Info("Processing notification event", map[string]interface{}{
			"event_id":   event.ID,
			"user_id":    event.UserID,
			"event_type": event.Type,
		})
		return nil
	})

	// Register chat message event handler
	eventService.RegisterHandler("chat_message", func(event *services.WebSocketEvent) error {
		facades.Log().Info("Processing chat message event", map[string]interface{}{
			"event_id": event.ID,
			"user_id":  event.UserID,
			"channel":  event.Channel,
		})
		return nil
	})

	// Register user status event handler
	eventService.RegisterHandler("user_status", func(event *services.WebSocketEvent) error {
		facades.Log().Debug("Processing user status event", map[string]interface{}{
			"event_id": event.ID,
			"user_id":  event.UserID,
			"status":   event.Data["status"],
		})
		return nil
	})

	// Register system event handler
	eventService.RegisterHandler("system", func(event *services.WebSocketEvent) error {
		facades.Log().Info("Processing system event", map[string]interface{}{
			"event_id": event.ID,
			"message":  event.Data["message"],
		})
		return nil
	})

	// Register typing indicator event handler
	eventService.RegisterHandler("typing", func(event *services.WebSocketEvent) error {
		facades.Log().Debug("Processing typing event", map[string]interface{}{
			"event_id": event.ID,
			"user_id":  event.UserID,
		})
		return nil
	})

	// Register custom event handler
	eventService.RegisterHandler("custom", func(event *services.WebSocketEvent) error {
		facades.Log().Info("Processing custom event", map[string]interface{}{
			"event_id":   event.ID,
			"user_id":    event.UserID,
			"event_type": event.Type,
			"data":       event.Data,
		})
		return nil
	})

	facades.Log().Info("Default WebSocket event handlers registered")
}

// startMonitoringService starts the WebSocket monitoring service
func (receiver *WebSocketServiceProvider) startMonitoringService(hub *services.WebSocketHub, eventService *services.WebSocketEventService) {
	if !facades.Config().GetBool("websocket.monitoring.enabled", true) {
		return
	}

	statsInterval := facades.Config().GetInt("websocket.monitoring.stats_interval", 300)

	go func() {
		ticker := time.NewTicker(time.Duration(statsInterval) * time.Second)
		defer ticker.Stop()

		for range ticker.C {
			// Log connection statistics
			if facades.Config().GetBool("websocket.monitoring.log_connections", true) {
				facades.Log().Info("WebSocket connection statistics", map[string]interface{}{
					"total_connections": hub.GetTotalConnections(),
					"connected_users":   hub.GetConnectedUsers(),
				})
			}

			// Log event statistics
			eventStats := eventService.GetStats()
			facades.Log().Info("WebSocket event statistics", map[string]interface{}{
				"total_events":      eventStats.TotalEvents,
				"failed_events":     eventStats.FailedEvents,
				"events_by_type":    eventStats.EventsByType,
				"events_by_channel": eventStats.EventsByChannel,
			})
		}
	}()

	facades.Log().Info("WebSocket monitoring service started", map[string]interface{}{
		"stats_interval": statsInterval,
	})
}

// startCleanupService starts the WebSocket cleanup service
func (receiver *WebSocketServiceProvider) startCleanupService(hub *services.WebSocketHub) {
	if !facades.Config().GetBool("websocket.cleanup.enabled", true) {
		return
	}

	cleanupInterval := facades.Config().GetInt("websocket.cleanup.interval", 300)

	go func() {
		ticker := time.NewTicker(time.Duration(cleanupInterval) * time.Second)
		defer ticker.Stop()

		for range ticker.C {
			// Perform cleanup operations
			receiver.performCleanup(hub)
		}
	}()

	facades.Log().Info("WebSocket cleanup service started", map[string]interface{}{
		"cleanup_interval": cleanupInterval,
	})
}

// performCleanup performs cleanup operations
func (receiver *WebSocketServiceProvider) performCleanup(hub *services.WebSocketHub) {
	// This is a placeholder for cleanup operations
	// In a real implementation, you might:
	// 1. Check for stale connections
	// 2. Clean up expired event data
	// 3. Perform garbage collection
	// 4. Update connection statistics

	facades.Log().Debug("Performing WebSocket cleanup", map[string]interface{}{
		"total_connections": hub.GetTotalConnections(),
		"connected_users":   hub.GetConnectedUsers(),
	})
}

// initializeNotificationChannel initializes the WebSocket notification channel
func (receiver *WebSocketServiceProvider) initializeNotificationChannel() {
	// Check if WebSocket notification channel is enabled
	if !facades.Config().GetBool("notification.channels.websocket.enabled", true) {
		return
	}

	// The WebSocket notification channel should already be registered in notification service
	// This is just to ensure it's properly initialized
	facades.Log().Info("WebSocket notification channel initialized")
}

// Helper methods for WebSocket operations

// BroadcastSystemMessage broadcasts a system message to all connected users
func BroadcastSystemMessage(message string, data map[string]interface{}) error {
	eventService := services.GetWebSocketEventService()
	event := services.CreateSystemEvent("system", message, data)
	return eventService.BroadcastToAll(event)
}

// BroadcastUserNotification broadcasts a notification to a specific user
func BroadcastUserNotification(userID, title, message string, data map[string]interface{}) error {
	eventService := services.GetWebSocketEventService()
	event := services.CreateNotificationEvent(userID, title, message, data)
	return eventService.BroadcastToUser(userID, event)
}

// BroadcastChatMessage broadcasts a chat message to a chat room
func BroadcastChatMessage(userID, roomID, message string, data map[string]interface{}) error {
	eventService := services.GetWebSocketEventService()
	event := services.CreateChatMessageEvent(userID, roomID, message, data)
	return eventService.BroadcastToChannel(fmt.Sprintf("chat_room_%s", roomID), event)
}

// BroadcastUserStatus broadcasts a user status change
func BroadcastUserStatus(userID, status string, data map[string]interface{}) error {
	eventService := services.GetWebSocketEventService()
	event := services.CreateUserStatusEvent(userID, status, data)
	return eventService.BroadcastToUser(userID, event)
}

// GetWebSocketStats returns WebSocket statistics
func GetWebSocketStats() map[string]interface{} {
	hub := services.GetWebSocketHub()
	eventService := services.GetWebSocketEventService()
	eventStats := eventService.GetStats()

	return map[string]interface{}{
		"connections": map[string]interface{}{
			"total_connections": hub.GetTotalConnections(),
			"connected_users":   hub.GetConnectedUsers(),
		},
		"events": map[string]interface{}{
			"total_events":      eventStats.TotalEvents,
			"failed_events":     eventStats.FailedEvents,
			"events_by_type":    eventStats.EventsByType,
			"events_by_channel": eventStats.EventsByChannel,
		},
		"configuration": map[string]interface{}{
			"enabled":                  facades.Config().GetBool("websocket.enabled", true),
			"monitoring_enabled":       facades.Config().GetBool("websocket.monitoring.enabled", true),
			"cleanup_enabled":          facades.Config().GetBool("websocket.cleanup.enabled", true),
			"max_connections_per_user": facades.Config().GetInt("websocket.connection.max_connections_per_user", 5),
			"rate_limit_enabled":       facades.Config().GetBool("websocket.rate_limit.enabled", true),
		},
	}
}
