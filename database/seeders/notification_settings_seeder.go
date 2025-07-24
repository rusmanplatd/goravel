package seeders

import (
	"encoding/json"
	"fmt"
	"time"

	"goravel/app/models"

	"github.com/goravel/framework/facades"
)

type NotificationSettingsSeeder struct {
}

// Signature The unique signature for the migration.
func (s *NotificationSettingsSeeder) Signature() string {
	return "notification_settings_seeder"
}

// Run executes the seeder logic.
func (s *NotificationSettingsSeeder) Run() error {
	facades.Log().Info(fmt.Sprintf("%s started", s.Signature()))
	defer facades.Log().Info(fmt.Sprintf("%s completed", s.Signature()))
	// Get some existing users and chat rooms for testing
	var users []models.User
	err := facades.Orm().Query().Limit(5).Find(&users)
	if err != nil {
		return err
	}

	if len(users) == 0 {
		facades.Log().Info("No users found for notification settings seeding")
		return nil
	}

	var chatRooms []models.ChatRoom
	err = facades.Orm().Query().Limit(3).Find(&chatRooms)
	if err != nil {
		return err
	}

	// Create global notification settings for each user
	for _, user := range users {
		globalSettings := models.ChatNotificationSettings{
			UserID:                user.ID,
			EmailNotifications:    true,
			PushNotifications:     true,
			DesktopNotifications:  true,
			MentionNotifications:  true,
			ReactionNotifications: true,
			ThreadNotifications:   true,
			IsMuted:               false,
			CustomSettings:        "",
		}

		// Add some custom settings for variety
		customSettings := map[string]interface{}{
			"sound":     "default",
			"vibration": true,
			"badge":     true,
			"quiet_hours": map[string]interface{}{
				"enabled": false,
				"start":   "22:00",
				"end":     "08:00",
			},
		}

		customSettingsJSON, _ := json.Marshal(customSettings)
		globalSettings.CustomSettings = string(customSettingsJSON)

		err := facades.Orm().Query().Create(&globalSettings)
		if err != nil {
			facades.Log().Error("Failed to create global notification settings", map[string]interface{}{
				"error":   err.Error(),
				"user_id": user.ID,
			})
		}
	}

	// Create room-specific notification settings
	if len(chatRooms) > 0 {
		for i, user := range users {
			if i >= len(chatRooms) {
				break
			}

			roomSettings := models.ChatNotificationSettings{
				UserID:                user.ID,
				ChatRoomID:            &chatRooms[i].ID,
				EmailNotifications:    true,
				PushNotifications:     true,
				DesktopNotifications:  true,
				MentionNotifications:  true,
				ReactionNotifications: true,
				ThreadNotifications:   true,
				IsMuted:               false,
				CustomSettings:        "",
			}

			// Add some variety to room settings
			if i == 0 {
				roomSettings.IsMuted = true
				muteUntil := time.Now().Add(24 * time.Hour)
				roomSettings.MuteUntil = &muteUntil
			} else if i == 1 {
				roomSettings.EmailNotifications = false
				roomSettings.PushNotifications = false
			}

			err := facades.Orm().Query().Create(&roomSettings)
			if err != nil {
				facades.Log().Error("Failed to create room notification settings", map[string]interface{}{
					"error":   err.Error(),
					"user_id": user.ID,
					"room_id": chatRooms[i].ID,
				})
			}
		}
	}

	facades.Log().Info("Notification settings seeder completed", map[string]interface{}{
		"users_processed": len(users),
		"rooms_processed": len(chatRooms),
	})

	return nil
}
