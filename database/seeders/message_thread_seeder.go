package seeders

import (
	"fmt"
	"time"

	"goravel/app/models"

	"github.com/goravel/framework/facades"
)

type MessageThreadSeeder struct {
}

// Signature The unique signature for the migration.
func (s *MessageThreadSeeder) Signature() string {
	return "message_thread_seeder"
}

// Run executes the seeder logic.
func (s *MessageThreadSeeder) Run() error {
	facades.Log().Info(fmt.Sprintf("%s started", s.Signature()))
	defer facades.Log().Info(fmt.Sprintf("%s completed", s.Signature()))
	// Get some existing chat rooms and messages for testing
	var chatRooms []models.ChatRoom
	err := facades.Orm().Query().Limit(5).Find(&chatRooms)
	if err != nil {
		return err
	}

	if len(chatRooms) == 0 {
		facades.Log().Info("No chat rooms found for thread seeding")
		return nil
	}

	var messages []models.ChatMessage
	err = facades.Orm().Query().Limit(10).Find(&messages)
	if err != nil {
		return err
	}

	if len(messages) == 0 {
		facades.Log().Info("No messages found for thread seeding")
		return nil
	}

	// Create some sample threads
	threads := []models.MessageThread{
		{
			ChatRoomID:    chatRooms[0].ID,
			RootMessageID: messages[0].ID,
			Title:         "Bug Discussion",
			MessageCount:  3,
			LastActivityAt: func() *time.Time {
				t := time.Now().Add(-2 * time.Hour)
				return &t
			}(),
			IsResolved: false,
		},
		{
			ChatRoomID:    chatRooms[0].ID,
			RootMessageID: messages[1].ID,
			Title:         "Feature Request",
			MessageCount:  5,
			LastActivityAt: func() *time.Time {
				t := time.Now().Add(-1 * time.Hour)
				return &t
			}(),
			IsResolved: false,
		},
		{
			ChatRoomID:    chatRooms[1].ID,
			RootMessageID: messages[2].ID,
			Title:         "General Discussion",
			MessageCount:  2,
			LastActivityAt: func() *time.Time {
				t := time.Now().Add(-30 * time.Minute)
				return &t
			}(),
			IsResolved: true,
			ResolvedBy: func() *string {
				s := "01HXYZ123456789ABCDEFGHIJK" // Example user ID
				return &s
			}(),
			ResolvedAt: func() *time.Time {
				t := time.Now().Add(-15 * time.Minute)
				return &t
			}(),
		},
	}

	for _, thread := range threads {
		err := facades.Orm().Query().Create(&thread)
		if err != nil {
			facades.Log().Error("Failed to create thread", map[string]interface{}{
				"error": err.Error(),
				"title": thread.Title,
			})
		}
	}

	facades.Log().Info("Message thread seeder completed", map[string]interface{}{
		"threads_created": len(threads),
	})

	return nil
}
