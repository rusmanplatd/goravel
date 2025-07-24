package seeders

import (
	"time"

	"goravel/app/models"
	"goravel/app/services"

	"github.com/goravel/framework/facades"
)

type ChatSeeder struct {
}

// Signature The unique signature for the seeder.
func (s *ChatSeeder) Signature() string {
	return "ChatSeeder"
}

// Run executes the seeder.
func (s *ChatSeeder) Run() error {
	facades.Log().Info("Running ChatSeeder...")

	// Get or create a tenant
	var tenant models.Tenant
	err := facades.Orm().Query().Where("slug", "default").First(&tenant)
	if err != nil {
		// Create default tenant if it doesn't exist
		tenant = models.Tenant{
			Name:        "Default Tenant",
			Slug:        "default",
			Domain:      "localhost",
			Description: "Default tenant for chat system",
			IsActive:    true,
		}
		err = facades.Orm().Query().Create(&tenant)
		if err != nil {
			return err
		}
	}

	// Get some users for testing
	var users []models.User
	err = facades.Orm().Query().Limit(5).Find(&users)
	if err != nil {
		return err
	}

	if len(users) < 2 {
		facades.Log().Info("Not enough users found, skipping chat seeding")
		return nil
	}

	// Generate encryption keys for users
	e2eeService := services.NewE2EEService()
	for i := range users {
		// Generate identity key for each user
		keyPair, err := e2eeService.GenerateKeyPair()
		if err != nil {
			facades.Log().Error("Failed to generate key pair for user", map[string]interface{}{
				"user_id": users[i].ID,
				"error":   err.Error(),
			})
			continue
		}

		// Save user key
		userKey := &models.UserKey{
			UserID:              users[i].ID,
			KeyType:             "identity",
			PublicKey:           keyPair.PublicKey,
			EncryptedPrivateKey: keyPair.PrivateKey, // In production, this should be encrypted
			Version:             1,
			IsActive:            true,
		}

		err = e2eeService.SaveUserKey(userKey)
		if err != nil {
			facades.Log().Error("Failed to save user key", map[string]interface{}{
				"user_id": users[i].ID,
				"error":   err.Error(),
			})
		}
	}

	// Create some chat rooms
	chatRooms := []models.ChatRoom{
		{
			Name:        "General Discussion",
			Description: "Main discussion channel for the team",
			Type:        "group",
			IsActive:    true,
			TenantID:    tenant.ID,
			BaseModel: models.BaseModel{
				CreatedBy: &users[0].ID,
			},
		},
		{
			Name:        "Direct Chat",
			Description: "Direct conversation between users",
			Type:        "direct",
			IsActive:    true,
			TenantID:    tenant.ID,
			BaseModel: models.BaseModel{
				CreatedBy: &users[0].ID,
			},
		},
		{
			Name:        "Project Updates",
			Description: "Channel for project updates and announcements",
			Type:        "channel",
			IsActive:    true,
			TenantID:    tenant.ID,
			BaseModel: models.BaseModel{
				CreatedBy: &users[1].ID,
			},
		},
	}

	for i := range chatRooms {
		err = facades.Orm().Query().Create(&chatRooms[i])
		if err != nil {
			facades.Log().Error("Failed to create chat room", map[string]interface{}{
				"room_name": chatRooms[i].Name,
				"error":     err.Error(),
			})
			continue
		}

		// Add members to the room
		memberIDs := []string{}
		if chatRooms[i].Type == "direct" {
			// For direct chat, add only 2 users
			if len(users) >= 2 {
				memberIDs = []string{users[0].ID, users[1].ID}
			}
		} else {
			// For group/channel, add all users
			for _, user := range users {
				memberIDs = append(memberIDs, user.ID)
			}
		}

		// Create room members
		for j, memberID := range memberIDs {
			role := "member"
			if j == 0 {
				role = "admin" // First member is admin
			}

			member := &models.ChatRoomMember{
				ChatRoomID: chatRooms[i].ID,
				UserID:     memberID,
				Role:       role,
				IsActive:   true,
				JoinedAt:   time.Now(),
			}

			// Get user's public key
			var userKey models.UserKey
			err = facades.Orm().Query().Where("user_id", memberID).Where("key_type", "identity").Where("is_active", true).First(&userKey)
			if err == nil {
				member.PublicKey = userKey.PublicKey
			}

			err = facades.Orm().Query().Create(member)
			if err != nil {
				facades.Log().Error("Failed to create room member", map[string]interface{}{
					"room_id": chatRooms[i].ID,
					"user_id": memberID,
					"error":   err.Error(),
				})
			}
		}

		// Generate room key for E2EE
		chatService := services.NewChatService()
		err = chatService.GenerateRoomKey(chatRooms[i].ID)
		if err != nil {
			facades.Log().Error("Failed to generate room key", map[string]interface{}{
				"room_id": chatRooms[i].ID,
				"error":   err.Error(),
			})
		}
	}

	// Create some sample messages
	if len(chatRooms) > 0 {
		sampleMessages := []struct {
			RoomID   string
			SenderID string
			Content  string
			Type     string
		}{
			{
				RoomID:   chatRooms[0].ID,
				SenderID: users[0].ID,
				Content:  "Welcome to the General Discussion channel!",
				Type:     "text",
			},
			{
				RoomID:   chatRooms[0].ID,
				SenderID: users[1].ID,
				Content:  "Thanks! Looking forward to collaborating with everyone.",
				Type:     "text",
			},
			{
				RoomID:   chatRooms[2].ID,
				SenderID: users[1].ID,
				Content:  "Project Alpha milestone 1 completed successfully.",
				Type:     "text",
			},
		}

		for _, msg := range sampleMessages {
			// Encrypt the message content
			encryptedContent := "encrypted_" + msg.Content // Simplified for seeding

			message := &models.ChatMessage{
				ChatRoomID:        msg.RoomID,
				SenderID:          msg.SenderID,
				Type:              msg.Type,
				EncryptedContent:  encryptedContent,
				Status:            "sent",
				EncryptionVersion: 1,
			}

			err = facades.Orm().Query().Create(message)
			if err != nil {
				facades.Log().Error("Failed to create message", map[string]interface{}{
					"room_id": msg.RoomID,
					"error":   err.Error(),
				})
			}
		}
	}

	facades.Log().Info("ChatSeeder completed successfully")
	return nil
}
