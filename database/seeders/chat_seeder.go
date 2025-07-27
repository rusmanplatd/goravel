package seeders

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/goravel/framework/facades"

	"goravel/app/models"
	"goravel/app/services"
)

type ChatSeeder struct{}

func (s *ChatSeeder) Signature() string {
	return "ChatSeeder"
}

func (s *ChatSeeder) Run() error {
	facades.Log().Info(fmt.Sprintf("%s started", s.Signature()))
	defer facades.Log().Info(fmt.Sprintf("%s completed", s.Signature()))

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

	// Initialize E2EE service
	e2eeService := services.NewE2EEService()

	// Get existing users to create chat rooms for
	var users []models.User
	err = facades.Orm().Query().Limit(10).Find(&users)
	if err != nil {
		facades.Log().Error("Failed to fetch users for chat seeding", map[string]interface{}{
			"error": err.Error(),
		})
		return err
	}

	if len(users) == 0 {
		facades.Log().Info("No users found, skipping chat seeding")
		return nil
	}

	// Master seed key for encryption (in production, use a proper key management system)
	masterSeedKey := facades.Config().GetString("app.key", "default-seed-key")

	// Generate key pairs for users who don't have them
	for i := range users {
		// Check if user already has an active key pair
		var existingKey models.UserKey
		err := facades.Orm().Query().
			Where("user_id = ? AND is_active = ?", users[i].ID, true).
			First(&existingKey)
		if err == nil {
			// User already has a key pair, skip
			continue
		}

		// Generate new key pair
		keyPair, err := e2eeService.GenerateKeyPair()
		if err != nil {
			facades.Log().Error("Failed to generate key pair for user", map[string]interface{}{
				"user_id": users[i].ID,
				"error":   err.Error(),
			})
			continue
		}

		// Create a secure passphrase for this user's private key
		// In production, this would be derived from the user's password or stored securely
		passphrase := s.deriveUserPassphrase(users[i].ID, masterSeedKey)

		// Encrypt the private key
		encryptedPrivateKey, err := e2eeService.EncryptPrivateKey(keyPair.PrivateKey, passphrase)
		if err != nil {
			facades.Log().Error("Failed to encrypt private key for user", map[string]interface{}{
				"user_id": users[i].ID,
				"error":   err.Error(),
			})
			continue
		}

		// Save user key with properly encrypted private key
		userKey := &models.UserKey{
			UserID:              users[i].ID,
			KeyType:             "identity",
			PublicKey:           keyPair.PublicKey,
			EncryptedPrivateKey: encryptedPrivateKey,
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
			TenantID:    tenant.ID,
			Name:        "General",
			Description: "General discussion room",
			Type:        "public",
			IsActive:    true,
		},
		{
			TenantID:    tenant.ID,
			Name:        "Development",
			Description: "Development team discussions",
			Type:        "private",
			IsActive:    true,
		},
		{
			TenantID:    tenant.ID,
			Name:        "Random",
			Description: "Random conversations",
			Type:        "public",
			IsActive:    true,
		},
	}

	for i := range chatRooms {
		err := facades.Orm().Query().Create(&chatRooms[i])
		if err != nil {
			facades.Log().Error("Failed to create chat room", map[string]interface{}{
				"room_name": chatRooms[i].Name,
				"error":     err.Error(),
			})
			continue
		}

		// Add some users to each room
		maxUsersPerRoom := 3
		if len(users) < maxUsersPerRoom {
			maxUsersPerRoom = len(users)
		}

		for j := 0; j < maxUsersPerRoom; j++ {
			member := models.ChatRoomMember{
				ChatRoomID: chatRooms[i].ID,
				UserID:     users[j].ID,
				Role:       "member",
				IsActive:   true,
				JoinedAt:   time.Now(),
			}
			if j == 0 {
				member.Role = "admin"
			}

			err := facades.Orm().Query().Create(&member)
			if err != nil {
				facades.Log().Error("Failed to add member to room", map[string]interface{}{
					"room_id": chatRooms[i].ID,
					"user_id": users[j].ID,
					"error":   err.Error(),
				})
			}
		}
	}

	// Create some sample messages
	if len(users) >= 2 {
		sampleMessages := []struct {
			content string
			userIdx int
		}{
			{"Hello everyone! Welcome to the chat.", 0},
			{"Thanks! Excited to be here.", 1},
			{"This is a test message with encryption.", 0},
			{"The encryption is working great!", 1},
		}

		for _, msg := range sampleMessages {
			if msg.userIdx >= len(users) {
				continue
			}

			// Use production-grade encryption for seeding
			e2eeService := services.NewE2EEService()

			// Get recipient public keys (simplified for seeding - in production this would be from user profiles)
			recipientKeys := []string{"seeding_public_key_placeholder"}

			encryptedMsg, err := e2eeService.EncryptMessage(msg.content, recipientKeys)
			var encryptedContent string
			if err != nil {
				facades.Log().Warning("Failed to encrypt message during seeding", map[string]interface{}{
					"error":   err.Error(),
					"content": msg.content,
				})
				// Fallback to base64 encoding if encryption fails
				encryptedContent = base64.StdEncoding.EncodeToString([]byte(msg.content))
			} else {
				// Convert encrypted message to string format for storage
				encryptedContent = encryptedMsg.Content
			}

			message := models.ChatMessage{
				ChatRoomID:       chatRooms[0].ID, // Add to General room
				SenderID:         users[msg.userIdx].ID,
				Type:             "text",
				EncryptedContent: encryptedContent,
			}

			err = facades.Orm().Query().Create(&message)
			if err != nil {
				facades.Log().Error("Failed to create message", map[string]interface{}{
					"error": err.Error(),
				})
			}
		}
	}

	return nil
}

// deriveUserPassphrase creates a secure passphrase for encrypting a user's private key
func (s *ChatSeeder) deriveUserPassphrase(userID string, masterSeedKey string) string {
	// Combine user ID with master seed key
	combined := fmt.Sprintf("%s:%s", userID, masterSeedKey)

	// Hash the combined string to create a deterministic but secure passphrase
	hash := sha256.Sum256([]byte(combined))
	return hex.EncodeToString(hash[:])
}
