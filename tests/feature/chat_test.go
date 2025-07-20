package feature

import (
	"testing"

	"goravel/app/http/requests"
	"goravel/app/models"
	"goravel/app/services"

	"github.com/stretchr/testify/assert"
)

func TestChatSystem(t *testing.T) {
	// Test E2EE service
	t.Run("E2EE Service", func(t *testing.T) {
		e2eeService := services.NewE2EEService()

		// Test key pair generation
		keyPair, err := e2eeService.GenerateKeyPair()
		assert.NoError(t, err)
		assert.NotEmpty(t, keyPair.PublicKey)
		assert.NotEmpty(t, keyPair.PrivateKey)

		// Test message encryption and decryption
		message := "Hello, this is a test message!"
		recipientPublicKeys := []string{keyPair.PublicKey}

		encryptedMsg, err := e2eeService.EncryptMessage(message, recipientPublicKeys)
		assert.NoError(t, err)
		assert.NotEmpty(t, encryptedMsg.Content)

		decryptedMessage, err := e2eeService.DecryptMessage(encryptedMsg, keyPair.PrivateKey)
		assert.NoError(t, err)
		assert.Equal(t, message, decryptedMessage)

		// Test room key generation
		roomKey, err := e2eeService.GenerateRoomKey()
		assert.NoError(t, err)
		assert.NotEmpty(t, roomKey)

		// Test room key encryption
		encryptedRoomKey, err := e2eeService.EncryptRoomKey(roomKey, keyPair.PublicKey)
		assert.NoError(t, err)
		assert.NotEmpty(t, encryptedRoomKey)

		// Test room key decryption
		decryptedRoomKey, err := e2eeService.DecryptRoomKey(encryptedRoomKey, keyPair.PrivateKey)
		assert.NoError(t, err)
		assert.Equal(t, roomKey, decryptedRoomKey)

		// Test message encryption with room key
		encryptedWithRoomKey, err := e2eeService.EncryptWithRoomKey(message, roomKey)
		assert.NoError(t, err)
		assert.NotEmpty(t, encryptedWithRoomKey)

		// Test message decryption with room key
		decryptedWithRoomKey, err := e2eeService.DecryptWithRoomKey(encryptedWithRoomKey, roomKey)
		assert.NoError(t, err)
		assert.Equal(t, message, decryptedWithRoomKey)
	})

	// Test chat service
	t.Run("Chat Service", func(t *testing.T) {
		chatService := services.NewChatService()

		// Create test data
		tenantID := "test_tenant_123"
		user1ID := "test_user_1"
		user2ID := "test_user_2"

		// Test chat room creation
		chatRoom, err := chatService.CreateChatRoom(
			"Test Room",
			"Test Description",
			"group",
			tenantID,
			user1ID,
			[]string{user2ID},
		)
		assert.NoError(t, err)
		assert.NotEmpty(t, chatRoom.ID)
		assert.Equal(t, "Test Room", chatRoom.Name)
		assert.Equal(t, "group", chatRoom.Type)

		// Test sending a message
		message, err := chatService.SendMessage(
			chatRoom.ID,
			user1ID,
			"text",
			"Hello, this is a test message!",
			nil,
			nil,
		)
		assert.NoError(t, err)
		assert.NotEmpty(t, message.ID)
		assert.Equal(t, chatRoom.ID, message.ChatRoomID)
		assert.Equal(t, user1ID, message.SenderID)

		// Test getting messages
		messages, err := chatService.GetMessages(chatRoom.ID, user1ID, 10, nil)
		assert.NoError(t, err)
		assert.Len(t, messages, 1)
		assert.Equal(t, message.ID, messages[0].ID)

		// Test getting room members
		members, err := chatService.GetRoomMembers(chatRoom.ID)
		assert.NoError(t, err)
		assert.Len(t, members, 2) // user1 and user2

		// Test marking room as read
		err = chatService.MarkRoomAsRead(chatRoom.ID, user1ID)
		assert.NoError(t, err)
	})

	// Test API endpoints (if running with HTTP server)
	t.Run("Chat API Endpoints", func(t *testing.T) {
		// This test would require a running HTTP server
		// For now, we'll just test the request/response structures

		// Test create chat room request
		createRoomReq := requests.CreateChatRoomRequest{
			Name:        "API Test Room",
			Description: "Test room created via API",
			Type:        "group",
			MemberIDs:   []string{"user1", "user2"},
		}

		// Test send message request
		sendMessageReq := requests.SendMessageRequest{
			Content: "Hello from API test!",
			Type:    "text",
		}

		// Test add member request
		addMemberReq := requests.AddMemberRequest{
			UserID: "user3",
			Role:   "member",
		}

		// Verify request structures are valid
		assert.NotEmpty(t, createRoomReq.Name)
		assert.NotEmpty(t, sendMessageReq.Content)
		assert.NotEmpty(t, addMemberReq.UserID)
	})
}

// TestChatModels tests the chat model structures
func TestChatModels(t *testing.T) {
	t.Run("Chat Room Model", func(t *testing.T) {
		chatRoom := models.ChatRoom{
			Name:        "Test Room",
			Description: "Test Description",
			Type:        "group",
			IsActive:    true,
			TenantID:    "test_tenant",
			CreatedBy:   "test_user",
		}

		assert.Equal(t, "Test Room", chatRoom.Name)
		assert.Equal(t, "group", chatRoom.Type)
		assert.True(t, chatRoom.IsActive)
	})

	t.Run("Chat Message Model", func(t *testing.T) {
		chatMessage := models.ChatMessage{
			ChatRoomID:        "test_room",
			SenderID:          "test_user",
			Type:              "text",
			EncryptedContent:  "encrypted_content",
			Status:            "sent",
			EncryptionVersion: 1,
		}

		assert.Equal(t, "test_room", chatMessage.ChatRoomID)
		assert.Equal(t, "text", chatMessage.Type)
		assert.Equal(t, "sent", chatMessage.Status)
	})

	t.Run("Chat Room Member Model", func(t *testing.T) {
		member := models.ChatRoomMember{
			ChatRoomID: "test_room",
			UserID:     "test_user",
			Role:       "admin",
			IsActive:   true,
		}

		assert.Equal(t, "test_room", member.ChatRoomID)
		assert.Equal(t, "admin", member.Role)
		assert.True(t, member.IsActive)
	})

	t.Run("User Key Model", func(t *testing.T) {
		userKey := models.UserKey{
			UserID:              "test_user",
			KeyType:             "identity",
			PublicKey:           "public_key_data",
			EncryptedPrivateKey: "encrypted_private_key_data",
			Version:             1,
			IsActive:            true,
		}

		assert.Equal(t, "test_user", userKey.UserID)
		assert.Equal(t, "identity", userKey.KeyType)
		assert.Equal(t, 1, userKey.Version)
		assert.True(t, userKey.IsActive)
	})
}

// TestChatEncryption tests the encryption functionality
func TestChatEncryption(t *testing.T) {
	e2eeService := services.NewE2EEService()

	t.Run("Direct Message Encryption", func(t *testing.T) {
		// Generate key pairs for two users
		user1Keys, err := e2eeService.GenerateKeyPair()
		assert.NoError(t, err)

		user2Keys, err := e2eeService.GenerateKeyPair()
		assert.NoError(t, err)

		// User1 sends a message to User2
		message := "Secret message from user1 to user2"
		recipientPublicKeys := []string{user2Keys.PublicKey}

		encryptedMsg, err := e2eeService.EncryptMessage(message, recipientPublicKeys)
		assert.NoError(t, err)

		// User2 decrypts the message
		decryptedMessage, err := e2eeService.DecryptMessage(encryptedMsg, user2Keys.PrivateKey)
		assert.NoError(t, err)
		assert.Equal(t, message, decryptedMessage)

		// User1 should not be able to decrypt the message (different key pair)
		_, err = e2eeService.DecryptMessage(encryptedMsg, user1Keys.PrivateKey)
		assert.Error(t, err) // Should fail
	})

	t.Run("Group Message Encryption", func(t *testing.T) {
		// Generate room key
		roomKey, err := e2eeService.GenerateRoomKey()
		assert.NoError(t, err)

		// Encrypt message with room key
		message := "Group message for all members"
		encryptedMessage, err := e2eeService.EncryptWithRoomKey(message, roomKey)
		assert.NoError(t, err)

		// Decrypt message with room key
		decryptedMessage, err := e2eeService.DecryptWithRoomKey(encryptedMessage, roomKey)
		assert.NoError(t, err)
		assert.Equal(t, message, decryptedMessage)
	})

	t.Run("Key Rotation", func(t *testing.T) {
		// Test room key rotation
		// This would require a database connection
		// For now, we'll just test the key generation
		newRoomKey, err := e2eeService.GenerateRoomKey()
		assert.NoError(t, err)
		assert.NotEmpty(t, newRoomKey)
	})
}

// TestMessageReactions tests message reaction functionality
func TestMessageReactions(t *testing.T) {
	chatService := services.NewChatService()

	// Create test data
	tenantID := "test_tenant_123"
	user1ID := "test_user_1"
	user2ID := "test_user_2"

	// Create a chat room
	chatRoom, err := chatService.CreateChatRoom(
		"Test Room",
		"Test Description",
		"group",
		tenantID,
		user1ID,
		[]string{user2ID},
	)
	assert.NoError(t, err)

	// Send a message
	message, err := chatService.SendMessage(
		chatRoom.ID,
		user1ID,
		"text",
		"Hello, this is a test message!",
		nil,
		nil,
	)
	assert.NoError(t, err)

	// Test adding a reaction
	reaction, err := chatService.AddMessageReaction(message.ID, user2ID, "👍")
	assert.NoError(t, err)
	assert.Equal(t, message.ID, reaction.MessageID)
	assert.Equal(t, user2ID, reaction.UserID)
	assert.Equal(t, "👍", reaction.Emoji)

	// Test adding another reaction
	reaction2, err := chatService.AddMessageReaction(message.ID, user1ID, "❤️")
	assert.NoError(t, err)
	assert.Equal(t, "❤️", reaction2.Emoji)

	// Test getting reactions
	reactions, err := chatService.GetMessageReactions(message.ID)
	assert.NoError(t, err)
	assert.Len(t, reactions, 2)

	// Test getting reaction summary
	summary, err := chatService.GetReactionSummary(message.ID)
	assert.NoError(t, err)
	assert.Equal(t, 1, summary["👍"])
	assert.Equal(t, 1, summary["❤️"])

	// Test removing a reaction
	err = chatService.RemoveMessageReaction(message.ID, user2ID, "👍")
	assert.NoError(t, err)

	// Verify reaction was removed
	reactions, err = chatService.GetMessageReactions(message.ID)
	assert.NoError(t, err)
	assert.Len(t, reactions, 1)
	assert.Equal(t, "❤️", reactions[0].Emoji)
}

// TestEncryptedFileSharing tests encrypted file sharing functionality
func TestEncryptedFileSharing(t *testing.T) {
	e2eeService := services.NewE2EEService()

	// Generate key pairs for two users
	user1Keys, err := e2eeService.GenerateKeyPair()
	assert.NoError(t, err)

	user2Keys, err := e2eeService.GenerateKeyPair()
	assert.NoError(t, err)

	// Test file encryption
	fileData := []byte("This is a test file content with sensitive information")
	fileName := "test_document.txt"
	mimeType := "text/plain"
	recipientPublicKeys := []string{user2Keys.PublicKey}

	encryptedFile, err := e2eeService.EncryptFile(fileData, fileName, mimeType, recipientPublicKeys)
	assert.NoError(t, err)
	assert.NotEmpty(t, encryptedFile.ID)
	assert.Equal(t, fileName, encryptedFile.FileName)
	assert.Equal(t, mimeType, encryptedFile.MimeType)
	assert.Equal(t, int64(len(fileData)), encryptedFile.FileSize)
	assert.NotEmpty(t, encryptedFile.EncryptedData)

	// Test file decryption
	decryptedData, err := e2eeService.DecryptFile(encryptedFile, user2Keys.PrivateKey)
	assert.NoError(t, err)
	assert.Equal(t, fileData, decryptedData)

	// Test that user1 cannot decrypt the file (different key pair)
	_, err = e2eeService.DecryptFile(encryptedFile, user1Keys.PrivateKey)
	assert.Error(t, err) // Should fail
}

// TestPerfectForwardSecrecy tests PFS functionality
func TestPerfectForwardSecrecy(t *testing.T) {
	e2eeService := services.NewE2EEService()

	// Test prekey bundle generation
	userID := "test_user_123"
	deviceID := 1

	prekeyBundle, err := e2eeService.GeneratePrekeyBundle(userID, deviceID)
	assert.NoError(t, err)
	assert.NotEmpty(t, prekeyBundle.IdentityKey)
	assert.NotNil(t, prekeyBundle.SignedPrekey)
	assert.Len(t, prekeyBundle.OneTimePrekeys, 100)
	assert.Greater(t, prekeyBundle.RegistrationID, 0)
	assert.Equal(t, deviceID, prekeyBundle.DeviceID)

	// Test signed prekey generation
	signedPrekey, err := e2eeService.GenerateSignedPrekey(prekeyBundle.IdentityKey)
	assert.NoError(t, err)
	assert.Greater(t, signedPrekey.KeyID, 0)
	assert.NotEmpty(t, signedPrekey.PublicKey)
	assert.NotEmpty(t, signedPrekey.Signature)
	assert.Greater(t, signedPrekey.Timestamp, int64(0))

	// Test one-time prekey generation
	oneTimePrekey, err := e2eeService.GenerateOneTimePrekey()
	assert.NoError(t, err)
	assert.Greater(t, oneTimePrekey.KeyID, 0)
	assert.NotEmpty(t, oneTimePrekey.PublicKey)
}

// TestEncryptedSearch tests encrypted search functionality
func TestEncryptedSearch(t *testing.T) {
	e2eeService := services.NewE2EEService()

	// Test search hash generation
	encryptedContent := "encrypted_message_content"
	searchTerms := []string{"hello", "world"}

	searchHash, err := e2eeService.GenerateSearchHash(encryptedContent, searchTerms)
	assert.NoError(t, err)
	assert.NotEmpty(t, searchHash)

	// Test content hash generation
	contentHash := e2eeService.GenerateContentHash(encryptedContent)
	assert.NotEmpty(t, contentHash)

	// Test that same content produces same hash
	contentHash2 := e2eeService.GenerateContentHash(encryptedContent)
	assert.Equal(t, contentHash, contentHash2)

	// Test that different content produces different hash
	differentContent := "different_encrypted_content"
	differentHash := e2eeService.GenerateContentHash(differentContent)
	assert.NotEqual(t, contentHash, differentHash)
}

// TestRealTimeEvents tests real-time event broadcasting
func TestRealTimeEvents(t *testing.T) {
	chatService := services.NewChatService()

	// Create test data
	tenantID := "test_tenant_123"
	user1ID := "test_user_1"
	user2ID := "test_user_2"

	// Create a chat room
	chatRoom, err := chatService.CreateChatRoom(
		"Test Room",
		"Test Description",
		"group",
		tenantID,
		user1ID,
		[]string{user2ID},
	)
	assert.NoError(t, err)

	// Test sending message with notification
	message, err := chatService.SendMessageWithNotification(
		chatRoom.ID,
		user1ID,
		"text",
		"Hello with notification!",
		nil,
		nil,
	)
	assert.NoError(t, err)
	assert.NotEmpty(t, message.ID)

	// Test adding reaction with notification
	reaction, err := chatService.AddMessageReactionWithNotification(message.ID, user2ID, "👍")
	assert.NoError(t, err)
	assert.Equal(t, "👍", reaction.Emoji)

	// Test removing reaction with notification
	err = chatService.RemoveMessageReactionWithNotification(message.ID, user2ID, "👍")
	assert.NoError(t, err)

	// Test broadcasting custom event
	err = chatService.BroadcastEvent(chatRoom.ID, "custom_event", user1ID, map[string]interface{}{
		"custom_data": "test_value",
	})
	assert.NoError(t, err)
}

// TestChatEventTypes tests chat event type constants
func TestChatEventTypes(t *testing.T) {
	// Test that all event types are defined
	assert.NotEmpty(t, services.EventMessageSent)
	assert.NotEmpty(t, services.EventMessageReceived)
	assert.NotEmpty(t, services.EventMessageRead)
	assert.NotEmpty(t, services.EventMemberJoined)
	assert.NotEmpty(t, services.EventMemberLeft)
	assert.NotEmpty(t, services.EventReactionAdded)
	assert.NotEmpty(t, services.EventReactionRemoved)
	assert.NotEmpty(t, services.EventRoomUpdated)
	assert.NotEmpty(t, services.EventKeyRotated)

	// Test that event types are unique
	eventTypes := []string{
		services.EventMessageSent,
		services.EventMessageReceived,
		services.EventMessageRead,
		services.EventMemberJoined,
		services.EventMemberLeft,
		services.EventReactionAdded,
		services.EventReactionRemoved,
		services.EventRoomUpdated,
		services.EventKeyRotated,
	}

	uniqueTypes := make(map[string]bool)
	for _, eventType := range eventTypes {
		assert.False(t, uniqueTypes[eventType], "Duplicate event type: %s", eventType)
		uniqueTypes[eventType] = true
	}
}
