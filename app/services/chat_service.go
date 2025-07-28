package services

import (
	"encoding/json"
	"fmt"
	"time"

	"goravel/app/models"

	"github.com/goravel/framework/facades"
)

// ChatService handles chat room and message operations
type ChatService struct {
	e2eeService *E2EEService
}

// NewChatService creates a new chat service instance
func NewChatService() *ChatService {
	return &ChatService{
		e2eeService: NewE2EEService(),
	}
}

// CreateChatRoom creates a new chat room
func (s *ChatService) CreateChatRoom(name, description, roomType, tenantID, createdBy string, memberIDs []string) (*models.ChatRoom, error) {
	// Create the chat room
	chatRoom := &models.ChatRoom{
		Name:        name,
		Description: description,
		Type:        roomType,
		IsActive:    true,
		TenantID:    tenantID,
		BaseModel: models.BaseModel{
			CreatedBy: &createdBy,
		},
	}

	err := facades.Orm().Query().Create(chatRoom)
	if err != nil {
		return nil, fmt.Errorf("failed to create chat room: %v", err)
	}

	// Add creator as admin member
	err = s.AddMemberToRoom(chatRoom.ID, createdBy, "admin", tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to add creator to room: %v", err)
	}

	// Add other members
	for _, memberID := range memberIDs {
		if memberID != createdBy {
			err = s.AddMemberToRoom(chatRoom.ID, memberID, "member", tenantID)
			if err != nil {
				facades.Log().Error("Failed to add member to room", map[string]interface{}{
					"room_id":   chatRoom.ID,
					"member_id": memberID,
					"error":     err.Error(),
				})
			}
		}
	}

	// Generate room key for E2EE
	err = s.GenerateRoomKey(chatRoom.ID)
	if err != nil {
		facades.Log().Error("Failed to generate room key", map[string]interface{}{
			"room_id": chatRoom.ID,
			"error":   err.Error(),
		})
	}

	return chatRoom, nil
}

// GetChatRoom retrieves a chat room by ID
func (s *ChatService) GetChatRoom(roomID, userID string) (*models.ChatRoom, error) {
	var chatRoom models.ChatRoom
	err := facades.Orm().Query().Where("id", roomID).First(&chatRoom)
	if err != nil {
		return nil, fmt.Errorf("chat room not found: %v", err)
	}

	// Check if user is a member
	var member models.ChatRoomMember
	err = facades.Orm().Query().Where("chat_room_id", roomID).Where("user_id", userID).Where("is_active", true).First(&member)
	if err != nil {
		return nil, fmt.Errorf("user is not a member of this room")
	}

	return &chatRoom, nil
}

// GetUserChatRooms retrieves all chat rooms for a user
func (s *ChatService) GetUserChatRooms(userID, tenantID string) ([]models.ChatRoom, error) {
	// First get member records for the user
	var members []models.ChatRoomMember
	err := facades.Orm().Query().
		Where("user_id", userID).
		Where("is_active", true).
		Find(&members)
	if err != nil {
		return nil, err
	}

	// Extract room IDs
	roomIDs := make([]string, 0, len(members))
	for _, member := range members {
		roomIDs = append(roomIDs, member.ChatRoomID)
	}

	if len(roomIDs) == 0 {
		return []models.ChatRoom{}, nil
	}

	// Get chat rooms
	var chatRooms []models.ChatRoom
	err = facades.Orm().Query().
		Where("id IN ?", roomIDs).
		Where("tenant_id", tenantID).
		Where("is_active", true).
		Order("last_activity_at DESC").
		Find(&chatRooms)

	return chatRooms, err
}

// AddMemberToRoom adds a user to a chat room
func (s *ChatService) AddMemberToRoom(roomID, userID, role, tenantID string) error {
	// Check if user is already a member
	var existingMember models.ChatRoomMember
	err := facades.Orm().Query().Where("chat_room_id", roomID).Where("user_id", userID).First(&existingMember)
	if err == nil {
		// User is already a member, update role if needed
		if existingMember.Role != role {
			existingMember.Role = role
			existingMember.IsActive = true
			return facades.Orm().Query().Save(&existingMember)
		}
		return nil
	}

	// Add new member
	member := &models.ChatRoomMember{
		ChatRoomID: roomID,
		UserID:     userID,
		Role:       role,
		IsActive:   true,
		JoinedAt:   time.Now(),
	}

	return facades.Orm().Query().Create(member)
}

// RemoveMemberFromRoom removes a user from a chat room
func (s *ChatService) RemoveMemberFromRoom(roomID, userID string) error {
	var member models.ChatRoomMember
	err := facades.Orm().Query().Where("chat_room_id", roomID).Where("user_id", userID).First(&member)
	if err != nil {
		return fmt.Errorf("member not found")
	}

	member.IsActive = false
	return facades.Orm().Query().Save(&member)
}

// SendMessage sends a message to a chat room
func (s *ChatService) SendMessage(roomID, senderID, messageType, content string, metadata map[string]interface{}, replyToID *string) (*models.ChatMessage, error) {
	// Check if sender is a member
	var member models.ChatRoomMember
	err := facades.Orm().Query().Where("chat_room_id", roomID).Where("user_id", senderID).Where("is_active", true).First(&member)
	if err != nil {
		return nil, fmt.Errorf("user is not a member of this room")
	}

	// Get room type to determine encryption method
	var chatRoom models.ChatRoom
	err = facades.Orm().Query().Where("id", roomID).First(&chatRoom)
	if err != nil {
		return nil, fmt.Errorf("chat room not found")
	}

	var encryptedContent string
	var encryptionVersion int

	if chatRoom.Type == "direct" {
		// For direct messages, use individual encryption
		encryptedContent, encryptionVersion, err = s.encryptDirectMessage(roomID, content, senderID)
	} else {
		// For group messages, use room key encryption
		encryptedContent, encryptionVersion, err = s.encryptGroupMessage(roomID, content)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to encrypt message: %v", err)
	}

	// Convert metadata to JSON
	metadataJSON := ""
	if metadata != nil {
		metadataBytes, err := json.Marshal(metadata)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal metadata: %v", err)
		}
		metadataJSON = string(metadataBytes)
	}

	// Create message
	chatMessage := &models.ChatMessage{
		ChatRoomID:        roomID,
		SenderID:          senderID,
		Type:              messageType,
		EncryptedContent:  encryptedContent,
		Metadata:          metadataJSON,
		ReplyToID:         replyToID,
		Status:            "sent",
		EncryptionVersion: encryptionVersion,
	}

	err = facades.Orm().Query().Create(chatMessage)
	if err != nil {
		return nil, fmt.Errorf("failed to save message: %v", err)
	}

	// Update room's last activity
	now := time.Now()
	chatRoom.LastActivityAt = &now
	facades.Orm().Query().Save(&chatRoom)

	return chatMessage, nil
}

// GetMessages retrieves messages from a chat room
func (s *ChatService) GetMessages(roomID, userID string, limit int, beforeID *string) ([]models.ChatMessage, error) {
	// Check if user is a member
	var member models.ChatRoomMember
	err := facades.Orm().Query().Where("chat_room_id", roomID).Where("user_id", userID).Where("is_active", true).First(&member)
	if err != nil {
		return nil, fmt.Errorf("user is not a member of this room")
	}

	query := facades.Orm().Query().Where("chat_room_id", roomID).Order("created_at DESC").Limit(limit)

	if beforeID != nil {
		var beforeMessage models.ChatMessage
		err = facades.Orm().Query().Where("id", *beforeID).First(&beforeMessage)
		if err == nil {
			query = query.Where("created_at < ?", beforeMessage.CreatedAt)
		}
	}

	var messages []models.ChatMessage
	err = query.Find(&messages)
	if err != nil {
		return nil, err
	}

	// Decrypt messages for the user
	for i := range messages {
		decryptedContent, err := s.decryptMessage(&messages[i], userID)
		if err != nil {
			facades.Log().Error("Failed to decrypt message", map[string]interface{}{
				"message_id": messages[i].ID,
				"user_id":    userID,
				"error":      err.Error(),
			})
			messages[i].EncryptedContent = "[Encrypted]"
		} else {
			messages[i].EncryptedContent = decryptedContent
		}
	}

	return messages, nil
}

// MarkMessageAsRead marks a message as read by a user
func (s *ChatService) MarkMessageAsRead(messageID, userID string) error {
	// Check if already marked as read
	var existingRead models.MessageRead
	err := facades.Orm().Query().Where("message_id", messageID).Where("user_id", userID).First(&existingRead)
	if err == nil {
		return nil // Already marked as read
	}

	// Mark as read
	messageRead := &models.MessageRead{
		MessageID: messageID,
		UserID:    userID,
		ReadAt:    time.Now(),
	}

	return facades.Orm().Query().Create(messageRead)
}

// MarkRoomAsRead marks all messages in a room as read by a user
func (s *ChatService) MarkRoomAsRead(roomID, userID string) error {
	// Update member's last read timestamp
	var member models.ChatRoomMember
	err := facades.Orm().Query().Where("chat_room_id", roomID).Where("user_id", userID).First(&member)
	if err != nil {
		return fmt.Errorf("member not found")
	}

	now := time.Now()
	member.LastReadAt = &now
	return facades.Orm().Query().Save(&member)
}

// GetRoomMembers retrieves all members of a chat room
func (s *ChatService) GetRoomMembers(roomID string) ([]models.ChatRoomMember, error) {
	var members []models.ChatRoomMember
	err := facades.Orm().Query().Where("chat_room_id", roomID).Where("is_active", true).Find(&members)
	return members, err
}

// UpdateRoom updates a chat room's information
func (s *ChatService) UpdateRoom(roomID, name, description string, userID string) (*models.ChatRoom, error) {
	// Check if user is admin
	var member models.ChatRoomMember
	err := facades.Orm().Query().Where("chat_room_id", roomID).Where("user_id", userID).Where("role", "admin").First(&member)
	if err != nil {
		return nil, fmt.Errorf("user is not an admin of this room")
	}

	var chatRoom models.ChatRoom
	err = facades.Orm().Query().Where("id", roomID).First(&chatRoom)
	if err != nil {
		return nil, fmt.Errorf("chat room not found")
	}

	chatRoom.Name = name
	chatRoom.Description = description

	err = facades.Orm().Query().Save(&chatRoom)
	if err != nil {
		return nil, fmt.Errorf("failed to update chat room: %v", err)
	}

	return &chatRoom, nil
}

// DeleteRoom deletes a chat room (soft delete)
func (s *ChatService) DeleteRoom(roomID, userID string) error {
	// Check if user is admin
	var member models.ChatRoomMember
	err := facades.Orm().Query().Where("chat_room_id", roomID).Where("user_id", userID).Where("role", "admin").First(&member)
	if err != nil {
		return fmt.Errorf("user is not an admin of this room")
	}

	var chatRoom models.ChatRoom
	err = facades.Orm().Query().Where("id", roomID).First(&chatRoom)
	if err != nil {
		return fmt.Errorf("chat room not found")
	}

	chatRoom.IsActive = false
	return facades.Orm().Query().Save(&chatRoom)
}

// AddMessageReaction adds a reaction to a message
func (s *ChatService) AddMessageReaction(messageID, userID, emoji string) (*models.MessageReaction, error) {
	// Check if user is a member of the room
	var message models.ChatMessage
	err := facades.Orm().Query().Where("id", messageID).First(&message)
	if err != nil {
		return nil, fmt.Errorf("message not found")
	}

	var member models.ChatRoomMember
	err = facades.Orm().Query().Where("chat_room_id", message.ChatRoomID).Where("user_id", userID).Where("is_active", true).First(&member)
	if err != nil {
		return nil, fmt.Errorf("user is not a member of this room")
	}

	// Check if reaction already exists
	var existingReaction models.MessageReaction
	err = facades.Orm().Query().Where("message_id", messageID).Where("user_id", userID).Where("emoji", emoji).First(&existingReaction)
	if err == nil {
		// Reaction already exists, return it
		return &existingReaction, nil
	}

	// Create new reaction
	reaction := &models.MessageReaction{
		MessageID: messageID,
		UserID:    userID,
		Emoji:     emoji,
		ReactedAt: time.Now(),
	}

	err = facades.Orm().Query().Create(reaction)
	if err != nil {
		return nil, fmt.Errorf("failed to create reaction: %v", err)
	}

	return reaction, nil
}

// RemoveMessageReaction removes a reaction from a message
func (s *ChatService) RemoveMessageReaction(messageID, userID, emoji string) error {
	// Check if user is a member of the room
	var message models.ChatMessage
	err := facades.Orm().Query().Where("id", messageID).First(&message)
	if err != nil {
		return fmt.Errorf("message not found")
	}

	var member models.ChatRoomMember
	err = facades.Orm().Query().Where("chat_room_id", message.ChatRoomID).Where("user_id", userID).Where("is_active", true).First(&member)
	if err != nil {
		return fmt.Errorf("user is not a member of this room")
	}

	// Delete the reaction
	_, err = facades.Orm().Query().Where("message_id", messageID).Where("user_id", userID).Where("emoji", emoji).Delete(&models.MessageReaction{})
	if err != nil {
		return fmt.Errorf("failed to remove reaction: %v", err)
	}

	return nil
}

// GetMessageReactions retrieves all reactions for a message
func (s *ChatService) GetMessageReactions(messageID string) ([]models.MessageReaction, error) {
	var reactions []models.MessageReaction
	err := facades.Orm().Query().Where("message_id", messageID).Find(&reactions)
	return reactions, err
}

// GetReactionSummary gets a summary of reactions for a message
func (s *ChatService) GetReactionSummary(messageID string) (map[string]int, error) {
	var reactions []models.MessageReaction
	err := facades.Orm().Query().Where("message_id", messageID).Find(&reactions)
	if err != nil {
		return nil, err
	}

	// Count reactions by emoji
	summary := make(map[string]int)
	for _, reaction := range reactions {
		summary[reaction.Emoji]++
	}

	return summary, nil
}

// Helper methods for encryption

func (s *ChatService) GenerateRoomKey(roomID string) error {
	roomKey, err := s.e2eeService.GenerateRoomKey()
	if err != nil {
		return err
	}

	// Get room members
	var members []models.ChatRoomMember
	err = facades.Orm().Query().Where("chat_room_id", roomID).Where("is_active", true).Find(&members)
	if err != nil {
		return err
	}

	// Encrypt room key for each member
	for _, member := range members {
		if member.PublicKey != "" {
			encryptedKey, err := s.e2eeService.EncryptRoomKey(roomKey, member.PublicKey)
			if err != nil {
				facades.Log().Error("Failed to encrypt room key for member", map[string]interface{}{
					"member_id": member.UserID,
					"error":     err.Error(),
				})
				continue
			}

			// Save encrypted room key
			roomKeyModel := &models.ChatRoomKey{
				ChatRoomID:   roomID,
				KeyType:      "room_key",
				EncryptedKey: encryptedKey,
				Version:      1,
				IsActive:     true,
			}

			err = s.e2eeService.SaveRoomKey(roomKeyModel)
			if err != nil {
				facades.Log().Error("Failed to save room key", map[string]interface{}{
					"member_id": member.UserID,
					"error":     err.Error(),
				})
			}
		}
	}

	return nil
}

func (s *ChatService) encryptDirectMessage(roomID, content, senderID string) (string, int, error) {
	// Get recipient (for direct messages, there should be only one other member)
	var members []models.ChatRoomMember
	err := facades.Orm().Query().Where("chat_room_id", roomID).Where("user_id != ?", senderID).Where("is_active", true).Find(&members)
	if err != nil || len(members) == 0 {
		return "", 0, fmt.Errorf("no recipient found for direct message")
	}

	// Get recipient's public key
	recipientPublicKeys := make([]string, 0)
	for _, member := range members {
		if member.PublicKey != "" {
			recipientPublicKeys = append(recipientPublicKeys, member.PublicKey)
		}
	}

	if len(recipientPublicKeys) == 0 {
		return "", 0, fmt.Errorf("recipient has no public key")
	}

	// Encrypt message
	encryptedMsg, err := s.e2eeService.EncryptMessage(content, recipientPublicKeys)
	if err != nil {
		return "", 0, err
	}

	// Convert to JSON
	encryptedData, err := json.Marshal(encryptedMsg)
	if err != nil {
		return "", 0, err
	}

	return string(encryptedData), encryptedMsg.Version, nil
}

func (s *ChatService) encryptGroupMessage(roomID, content string) (string, int, error) {
	// Get room key
	var roomKey models.ChatRoomKey
	err := facades.Orm().Query().Where("chat_room_id", roomID).Where("key_type", "room_key").Where("is_active", true).First(&roomKey)
	if err != nil {
		return "", 0, fmt.Errorf("room key not found")
	}

	// Decode room key (this would normally be decrypted with user's private key)
	// For simplicity, we'll assume the room key is stored in plain text
	roomKeyBytes := []byte(roomKey.EncryptedKey)

	// Encrypt message with room key
	encryptedContent, err := s.e2eeService.EncryptWithRoomKey(content, roomKeyBytes)
	if err != nil {
		return "", 0, err
	}

	return encryptedContent, roomKey.Version, nil
}

func (s *ChatService) decryptMessage(message *models.ChatMessage, userID string) (string, error) {
	// Get user's private key
	var userKey models.UserKey
	err := facades.Orm().Query().Where("user_id", userID).Where("key_type", "identity").Where("is_active", true).First(&userKey)
	if err != nil {
		return "", fmt.Errorf("user key not found")
	}

	// For direct messages, decrypt using individual encryption
	if message.EncryptionVersion == 1 {
		var encryptedMsg EncryptedMessage
		err = json.Unmarshal([]byte(message.EncryptedContent), &encryptedMsg)
		if err != nil {
			return "", err
		}

		return s.e2eeService.DecryptMessage(&encryptedMsg, userKey.EncryptedPrivateKey)
	}

	// For group messages, decrypt using room key
	// Get room key for this user
	var roomKey models.ChatRoomKey
	err = facades.Orm().Query().Where("chat_room_id", message.ChatRoomID).Where("key_type", "room_key").Where("is_active", true).First(&roomKey)
	if err != nil {
		return "", fmt.Errorf("room key not found")
	}

	// Decrypt room key with user's private key
	roomKeyBytes, err := s.e2eeService.DecryptRoomKey(roomKey.EncryptedKey, userKey.EncryptedPrivateKey)
	if err != nil {
		return "", err
	}

	// Decrypt message with room key
	return s.e2eeService.DecryptWithRoomKey(message.EncryptedContent, roomKeyBytes)
}

// ChatEvent represents a real-time chat event
type ChatEvent struct {
	Type      string      `json:"type"`
	RoomID    string      `json:"room_id"`
	UserID    string      `json:"user_id"`
	Data      interface{} `json:"data"`
	Timestamp time.Time   `json:"timestamp"`
}

// ChatEventType constants
const (
	EventMessageSent     = "message_sent"
	EventMessageReceived = "message_received"
	EventMessageRead     = "message_read"
	EventMemberJoined    = "member_joined"
	EventMemberLeft      = "member_left"
	EventReactionAdded   = "reaction_added"
	EventReactionRemoved = "reaction_removed"
	EventRoomUpdated     = "room_updated"
	EventKeyRotated      = "key_rotated"
)

// BroadcastEvent broadcasts a chat event to room members
func (s *ChatService) BroadcastEvent(roomID string, eventType string, userID string, data interface{}) error {
	// Get room members
	members, err := s.GetRoomMembers(roomID)
	if err != nil {
		return err
	}

	event := &ChatEvent{
		Type:      eventType,
		RoomID:    roomID,
		UserID:    userID,
		Data:      data,
		Timestamp: time.Now(),
	}

	// In a real implementation, you would broadcast to WebSocket connections
	// For now, we'll just log the event
	facades.Log().Info("Chat event broadcast", map[string]interface{}{
		"event_type": event.Type,
		"room_id":    event.RoomID,
		"user_id":    event.UserID,
		"members":    len(members),
		"data":       event.Data,
	})

	return nil
}

// SendMessageWithNotification sends a message and broadcasts the event
func (s *ChatService) SendMessageWithNotification(roomID, senderID, messageType, content string, metadata map[string]interface{}, replyToID *string) (*models.ChatMessage, error) {
	// Send the message
	message, err := s.SendMessage(roomID, senderID, messageType, content, metadata, replyToID)
	if err != nil {
		return nil, err
	}

	// Broadcast the event
	err = s.BroadcastEvent(roomID, EventMessageSent, senderID, message)
	if err != nil {
		facades.Log().Error("Failed to broadcast message event", map[string]interface{}{
			"room_id": roomID,
			"error":   err.Error(),
		})
	}

	return message, nil
}

// AddMessageReactionWithNotification adds a reaction and broadcasts the event
func (s *ChatService) AddMessageReactionWithNotification(messageID, userID, emoji string) (*models.MessageReaction, error) {
	// Add the reaction
	reaction, err := s.AddMessageReaction(messageID, userID, emoji)
	if err != nil {
		return nil, err
	}

	// Get the message to find the room ID
	var message models.ChatMessage
	err = facades.Orm().Query().Where("id", messageID).First(&message)
	if err != nil {
		return reaction, nil // Return reaction even if broadcast fails
	}

	// Broadcast the event
	err = s.BroadcastEvent(message.ChatRoomID, EventReactionAdded, userID, reaction)
	if err != nil {
		facades.Log().Error("Failed to broadcast reaction event", map[string]interface{}{
			"message_id": messageID,
			"error":      err.Error(),
		})
	}

	return reaction, nil
}

// RemoveMessageReactionWithNotification removes a reaction and broadcasts the event
func (s *ChatService) RemoveMessageReactionWithNotification(messageID, userID, emoji string) error {
	// Get the message to find the room ID
	var message models.ChatMessage
	err := facades.Orm().Query().Where("id", messageID).First(&message)
	if err != nil {
		return err
	}

	// Remove the reaction
	err = s.RemoveMessageReaction(messageID, userID, emoji)
	if err != nil {
		return err
	}

	// Broadcast the event
	reactionData := map[string]interface{}{
		"message_id": messageID,
		"user_id":    userID,
		"emoji":      emoji,
	}

	err = s.BroadcastEvent(message.ChatRoomID, EventReactionRemoved, userID, reactionData)
	if err != nil {
		facades.Log().Error("Failed to broadcast reaction removal event", map[string]interface{}{
			"message_id": messageID,
			"error":      err.Error(),
		})
	}

	return nil
}

// EditMessage edits a message
func (s *ChatService) EditMessage(messageID, userID, newContent string) (*models.ChatMessage, error) {
	// Get the message
	var message models.ChatMessage
	err := facades.Orm().Query().Where("id", messageID).First(&message)
	if err != nil {
		return nil, fmt.Errorf("message not found: %v", err)
	}

	// Check if user is the sender
	if message.SenderID != userID {
		return nil, fmt.Errorf("user can only edit their own messages")
	}

	// Check if message is too old to edit (e.g., 15 minutes)
	editWindow := 15 * time.Minute
	if time.Since(message.CreatedAt) > editWindow {
		return nil, fmt.Errorf("message is too old to edit")
	}

	// Store original content if not already stored
	if !message.IsEdited {
		message.OriginalContent = message.EncryptedContent
	}

	// Encrypt the new content
	var encryptedContent string
	var encryptionVersion int
	if message.ChatRoom.Type == "direct" {
		encryptedContent, encryptionVersion, err = s.encryptDirectMessage(message.ChatRoomID, newContent, userID)
	} else {
		encryptedContent, encryptionVersion, err = s.encryptGroupMessage(message.ChatRoomID, newContent)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt message: %v", err)
	}

	// Update the message
	now := time.Now()
	message.EncryptedContent = encryptedContent
	message.EncryptionVersion = encryptionVersion
	message.IsEdited = true
	message.EditedAt = &now

	err = facades.Orm().Query().Save(&message)
	if err != nil {
		return nil, fmt.Errorf("failed to update message: %v", err)
	}

	return &message, nil
}

// DeleteMessage deletes a message
func (s *ChatService) DeleteMessage(messageID, userID string) error {
	// Get the message
	var message models.ChatMessage
	err := facades.Orm().Query().Where("id", messageID).First(&message)
	if err != nil {
		return fmt.Errorf("message not found: %v", err)
	}

	// Check if user is the sender or admin
	if message.SenderID != userID {
		// Check if user is admin of the room
		var member models.ChatRoomMember
		err = facades.Orm().Query().Where("chat_room_id", message.ChatRoomID).Where("user_id", userID).Where("role", "admin").First(&member)
		if err != nil {
			return fmt.Errorf("user can only delete their own messages or must be admin")
		}
	}

	// Soft delete the message
	_, err = facades.Orm().Query().Delete(&message)
	if err != nil {
		return fmt.Errorf("failed to delete message: %v", err)
	}

	return nil
}

// CreateThread creates a new message thread
func (s *ChatService) CreateThread(roomID, rootMessageID, title string, userID string) (*models.MessageThread, error) {
	// Check if user is a member of the room
	var member models.ChatRoomMember
	err := facades.Orm().Query().Where("chat_room_id", roomID).Where("user_id", userID).Where("is_active", true).First(&member)
	if err != nil {
		return nil, fmt.Errorf("user is not a member of this room")
	}

	// Check if root message exists
	var rootMessage models.ChatMessage
	err = facades.Orm().Query().Where("id", rootMessageID).Where("chat_room_id", roomID).First(&rootMessage)
	if err != nil {
		return nil, fmt.Errorf("root message not found")
	}

	// Create the thread
	thread := &models.MessageThread{
		ChatRoomID:    roomID,
		RootMessageID: rootMessageID,
		Title:         title,
		MessageCount:  1, // Root message counts as first message
		IsResolved:    false,
	}

	err = facades.Orm().Query().Create(thread)
	if err != nil {
		return nil, fmt.Errorf("failed to create thread: %v", err)
	}

	// Update the root message to be part of this thread
	rootMessage.ThreadID = &thread.ID
	err = facades.Orm().Query().Save(&rootMessage)
	if err != nil {
		return nil, fmt.Errorf("failed to update root message: %v", err)
	}

	return thread, nil
}

// GetThread retrieves a thread with its messages
func (s *ChatService) GetThread(threadID, userID string) (*models.MessageThread, error) {
	var thread models.MessageThread
	err := facades.Orm().Query().Where("id", threadID).First(&thread)
	if err != nil {
		return nil, fmt.Errorf("thread not found: %v", err)
	}

	// Check if user is a member of the room
	var member models.ChatRoomMember
	err = facades.Orm().Query().Where("chat_room_id", thread.ChatRoomID).Where("user_id", userID).Where("is_active", true).First(&member)
	if err != nil {
		return nil, fmt.Errorf("user is not a member of this room")
	}

	// Load messages in the thread
	var messages []models.ChatMessage
	err = facades.Orm().Query().Where("thread_id", threadID).Order("created_at ASC").Find(&messages)
	if err != nil {
		return nil, fmt.Errorf("failed to load thread messages: %v", err)
	}

	thread.Messages = messages

	return &thread, nil
}

// GetRoomThreads retrieves all threads in a room
func (s *ChatService) GetRoomThreads(roomID, userID string, limit int, offset int) ([]models.MessageThread, error) {
	// Check if user is a member of the room
	var member models.ChatRoomMember
	err := facades.Orm().Query().Where("chat_room_id", roomID).Where("user_id", userID).Where("is_active", true).First(&member)
	if err != nil {
		return nil, fmt.Errorf("user is not a member of this room")
	}

	var threads []models.MessageThread
	err = facades.Orm().Query().Where("chat_room_id", roomID).Order("last_activity_at DESC").Limit(limit).Offset(offset).Find(&threads)
	if err != nil {
		return nil, fmt.Errorf("failed to load threads: %v", err)
	}

	return threads, nil
}

// ResolveThread resolves a thread
func (s *ChatService) ResolveThread(threadID, userID string, note string) (*models.MessageThread, error) {
	var thread models.MessageThread
	err := facades.Orm().Query().Where("id", threadID).First(&thread)
	if err != nil {
		return nil, fmt.Errorf("thread not found: %v", err)
	}

	// Check if user is a member of the room
	var member models.ChatRoomMember
	err = facades.Orm().Query().Where("chat_room_id", thread.ChatRoomID).Where("user_id", userID).Where("is_active", true).First(&member)
	if err != nil {
		return nil, fmt.Errorf("user is not a member of this room")
	}

	// Update thread
	now := time.Now()
	thread.IsResolved = true
	thread.ResolvedBy = &userID
	thread.ResolvedAt = &now

	err = facades.Orm().Query().Save(&thread)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve thread: %v", err)
	}

	return &thread, nil
}

// GetNotificationSettings retrieves notification settings for a user and room
func (s *ChatService) GetNotificationSettings(userID, roomID string) (*models.ChatNotificationSettings, error) {
	var settings models.ChatNotificationSettings
	err := facades.Orm().Query().Where("user_id", userID).Where("chat_room_id", roomID).First(&settings)
	if err != nil {
		// Return default settings if not found
		return &models.ChatNotificationSettings{
			UserID:                userID,
			ChatRoomID:            &roomID,
			EmailNotifications:    true,
			PushNotifications:     true,
			DesktopNotifications:  true,
			MentionNotifications:  true,
			ReactionNotifications: true,
			ThreadNotifications:   true,
			IsMuted:               false,
		}, nil
	}

	return &settings, nil
}

// UpdateNotificationSettings updates notification settings for a user and room
func (s *ChatService) UpdateNotificationSettings(userID, roomID string, settings *models.ChatNotificationSettings) (*models.ChatNotificationSettings, error) {
	// Check if settings exist
	var existingSettings models.ChatNotificationSettings
	err := facades.Orm().Query().Where("user_id", userID).Where("chat_room_id", roomID).First(&existingSettings)
	if err != nil {
		// Create new settings
		settings.UserID = userID
		settings.ChatRoomID = &roomID
		err = facades.Orm().Query().Create(settings)
		if err != nil {
			return nil, fmt.Errorf("failed to create notification settings: %v", err)
		}
		return settings, nil
	}

	// Update existing settings
	if settings.EmailNotifications != existingSettings.EmailNotifications {
		existingSettings.EmailNotifications = settings.EmailNotifications
	}
	if settings.PushNotifications != existingSettings.PushNotifications {
		existingSettings.PushNotifications = settings.PushNotifications
	}
	if settings.DesktopNotifications != existingSettings.DesktopNotifications {
		existingSettings.DesktopNotifications = settings.DesktopNotifications
	}
	if settings.MentionNotifications != existingSettings.MentionNotifications {
		existingSettings.MentionNotifications = settings.MentionNotifications
	}
	if settings.ReactionNotifications != existingSettings.ReactionNotifications {
		existingSettings.ReactionNotifications = settings.ReactionNotifications
	}
	if settings.ThreadNotifications != existingSettings.ThreadNotifications {
		existingSettings.ThreadNotifications = settings.ThreadNotifications
	}
	if settings.IsMuted != existingSettings.IsMuted {
		existingSettings.IsMuted = settings.IsMuted
	}
	if settings.MuteUntil != nil {
		existingSettings.MuteUntil = settings.MuteUntil
	}
	if settings.CustomSettings != "" {
		existingSettings.CustomSettings = settings.CustomSettings
	}

	err = facades.Orm().Query().Save(&existingSettings)
	if err != nil {
		return nil, fmt.Errorf("failed to update notification settings: %v", err)
	}

	return &existingSettings, nil
}

// GetGlobalNotificationSettings retrieves global notification settings for a user
func (s *ChatService) GetGlobalNotificationSettings(userID string) (*models.ChatNotificationSettings, error) {
	var settings models.ChatNotificationSettings
	err := facades.Orm().Query().Where("user_id", userID).Where("chat_room_id IS NULL").First(&settings)
	if err != nil {
		// Return default settings if not found
		return &models.ChatNotificationSettings{
			UserID:                userID,
			EmailNotifications:    true,
			PushNotifications:     true,
			DesktopNotifications:  true,
			MentionNotifications:  true,
			ReactionNotifications: true,
			ThreadNotifications:   true,
			IsMuted:               false,
		}, nil
	}

	return &settings, nil
}

// UpdateGlobalNotificationSettings updates global notification settings for a user
func (s *ChatService) UpdateGlobalNotificationSettings(userID string, settings *models.ChatNotificationSettings) (*models.ChatNotificationSettings, error) {
	// Check if settings exist
	var existingSettings models.ChatNotificationSettings
	err := facades.Orm().Query().Where("user_id", userID).Where("chat_room_id IS NULL").First(&existingSettings)
	if err != nil {
		// Create new settings
		settings.UserID = userID
		err = facades.Orm().Query().Create(settings)
		if err != nil {
			return nil, fmt.Errorf("failed to create global notification settings: %v", err)
		}
		return settings, nil
	}

	// Update existing settings
	if settings.EmailNotifications != existingSettings.EmailNotifications {
		existingSettings.EmailNotifications = settings.EmailNotifications
	}
	if settings.PushNotifications != existingSettings.PushNotifications {
		existingSettings.PushNotifications = settings.PushNotifications
	}
	if settings.DesktopNotifications != existingSettings.DesktopNotifications {
		existingSettings.DesktopNotifications = settings.DesktopNotifications
	}
	if settings.MentionNotifications != existingSettings.MentionNotifications {
		existingSettings.MentionNotifications = settings.MentionNotifications
	}
	if settings.ReactionNotifications != existingSettings.ReactionNotifications {
		existingSettings.ReactionNotifications = settings.ReactionNotifications
	}
	if settings.ThreadNotifications != existingSettings.ThreadNotifications {
		existingSettings.ThreadNotifications = settings.ThreadNotifications
	}
	if settings.CustomSettings != "" {
		existingSettings.CustomSettings = settings.CustomSettings
	}

	err = facades.Orm().Query().Save(&existingSettings)
	if err != nil {
		return nil, fmt.Errorf("failed to update global notification settings: %v", err)
	}

	return &existingSettings, nil
}

// Public wrapper methods for encryption - used by WebSocket controller

// EncryptMessage encrypts a message for a room using appropriate encryption method
func (s *ChatService) EncryptMessage(roomID, content, senderID string, isGroup bool) (string, int, error) {
	if isGroup {
		return s.encryptGroupMessage(roomID, content)
	}
	return s.encryptDirectMessage(roomID, content, senderID)
}

// DecryptMessage decrypts a message for a user
func (s *ChatService) DecryptMessage(message *models.ChatMessage, userID string) (string, error) {
	return s.decryptMessage(message, userID)
}

// IsE2EEEnabled checks if E2EE is enabled for a room
func (s *ChatService) IsE2EEEnabled(roomID string) (bool, error) {
	keyCount, err := facades.Orm().Query().
		Model(&models.ChatRoomKey{}).
		Where("chat_room_id = ? AND is_active = ?", roomID, true).
		Count()

	if err != nil {
		return false, fmt.Errorf("failed to check E2EE status: %v", err)
	}

	return keyCount > 0, nil
}

// GetRoomEncryptionVersion gets the current encryption version for a room
func (s *ChatService) GetRoomEncryptionVersion(roomID string) (int, error) {
	var roomKey models.ChatRoomKey
	err := facades.Orm().Query().
		Where("chat_room_id = ? AND is_active = ?", roomID, true).
		OrderBy("version DESC").
		First(&roomKey)

	if err != nil {
		return 0, fmt.Errorf("failed to get encryption version: %v", err)
	}

	return roomKey.Version, nil
}
