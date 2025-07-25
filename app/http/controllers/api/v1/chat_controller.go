package v1

import (
	"encoding/json"
	"time"

	"github.com/goravel/framework/contracts/http"

	"goravel/app/helpers"
	"goravel/app/http/requests"
	"goravel/app/http/responses"
	"goravel/app/models"
	"goravel/app/services"
)

type ChatController struct {
	chatService *services.ChatService
	e2eeService *services.E2EEService
}

func NewChatController() *ChatController {
	return &ChatController{
		chatService: services.NewChatService(),
		e2eeService: services.NewE2EEService(),
	}
}

// CreateChatRoom creates a new chat room
// @Summary Create a new chat room
// @Description Create a new chat room with specified members
// @Tags chat
// @Accept json
// @Produce json
// @Param request body requests.CreateChatRoomRequest true "Chat room creation request"
// @Success 201 {object} responses.APIResponse{data=models.ChatRoom}
// @Failure 400 {object} responses.ErrorResponse
// @Failure 500 {object} responses.ErrorResponse
// @Router /chat/rooms [post]
func (cc *ChatController) CreateChatRoom(ctx http.Context) http.Response {
	var req requests.CreateChatRoomRequest
	if err := ctx.Request().Bind(&req); err != nil {
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Invalid request data",
			Timestamp: time.Now(),
		})
	}

	// Get current user
	user := ctx.Value("user").(*models.User)
	tenantID := ctx.Value("tenant_id").(string)

	// Create chat room
	chatRoom, err := cc.chatService.CreateChatRoom(
		req.Name,
		req.Description,
		req.Type,
		tenantID,
		user.ID,
		req.MemberIDs,
	)
	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to create chat room: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Status(201).Json(responses.APIResponse{
		Status:    "success",
		Message:   "Chat room created successfully",
		Data:      chatRoom,
		Timestamp: time.Now(),
	})
}

// GetChatRooms retrieves all chat rooms for the current user
// @Summary Get user's chat rooms
// @Description Retrieve all chat rooms where the current user is a member
// @Tags chat
// @Accept json
// @Produce json
// @Success 200 {object} responses.APIResponse{data=[]models.ChatRoom}
// @Failure 500 {object} responses.ErrorResponse
// @Router /chat/rooms [get]
func (cc *ChatController) GetChatRooms(ctx http.Context) http.Response {
	user := ctx.Value("user").(*models.User)
	tenantID := ctx.Value("tenant_id").(string)

	chatRooms, err := cc.chatService.GetUserChatRooms(user.ID, tenantID)
	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to retrieve chat rooms: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Message:   "Chat rooms retrieved successfully",
		Data:      chatRooms,
		Timestamp: time.Now(),
	})
}

// GetChatRoom retrieves a specific chat room
// @Summary Get chat room by ID
// @Description Retrieve a specific chat room by its ID
// @Tags chat
// @Accept json
// @Produce json
// @Param id path string true "Chat room ID"
// @Success 200 {object} responses.APIResponse{data=models.ChatRoom}
// @Failure 404 {object} responses.ErrorResponse
// @Failure 500 {object} responses.ErrorResponse
// @Router /chat/rooms/{id} [get]
func (cc *ChatController) GetChatRoom(ctx http.Context) http.Response {
	roomID := ctx.Request().Route("id")
	user := ctx.Value("user").(*models.User)

	chatRoom, err := cc.chatService.GetChatRoom(roomID, user.ID)
	if err != nil {
		status := 500
		if err.Error() == "chat room not found" || err.Error() == "user is not a member of this room" {
			status = 404
		}
		return ctx.Response().Status(status).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   err.Error(),
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Message:   "Chat room retrieved successfully",
		Data:      chatRoom,
		Timestamp: time.Now(),
	})
}

// UpdateChatRoom updates a chat room
// @Summary Update chat room
// @Description Update a chat room's information (admin only)
// @Tags chat
// @Accept json
// @Produce json
// @Param id path string true "Chat room ID"
// @Param request body requests.UpdateChatRoomRequest true "Chat room update request"
// @Success 200 {object} responses.APIResponse{data=models.ChatRoom}
// @Failure 400 {object} responses.ErrorResponse
// @Failure 403 {object} responses.ErrorResponse
// @Failure 500 {object} responses.ErrorResponse
// @Router /chat/rooms/{id} [put]
func (cc *ChatController) UpdateChatRoom(ctx http.Context) http.Response {
	roomID := ctx.Request().Route("id")
	user := ctx.Value("user").(*models.User)

	var req requests.UpdateChatRoomRequest
	if err := ctx.Request().Bind(&req); err != nil {
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Invalid request data",
			Timestamp: time.Now(),
		})
	}

	chatRoom, err := cc.chatService.UpdateRoom(roomID, req.Name, req.Description, user.ID)
	if err != nil {
		status := 500
		if err.Error() == "user is not an admin of this room" {
			status = 403
		} else if err.Error() == "chat room not found" {
			status = 404
		}
		return ctx.Response().Status(status).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   err.Error(),
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Message:   "Chat room updated successfully",
		Data:      chatRoom,
		Timestamp: time.Now(),
	})
}

// DeleteChatRoom deletes a chat room
// @Summary Delete chat room
// @Description Delete a chat room (admin only)
// @Tags chat
// @Accept json
// @Produce json
// @Param id path string true "Chat room ID"
// @Success 200 {object} responses.APIResponse
// @Failure 403 {object} responses.ErrorResponse
// @Failure 500 {object} responses.ErrorResponse
// @Router /chat/rooms/{id} [delete]
func (cc *ChatController) DeleteChatRoom(ctx http.Context) http.Response {
	roomID := ctx.Request().Route("id")
	user := ctx.Value("user").(*models.User)

	err := cc.chatService.DeleteRoom(roomID, user.ID)
	if err != nil {
		status := 500
		if err.Error() == "user is not an admin of this room" {
			status = 403
		} else if err.Error() == "chat room not found" {
			status = 404
		}
		return ctx.Response().Status(status).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   err.Error(),
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Message:   "Chat room deleted successfully",
		Timestamp: time.Now(),
	})
}

// SendMessage sends a message to a chat room
// @Summary Send message
// @Description Send a message to a chat room
// @Tags chat
// @Accept json
// @Produce json
// @Param id path string true "Chat room ID"
// @Param request body requests.SendMessageRequest true "Message request"
// @Success 201 {object} responses.APIResponse{data=models.ChatMessage}
// @Failure 400 {object} responses.ErrorResponse
// @Failure 500 {object} responses.ErrorResponse
// @Router /chat/rooms/{id}/messages [post]
func (cc *ChatController) SendMessage(ctx http.Context) http.Response {
	roomID := ctx.Request().Route("id")
	user := ctx.Value("user").(*models.User)

	var req requests.SendMessageRequest
	if err := ctx.Request().Bind(&req); err != nil {
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Invalid request data",
			Timestamp: time.Now(),
		})
	}

	var replyToID *string
	if req.ReplyToID != "" {
		replyToID = &req.ReplyToID
	}

	message, err := cc.chatService.SendMessage(
		roomID,
		user.ID,
		req.Type,
		req.Content,
		req.Metadata,
		replyToID,
	)
	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to send message: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Status(201).Json(responses.APIResponse{
		Status:    "success",
		Message:   "Message sent successfully",
		Data:      message,
		Timestamp: time.Now(),
	})
}

// GetMessages retrieves messages from a chat room
// @Summary Get messages
// @Description Retrieve messages from a chat room with pagination
// @Tags chat
// @Accept json
// @Produce json
// @Param id path string true "Chat room ID"
// @Param cursor query string false "Cursor for pagination"
// @Param limit query int false "Items per page" default(50)
// @Success 200 {object} responses.PaginatedResponse{data=[]models.ChatMessage}
// @Failure 500 {object} responses.ErrorResponse
// @Router /chat/rooms/{id}/messages [get]
func (cc *ChatController) GetMessages(ctx http.Context) http.Response {
	roomID := ctx.Request().Route("id")
	user := ctx.Value("user").(*models.User)
	cursor := ctx.Request().Input("cursor", "")
	limit := ctx.Request().InputInt("limit", 50)

	var beforeID *string
	if cursor != "" {
		beforeID = &cursor
	}

	messages, err := cc.chatService.GetMessages(roomID, user.ID, limit, beforeID)
	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to retrieve messages: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	// Check if there are more results
	hasMore := len(messages) > limit
	if hasMore {
		messages = messages[:limit] // Remove the extra item
	}

	// Build pagination info
	paginationInfo := helpers.BuildPaginationInfo(messages, limit, cursor, hasMore)

	return ctx.Response().Success().Json(responses.PaginatedResponse{
		Status: "success",
		Data:   messages,
		Pagination: responses.PaginationInfo{
			NextCursor: getStringValue(paginationInfo, "next_cursor"),
			PrevCursor: getStringValue(paginationInfo, "prev_cursor"),
			HasMore:    getBoolValue(paginationInfo, "has_more"),
			HasPrev:    getBoolValue(paginationInfo, "has_prev"),
			Count:      getIntValue(paginationInfo, "count"),
			Limit:      getIntValue(paginationInfo, "limit"),
		},
		Timestamp: time.Now(),
	})
}

// MarkRoomAsRead marks all messages in a room as read
// @Summary Mark room as read
// @Description Mark all messages in a chat room as read by the current user
// @Tags chat
// @Accept json
// @Produce json
// @Param id path string true "Chat room ID"
// @Success 200 {object} responses.APIResponse
// @Failure 500 {object} responses.ErrorResponse
// @Router /chat/rooms/{id}/read [post]
func (cc *ChatController) MarkRoomAsRead(ctx http.Context) http.Response {
	roomID := ctx.Request().Route("id")
	user := ctx.Value("user").(*models.User)

	err := cc.chatService.MarkRoomAsRead(roomID, user.ID)
	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to mark room as read: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Message:   "Room marked as read successfully",
		Timestamp: time.Now(),
	})
}

// GetRoomMembers retrieves all members of a chat room
// @Summary Get room members
// @Description Retrieve all members of a chat room
// @Tags chat
// @Accept json
// @Produce json
// @Param id path string true "Chat room ID"
// @Success 200 {object} responses.APIResponse{data=[]models.ChatRoomMember}
// @Failure 500 {object} responses.ErrorResponse
// @Router /chat/rooms/{id}/members [get]
func (cc *ChatController) GetRoomMembers(ctx http.Context) http.Response {
	roomID := ctx.Request().Route("id")

	members, err := cc.chatService.GetRoomMembers(roomID)
	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to retrieve room members: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Message:   "Room members retrieved successfully",
		Data:      members,
		Timestamp: time.Now(),
	})
}

// AddMember adds a member to a chat room
// @Summary Add member to room
// @Description Add a new member to a chat room (admin only)
// @Tags chat
// @Accept json
// @Produce json
// @Param id path string true "Chat room ID"
// @Param request body requests.AddMemberRequest true "Add member request"
// @Success 200 {object} responses.APIResponse
// @Failure 400 {object} responses.ErrorResponse
// @Failure 403 {object} responses.ErrorResponse
// @Failure 500 {object} responses.ErrorResponse
// @Router /chat/rooms/{id}/members [post]
func (cc *ChatController) AddMember(ctx http.Context) http.Response {
	roomID := ctx.Request().Route("id")
	tenantID := ctx.Value("tenant_id").(string)

	var req requests.AddMemberRequest
	if err := ctx.Request().Bind(&req); err != nil {
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Invalid request data",
			Timestamp: time.Now(),
		})
	}

	err := cc.chatService.AddMemberToRoom(roomID, req.UserID, req.Role, tenantID)
	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to add member: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Message:   "Member added successfully",
		Timestamp: time.Now(),
	})
}

// RemoveMember removes a member from a chat room
// @Summary Remove member from room
// @Description Remove a member from a chat room (admin only)
// @Tags chat
// @Accept json
// @Produce json
// @Param id path string true "Chat room ID"
// @Param user_id path string true "User ID to remove"
// @Success 200 {object} responses.APIResponse
// @Failure 403 {object} responses.ErrorResponse
// @Failure 500 {object} responses.ErrorResponse
// @Router /chat/rooms/{id}/members/{user_id} [delete]
func (cc *ChatController) RemoveMember(ctx http.Context) http.Response {
	roomID := ctx.Request().Route("id")
	userID := ctx.Request().Route("user_id")

	err := cc.chatService.RemoveMemberFromRoom(roomID, userID)
	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to remove member: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Message:   "Member removed successfully",
		Timestamp: time.Now(),
	})
}

// GenerateKeyPair generates encryption keys for the current user
// @Summary Generate encryption keys
// @Description Generate new encryption keys for the current user
// @Tags chat
// @Accept json
// @Produce json
// @Param request body requests.GenerateKeyPairRequest true "Key generation request"
// @Success 201 {object} responses.APIResponse{data=services.KeyPair}
// @Failure 400 {object} responses.ErrorResponse
// @Failure 500 {object} responses.ErrorResponse
// @Router /chat/keys [post]
func (cc *ChatController) GenerateKeyPair(ctx http.Context) http.Response {
	user := ctx.Value("user").(*models.User)

	var req requests.GenerateKeyPairRequest
	if err := ctx.Request().Bind(&req); err != nil {
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Invalid request data",
			Timestamp: time.Now(),
		})
	}

	keyPair, err := cc.e2eeService.GenerateKeyPair()
	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to generate key pair: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	// Generate a passphrase for encrypting the private key (in production, this could be derived from user password)
	passphrase := user.ID + "_key_passphrase" // Simple approach - in production use proper key derivation

	// Encrypt the private key before storage
	e2eeService := services.NewE2EEService()
	encryptedPrivateKey, err := e2eeService.EncryptPrivateKey(keyPair.PrivateKey, passphrase)
	if err != nil {
		return responses.CreateErrorResponse(ctx, "Failed to encrypt private key", err.Error(), 500)
	}

	// Save the key pair to database
	userKey := &models.UserKey{
		UserID:              user.ID,
		KeyType:             req.KeyType,
		PublicKey:           keyPair.PublicKey,
		EncryptedPrivateKey: encryptedPrivateKey, // Now properly encrypted
		Version:             1,
		IsActive:            true,
	}

	err = cc.e2eeService.SaveUserKey(userKey)
	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to save key pair: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Status(201).Json(responses.APIResponse{
		Status:    "success",
		Message:   "Key pair generated successfully",
		Data:      keyPair,
		Timestamp: time.Now(),
	})
}

// GetUserKeys retrieves all keys for the current user
// @Summary Get user keys
// @Description Retrieve all encryption keys for the current user
// @Tags chat
// @Accept json
// @Produce json
// @Success 200 {object} responses.APIResponse{data=[]models.UserKey}
// @Failure 500 {object} responses.ErrorResponse
// @Router /chat/keys [get]
func (cc *ChatController) GetUserKeys(ctx http.Context) http.Response {
	user := ctx.Value("user").(*models.User)

	keys, err := cc.e2eeService.GetUserKeys(user.ID)
	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to retrieve user keys: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Message:   "User keys retrieved successfully",
		Data:      keys,
		Timestamp: time.Now(),
	})
}

// RotateRoomKey rotates the encryption key for a chat room
// @Summary Rotate room key
// @Description Rotate the encryption key for a chat room (admin only)
// @Tags chat
// @Accept json
// @Produce json
// @Param id path string true "Chat room ID"
// @Success 200 {object} responses.APIResponse
// @Failure 403 {object} responses.ErrorResponse
// @Failure 500 {object} responses.ErrorResponse
// @Router /chat/rooms/{id}/rotate-key [post]
func (cc *ChatController) RotateRoomKey(ctx http.Context) http.Response {
	roomID := ctx.Request().Route("id")

	err := cc.e2eeService.RotateRoomKey(roomID)
	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to rotate room key: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Message:   "Room key rotated successfully",
		Timestamp: time.Now(),
	})
}

// AddMessageReaction adds a reaction to a message
// @Summary Add message reaction
// @Description Add an emoji reaction to a message
// @Tags chat
// @Accept json
// @Produce json
// @Param id path string true "Chat room ID"
// @Param message_id path string true "Message ID"
// @Param request body requests.AddReactionRequest true "Reaction request"
// @Success 201 {object} responses.APIResponse{data=models.MessageReaction}
// @Failure 400 {object} responses.ErrorResponse
// @Failure 500 {object} responses.ErrorResponse
// @Router /chat/rooms/{id}/messages/{message_id}/reactions [post]
func (cc *ChatController) AddMessageReaction(ctx http.Context) http.Response {
	messageID := ctx.Request().Route("message_id")
	user := ctx.Value("user").(*models.User)

	var req requests.AddReactionRequest
	if err := ctx.Request().Bind(&req); err != nil {
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Invalid request data",
			Timestamp: time.Now(),
		})
	}

	reaction, err := cc.chatService.AddMessageReaction(messageID, user.ID, req.Emoji)
	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to add reaction: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Status(201).Json(responses.APIResponse{
		Status:    "success",
		Message:   "Reaction added successfully",
		Data:      reaction,
		Timestamp: time.Now(),
	})
}

// RemoveMessageReaction removes a reaction from a message
// @Summary Remove message reaction
// @Description Remove an emoji reaction from a message
// @Tags chat
// @Accept json
// @Produce json
// @Param id path string true "Chat room ID"
// @Param message_id path string true "Message ID"
// @Param request body requests.RemoveReactionRequest true "Reaction removal request"
// @Success 200 {object} responses.APIResponse
// @Failure 400 {object} responses.ErrorResponse
// @Failure 500 {object} responses.ErrorResponse
// @Router /chat/rooms/{id}/messages/{message_id}/reactions [delete]
func (cc *ChatController) RemoveMessageReaction(ctx http.Context) http.Response {
	messageID := ctx.Request().Route("message_id")
	user := ctx.Value("user").(*models.User)

	var req requests.RemoveReactionRequest
	if err := ctx.Request().Bind(&req); err != nil {
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Invalid request data",
			Timestamp: time.Now(),
		})
	}

	err := cc.chatService.RemoveMessageReaction(messageID, user.ID, req.Emoji)
	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to remove reaction: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Message:   "Reaction removed successfully",
		Timestamp: time.Now(),
	})
}

// GetMessageReactions retrieves all reactions for a message
// @Summary Get message reactions
// @Description Retrieve all reactions for a specific message
// @Tags chat
// @Accept json
// @Produce json
// @Param id path string true "Chat room ID"
// @Param message_id path string true "Message ID"
// @Success 200 {object} responses.APIResponse{data=[]models.MessageReaction}
// @Failure 500 {object} responses.ErrorResponse
// @Router /chat/rooms/{id}/messages/{message_id}/reactions [get]
func (cc *ChatController) GetMessageReactions(ctx http.Context) http.Response {
	messageID := ctx.Request().Route("message_id")

	reactions, err := cc.chatService.GetMessageReactions(messageID)
	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to retrieve reactions: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Message:   "Reactions retrieved successfully",
		Data:      reactions,
		Timestamp: time.Now(),
	})
}

// GetReactionSummary gets a summary of reactions for a message
// @Summary Get reaction summary
// @Description Get a summary of reactions grouped by emoji
// @Tags chat
// @Accept json
// @Produce json
// @Param id path string true "Chat room ID"
// @Param message_id path string true "Message ID"
// @Success 200 {object} responses.APIResponse{data=map[string]int}
// @Failure 500 {object} responses.ErrorResponse
// @Router /chat/rooms/{id}/messages/{message_id}/reactions/summary [get]
func (cc *ChatController) GetReactionSummary(ctx http.Context) http.Response {
	messageID := ctx.Request().Route("message_id")

	summary, err := cc.chatService.GetReactionSummary(messageID)
	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to retrieve reaction summary: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Message:   "Reaction summary retrieved successfully",
		Data:      summary,
		Timestamp: time.Now(),
	})
}

// EditMessage edits a message
// @Summary Edit message
// @Description Edit a message (only sender can edit within 15 minutes)
// @Tags chat
// @Accept json
// @Produce json
// @Param id path string true "Chat room ID"
// @Param message_id path string true "Message ID"
// @Param request body requests.EditMessageRequest true "Edit message request"
// @Success 200 {object} responses.APIResponse{data=models.ChatMessage}
// @Failure 400 {object} responses.ErrorResponse
// @Failure 403 {object} responses.ErrorResponse
// @Failure 500 {object} responses.ErrorResponse
// @Router /chat/rooms/{id}/messages/{message_id} [put]
func (cc *ChatController) EditMessage(ctx http.Context) http.Response {
	messageID := ctx.Request().Route("message_id")
	user := ctx.Value("user").(*models.User)

	var req requests.EditMessageRequest
	if err := ctx.Request().Bind(&req); err != nil {
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Invalid request data",
			Timestamp: time.Now(),
		})
	}

	message, err := cc.chatService.EditMessage(messageID, user.ID, req.Content)
	if err != nil {
		status := 500
		if err.Error() == "user can only edit their own messages" {
			status = 403
		} else if err.Error() == "message is too old to edit" {
			status = 400
		} else if err.Error() == "message not found" {
			status = 404
		}
		return ctx.Response().Status(status).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   err.Error(),
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Message:   "Message edited successfully",
		Data:      message,
		Timestamp: time.Now(),
	})
}

// DeleteMessage deletes a message
// @Summary Delete message
// @Description Delete a message (sender or admin only)
// @Tags chat
// @Accept json
// @Produce json
// @Param id path string true "Chat room ID"
// @Param message_id path string true "Message ID"
// @Success 200 {object} responses.APIResponse
// @Failure 403 {object} responses.ErrorResponse
// @Failure 500 {object} responses.ErrorResponse
// @Router /chat/rooms/{id}/messages/{message_id} [delete]
func (cc *ChatController) DeleteMessage(ctx http.Context) http.Response {
	messageID := ctx.Request().Route("message_id")
	user := ctx.Value("user").(*models.User)

	err := cc.chatService.DeleteMessage(messageID, user.ID)
	if err != nil {
		status := 500
		if err.Error() == "user can only delete their own messages or must be admin" {
			status = 403
		} else if err.Error() == "message not found" {
			status = 404
		}
		return ctx.Response().Status(status).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   err.Error(),
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Message:   "Message deleted successfully",
		Timestamp: time.Now(),
	})
}

// CreateThread creates a new message thread
// @Summary Create thread
// @Description Create a new message thread from a root message
// @Tags chat
// @Accept json
// @Produce json
// @Param id path string true "Chat room ID"
// @Param message_id path string true "Root message ID"
// @Param request body requests.CreateThreadRequest true "Create thread request"
// @Success 201 {object} responses.APIResponse{data=models.MessageThread}
// @Failure 400 {object} responses.ErrorResponse
// @Failure 500 {object} responses.ErrorResponse
// @Router /chat/rooms/{id}/messages/{message_id}/threads [post]
func (cc *ChatController) CreateThread(ctx http.Context) http.Response {
	roomID := ctx.Request().Route("id")
	messageID := ctx.Request().Route("message_id")
	user := ctx.Value("user").(*models.User)

	var req requests.CreateThreadRequest
	if err := ctx.Request().Bind(&req); err != nil {
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Invalid request data",
			Timestamp: time.Now(),
		})
	}

	thread, err := cc.chatService.CreateThread(roomID, messageID, req.Title, user.ID)
	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to create thread: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Status(201).Json(responses.APIResponse{
		Status:    "success",
		Message:   "Thread created successfully",
		Data:      thread,
		Timestamp: time.Now(),
	})
}

// GetThread retrieves a thread with its messages
// @Summary Get thread
// @Description Retrieve a thread with all its messages
// @Tags chat
// @Accept json
// @Produce json
// @Param thread_id path string true "Thread ID"
// @Success 200 {object} responses.APIResponse{data=models.MessageThread}
// @Failure 404 {object} responses.ErrorResponse
// @Failure 500 {object} responses.ErrorResponse
// @Router /chat/threads/{thread_id} [get]
func (cc *ChatController) GetThread(ctx http.Context) http.Response {
	threadID := ctx.Request().Route("thread_id")
	user := ctx.Value("user").(*models.User)

	thread, err := cc.chatService.GetThread(threadID, user.ID)
	if err != nil {
		status := 500
		if err.Error() == "thread not found" || err.Error() == "user is not a member of this room" {
			status = 404
		}
		return ctx.Response().Status(status).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   err.Error(),
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Message:   "Thread retrieved successfully",
		Data:      thread,
		Timestamp: time.Now(),
	})
}

// GetRoomThreads retrieves all threads in a room
// @Summary Get room threads
// @Description Retrieve all threads in a chat room
// @Tags chat
// @Accept json
// @Produce json
// @Param id path string true "Chat room ID"
// @Param limit query int false "Items per page" default(20)
// @Param offset query int false "Offset for pagination" default(0)
// @Success 200 {object} responses.APIResponse{data=[]models.MessageThread}
// @Failure 500 {object} responses.ErrorResponse
// @Router /chat/rooms/{id}/threads [get]
func (cc *ChatController) GetRoomThreads(ctx http.Context) http.Response {
	roomID := ctx.Request().Route("id")
	user := ctx.Value("user").(*models.User)
	limit := ctx.Request().InputInt("limit", 20)
	offset := ctx.Request().InputInt("offset", 0)

	threads, err := cc.chatService.GetRoomThreads(roomID, user.ID, limit, offset)
	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to retrieve threads: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Message:   "Threads retrieved successfully",
		Data:      threads,
		Timestamp: time.Now(),
	})
}

// ResolveThread resolves a thread
// @Summary Resolve thread
// @Description Mark a thread as resolved
// @Tags chat
// @Accept json
// @Produce json
// @Param thread_id path string true "Thread ID"
// @Param request body requests.ResolveThreadRequest true "Resolve thread request"
// @Success 200 {object} responses.APIResponse{data=models.MessageThread}
// @Failure 400 {object} responses.ErrorResponse
// @Failure 500 {object} responses.ErrorResponse
// @Router /chat/threads/{thread_id}/resolve [post]
func (cc *ChatController) ResolveThread(ctx http.Context) http.Response {
	threadID := ctx.Request().Route("thread_id")
	user := ctx.Value("user").(*models.User)

	var req requests.ResolveThreadRequest
	if err := ctx.Request().Bind(&req); err != nil {
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Invalid request data",
			Timestamp: time.Now(),
		})
	}

	thread, err := cc.chatService.ResolveThread(threadID, user.ID, req.Note)
	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to resolve thread: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Message:   "Thread resolved successfully",
		Data:      thread,
		Timestamp: time.Now(),
	})
}

// GetNotificationSettings retrieves notification settings for a room
// @Summary Get notification settings
// @Description Retrieve notification settings for the current user in a specific room
// @Tags chat
// @Accept json
// @Produce json
// @Param id path string true "Chat room ID"
// @Success 200 {object} responses.APIResponse{data=models.ChatNotificationSettings}
// @Failure 500 {object} responses.ErrorResponse
// @Router /chat/rooms/{id}/notifications [get]
func (cc *ChatController) GetNotificationSettings(ctx http.Context) http.Response {
	roomID := ctx.Request().Route("id")
	user := ctx.Value("user").(*models.User)

	settings, err := cc.chatService.GetNotificationSettings(user.ID, roomID)
	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to retrieve notification settings: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Message:   "Notification settings retrieved successfully",
		Data:      settings,
		Timestamp: time.Now(),
	})
}

// UpdateNotificationSettings updates notification settings for a room
// @Summary Update notification settings
// @Description Update notification settings for the current user in a specific room
// @Tags chat
// @Accept json
// @Produce json
// @Param id path string true "Chat room ID"
// @Param request body requests.UpdateNotificationSettingsRequest true "Update notification settings request"
// @Success 200 {object} responses.APIResponse{data=models.ChatNotificationSettings}
// @Failure 400 {object} responses.ErrorResponse
// @Failure 500 {object} responses.ErrorResponse
// @Router /chat/rooms/{id}/notifications [put]
func (cc *ChatController) UpdateNotificationSettings(ctx http.Context) http.Response {
	roomID := ctx.Request().Route("id")
	user := ctx.Value("user").(*models.User)

	var req requests.UpdateNotificationSettingsRequest
	if err := ctx.Request().Bind(&req); err != nil {
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Invalid request data",
			Timestamp: time.Now(),
		})
	}

	// Convert request to settings model
	settings := &models.ChatNotificationSettings{
		CustomSettings: "",
	}

	// Set boolean values with nil checks
	if req.EmailNotifications != nil {
		settings.EmailNotifications = *req.EmailNotifications
	}
	if req.PushNotifications != nil {
		settings.PushNotifications = *req.PushNotifications
	}
	if req.DesktopNotifications != nil {
		settings.DesktopNotifications = *req.DesktopNotifications
	}
	if req.MentionNotifications != nil {
		settings.MentionNotifications = *req.MentionNotifications
	}
	if req.ReactionNotifications != nil {
		settings.ReactionNotifications = *req.ReactionNotifications
	}
	if req.ThreadNotifications != nil {
		settings.ThreadNotifications = *req.ThreadNotifications
	}
	if req.IsMuted != nil {
		settings.IsMuted = *req.IsMuted
	}

	// Convert custom settings to JSON if provided
	if req.CustomSettings != nil {
		customSettingsJSON, err := json.Marshal(req.CustomSettings)
		if err == nil {
			settings.CustomSettings = string(customSettingsJSON)
		}
	}

	// Parse mute until if provided
	if req.MuteUntil != nil && *req.MuteUntil != "" {
		if muteTime, err := time.Parse(time.RFC3339, *req.MuteUntil); err == nil {
			settings.MuteUntil = &muteTime
		}
	}

	updatedSettings, err := cc.chatService.UpdateNotificationSettings(user.ID, roomID, settings)
	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to update notification settings: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Message:   "Notification settings updated successfully",
		Data:      updatedSettings,
		Timestamp: time.Now(),
	})
}

// GetGlobalNotificationSettings retrieves global notification settings
// @Summary Get global notification settings
// @Description Retrieve global notification settings for the current user
// @Tags chat
// @Accept json
// @Produce json
// @Success 200 {object} responses.APIResponse{data=models.ChatNotificationSettings}
// @Failure 500 {object} responses.ErrorResponse
// @Router /chat/notifications/global [get]
func (cc *ChatController) GetGlobalNotificationSettings(ctx http.Context) http.Response {
	user := ctx.Value("user").(*models.User)

	settings, err := cc.chatService.GetGlobalNotificationSettings(user.ID)
	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to retrieve global notification settings: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Message:   "Global notification settings retrieved successfully",
		Data:      settings,
		Timestamp: time.Now(),
	})
}

// UpdateGlobalNotificationSettings updates global notification settings
// @Summary Update global notification settings
// @Description Update global notification settings for the current user
// @Tags chat
// @Accept json
// @Produce json
// @Param request body requests.UpdateNotificationSettingsRequest true "Update global notification settings request"
// @Success 200 {object} responses.APIResponse{data=models.ChatNotificationSettings}
// @Failure 400 {object} responses.ErrorResponse
// @Failure 500 {object} responses.ErrorResponse
// @Router /chat/notifications/global [put]
func (cc *ChatController) UpdateGlobalNotificationSettings(ctx http.Context) http.Response {
	user := ctx.Value("user").(*models.User)

	var req requests.UpdateNotificationSettingsRequest
	if err := ctx.Request().Bind(&req); err != nil {
		return ctx.Response().Status(400).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Invalid request data",
			Timestamp: time.Now(),
		})
	}

	// Convert request to settings model
	settings := &models.ChatNotificationSettings{
		CustomSettings: "",
	}

	// Set boolean values with nil checks
	if req.EmailNotifications != nil {
		settings.EmailNotifications = *req.EmailNotifications
	}
	if req.PushNotifications != nil {
		settings.PushNotifications = *req.PushNotifications
	}
	if req.DesktopNotifications != nil {
		settings.DesktopNotifications = *req.DesktopNotifications
	}
	if req.MentionNotifications != nil {
		settings.MentionNotifications = *req.MentionNotifications
	}
	if req.ReactionNotifications != nil {
		settings.ReactionNotifications = *req.ReactionNotifications
	}
	if req.ThreadNotifications != nil {
		settings.ThreadNotifications = *req.ThreadNotifications
	}
	if req.IsMuted != nil {
		settings.IsMuted = *req.IsMuted
	}

	// Convert custom settings to JSON if provided
	if req.CustomSettings != nil {
		customSettingsJSON, err := json.Marshal(req.CustomSettings)
		if err == nil {
			settings.CustomSettings = string(customSettingsJSON)
		}
	}

	updatedSettings, err := cc.chatService.UpdateGlobalNotificationSettings(user.ID, settings)
	if err != nil {
		return ctx.Response().Status(500).Json(responses.ErrorResponse{
			Status:    "error",
			Message:   "Failed to update global notification settings: " + err.Error(),
			Timestamp: time.Now(),
		})
	}

	return ctx.Response().Success().Json(responses.APIResponse{
		Status:    "success",
		Message:   "Global notification settings updated successfully",
		Data:      updatedSettings,
		Timestamp: time.Now(),
	})
}
