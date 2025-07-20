package requests

import (
	"github.com/goravel/framework/contracts/http"
)

// CreateChatRoomRequest represents the request for creating a chat room
type CreateChatRoomRequest struct {
	// Room name
	Name string `form:"name" json:"name"`

	// Room description
	Description string `form:"description" json:"description"`

	// Room type (direct, group, channel)
	Type string `form:"type" json:"type"`

	// Room avatar
	Avatar string `form:"avatar" json:"avatar"`

	// Member IDs to add to the room
	MemberIDs []string `form:"member_ids" json:"member_ids"`
}

// Rules returns the validation rules for creating a chat room
func (r *CreateChatRoomRequest) Rules(ctx http.Context) map[string]string {
	return map[string]string{
		"name":         "required|string|max:255",
		"description":  "string|max:1000",
		"type":         "required|string|in:direct,group,channel",
		"avatar":       "string|max:500",
		"member_ids":   "array",
		"member_ids.*": "string|exists:users,id",
	}
}

// Messages returns the validation messages for creating a chat room
func (r *CreateChatRoomRequest) Messages(ctx http.Context) map[string]string {
	return map[string]string{
		"name.required":       "Room name is required",
		"name.max":            "Room name cannot exceed 255 characters",
		"description.max":     "Room description cannot exceed 1000 characters",
		"type.required":       "Room type is required",
		"type.in":             "Room type must be direct, group, or channel",
		"avatar.max":          "Avatar URL cannot exceed 500 characters",
		"member_ids.array":    "Member IDs must be an array",
		"member_ids.*.string": "Member ID must be a string",
		"member_ids.*.exists": "Member ID does not exist",
	}
}

// Attributes returns the validation attributes for creating a chat room
func (r *CreateChatRoomRequest) Attributes(ctx http.Context) map[string]string {
	return map[string]string{
		"name":        "room name",
		"description": "room description",
		"type":        "room type",
		"avatar":      "room avatar",
		"member_ids":  "member IDs",
	}
}

// UpdateChatRoomRequest represents the request for updating a chat room
type UpdateChatRoomRequest struct {
	// Room name
	Name string `form:"name" json:"name"`

	// Room description
	Description string `form:"description" json:"description"`

	// Room avatar
	Avatar string `form:"avatar" json:"avatar"`
}

// Rules returns the validation rules for updating a chat room
func (r *UpdateChatRoomRequest) Rules(ctx http.Context) map[string]string {
	return map[string]string{
		"name":        "required|string|max:255",
		"description": "string|max:1000",
		"avatar":      "string|max:500",
	}
}

// Messages returns the validation messages for updating a chat room
func (r *UpdateChatRoomRequest) Messages(ctx http.Context) map[string]string {
	return map[string]string{
		"name.required":   "Room name is required",
		"name.max":        "Room name cannot exceed 255 characters",
		"description.max": "Room description cannot exceed 1000 characters",
		"avatar.max":      "Avatar URL cannot exceed 500 characters",
	}
}

// Attributes returns the validation attributes for updating a chat room
func (r *UpdateChatRoomRequest) Attributes(ctx http.Context) map[string]string {
	return map[string]string{
		"name":        "room name",
		"description": "room description",
		"avatar":      "room avatar",
	}
}

// SendMessageRequest represents the request for sending a message
type SendMessageRequest struct {
	// Message content
	Content string `form:"content" json:"content"`

	// Message type (text, image, file, system)
	Type string `form:"type" json:"type"`

	// Message metadata
	Metadata map[string]interface{} `form:"metadata" json:"metadata"`

	// Reply to message ID
	ReplyToID string `form:"reply_to_id" json:"reply_to_id"`
}

// Rules returns the validation rules for sending a message
func (r *SendMessageRequest) Rules(ctx http.Context) map[string]string {
	return map[string]string{
		"content":     "required|string|max:10000",
		"type":        "required|string|in:text,image,file,system",
		"metadata":    "array",
		"reply_to_id": "string|exists:chat_messages,id",
	}
}

// Messages returns the validation messages for sending a message
func (r *SendMessageRequest) Messages(ctx http.Context) map[string]string {
	return map[string]string{
		"content.required":   "Message content is required",
		"content.max":        "Message content cannot exceed 10000 characters",
		"type.required":      "Message type is required",
		"type.in":            "Message type must be text, image, file, or system",
		"metadata.array":     "Metadata must be an object",
		"reply_to_id.string": "Reply to ID must be a string",
		"reply_to_id.exists": "Reply to message does not exist",
	}
}

// Attributes returns the validation attributes for sending a message
func (r *SendMessageRequest) Attributes(ctx http.Context) map[string]string {
	return map[string]string{
		"content":     "message content",
		"type":        "message type",
		"metadata":    "message metadata",
		"reply_to_id": "reply to message ID",
	}
}

// AddMemberRequest represents the request for adding a member to a chat room
type AddMemberRequest struct {
	// User ID to add
	UserID string `form:"user_id" json:"user_id"`

	// Member role
	Role string `form:"role" json:"role"`
}

// Rules returns the validation rules for adding a member
func (r *AddMemberRequest) Rules(ctx http.Context) map[string]string {
	return map[string]string{
		"user_id": "required|string|exists:users,id",
		"role":    "required|string|in:admin,moderator,member",
	}
}

// Messages returns the validation messages for adding a member
func (r *AddMemberRequest) Messages(ctx http.Context) map[string]string {
	return map[string]string{
		"user_id.required": "User ID is required",
		"user_id.string":   "User ID must be a string",
		"user_id.exists":   "User does not exist",
		"role.required":    "Role is required",
		"role.string":      "Role must be a string",
		"role.in":          "Role must be admin, moderator, or member",
	}
}

// Attributes returns the validation attributes for adding a member
func (r *AddMemberRequest) Attributes(ctx http.Context) map[string]string {
	return map[string]string{
		"user_id": "user ID",
		"role":    "member role",
	}
}

// GenerateKeyPairRequest represents the request for generating encryption keys
type GenerateKeyPairRequest struct {
	// Key type (identity, signed_prekey, one_time_prekey)
	KeyType string `form:"key_type" json:"key_type"`

	// Key expiration (for prekeys)
	ExpiresAt string `form:"expires_at" json:"expires_at"`
}

// Rules returns the validation rules for generating keys
func (r *GenerateKeyPairRequest) Rules(ctx http.Context) map[string]string {
	return map[string]string{
		"key_type":   "required|string|in:identity,signed_prekey,one_time_prekey",
		"expires_at": "date",
	}
}

// Messages returns the validation messages for generating keys
func (r *GenerateKeyPairRequest) Messages(ctx http.Context) map[string]string {
	return map[string]string{
		"key_type.required": "Key type is required",
		"key_type.string":   "Key type must be a string",
		"key_type.in":       "Key type must be identity, signed_prekey, or one_time_prekey",
		"expires_at.date":   "Expiration date must be a valid date",
	}
}

// Attributes returns the validation attributes for generating keys
func (r *GenerateKeyPairRequest) Attributes(ctx http.Context) map[string]string {
	return map[string]string{
		"key_type":   "key type",
		"expires_at": "expiration date",
	}
}

// CreateInvitationRequest represents the request for creating a chat invitation
type CreateInvitationRequest struct {
	// Invited user ID
	InvitedUserID string `form:"invited_user_id" json:"invited_user_id"`

	// Invitation message
	Message string `form:"message" json:"message"`

	// Invitation expiration
	ExpiresAt string `form:"expires_at" json:"expires_at"`
}

// Rules returns the validation rules for creating an invitation
func (r *CreateInvitationRequest) Rules(ctx http.Context) map[string]string {
	return map[string]string{
		"invited_user_id": "required|string|exists:users,id",
		"message":         "string|max:500",
		"expires_at":      "date|after:now",
	}
}

// Messages returns the validation messages for creating an invitation
func (r *CreateInvitationRequest) Messages(ctx http.Context) map[string]string {
	return map[string]string{
		"invited_user_id.required": "Invited user ID is required",
		"invited_user_id.string":   "Invited user ID must be a string",
		"invited_user_id.exists":   "Invited user does not exist",
		"message.max":              "Invitation message cannot exceed 500 characters",
		"expires_at.date":          "Expiration date must be a valid date",
		"expires_at.after":         "Expiration date must be in the future",
	}
}

// Attributes returns the validation attributes for creating an invitation
func (r *CreateInvitationRequest) Attributes(ctx http.Context) map[string]string {
	return map[string]string{
		"invited_user_id": "invited user ID",
		"message":         "invitation message",
		"expires_at":      "expiration date",
	}
}

// RespondToInvitationRequest represents the request for responding to an invitation
type RespondToInvitationRequest struct {
	// Response (accept, decline)
	Response string `form:"response" json:"response"`
}

// Rules returns the validation rules for responding to an invitation
func (r *RespondToInvitationRequest) Rules(ctx http.Context) map[string]string {
	return map[string]string{
		"response": "required|string|in:accept,decline",
	}
}

// Messages returns the validation messages for responding to an invitation
func (r *RespondToInvitationRequest) Messages(ctx http.Context) map[string]string {
	return map[string]string{
		"response.required": "Response is required",
		"response.string":   "Response must be a string",
		"response.in":       "Response must be accept or decline",
	}
}

// Attributes returns the validation attributes for responding to an invitation
func (r *RespondToInvitationRequest) Attributes(ctx http.Context) map[string]string {
	return map[string]string{
		"response": "response",
	}
}

// AddReactionRequest represents a request to add a reaction to a message
type AddReactionRequest struct {
	// Emoji reaction
	// @example 👍
	Emoji string `json:"emoji" validate:"required" example:"👍"`
}

// RemoveReactionRequest represents a request to remove a reaction from a message
type RemoveReactionRequest struct {
	// Emoji reaction to remove
	// @example 👍
	Emoji string `json:"emoji" validate:"required" example:"👍"`
}

// EditMessageRequest represents a request to edit a message
type EditMessageRequest struct {
	// New message content
	Content string `form:"content" json:"content"`
}

// Rules returns the validation rules for editing a message
func (r *EditMessageRequest) Rules(ctx http.Context) map[string]string {
	return map[string]string{
		"content": "required|string|max:10000",
	}
}

// Messages returns the validation messages for editing a message
func (r *EditMessageRequest) Messages(ctx http.Context) map[string]string {
	return map[string]string{
		"content.required": "Message content is required",
		"content.max":      "Message content cannot exceed 10000 characters",
	}
}

// Attributes returns the validation attributes for editing a message
func (r *EditMessageRequest) Attributes(ctx http.Context) map[string]string {
	return map[string]string{
		"content": "message content",
	}
}

// CreateThreadRequest represents a request to create a new thread
type CreateThreadRequest struct {
	// Thread title
	Title string `form:"title" json:"title"`
}

// Rules returns the validation rules for creating a thread
func (r *CreateThreadRequest) Rules(ctx http.Context) map[string]string {
	return map[string]string{
		"title": "required|string|max:255",
	}
}

// Messages returns the validation messages for creating a thread
func (r *CreateThreadRequest) Messages(ctx http.Context) map[string]string {
	return map[string]string{
		"title.required": "Thread title is required",
		"title.max":      "Thread title cannot exceed 255 characters",
	}
}

// Attributes returns the validation attributes for creating a thread
func (r *CreateThreadRequest) Attributes(ctx http.Context) map[string]string {
	return map[string]string{
		"title": "thread title",
	}
}

// ResolveThreadRequest represents a request to resolve a thread
type ResolveThreadRequest struct {
	// Resolution note
	Note string `form:"note" json:"note"`
}

// Rules returns the validation rules for resolving a thread
func (r *ResolveThreadRequest) Rules(ctx http.Context) map[string]string {
	return map[string]string{
		"note": "string|max:500",
	}
}

// Messages returns the validation messages for resolving a thread
func (r *ResolveThreadRequest) Messages(ctx http.Context) map[string]string {
	return map[string]string{
		"note.max": "Resolution note cannot exceed 500 characters",
	}
}

// Attributes returns the validation attributes for resolving a thread
func (r *ResolveThreadRequest) Attributes(ctx http.Context) map[string]string {
	return map[string]string{
		"note": "resolution note",
	}
}

// UpdateNotificationSettingsRequest represents a request to update notification settings
type UpdateNotificationSettingsRequest struct {
	// Email notifications enabled
	EmailNotifications *bool `form:"email_notifications" json:"email_notifications"`

	// Push notifications enabled
	PushNotifications *bool `form:"push_notifications" json:"push_notifications"`

	// Desktop notifications enabled
	DesktopNotifications *bool `form:"desktop_notifications" json:"desktop_notifications"`

	// Mention notifications enabled
	MentionNotifications *bool `form:"mention_notifications" json:"mention_notifications"`

	// Reaction notifications enabled
	ReactionNotifications *bool `form:"reaction_notifications" json:"reaction_notifications"`

	// Thread notifications enabled
	ThreadNotifications *bool `form:"thread_notifications" json:"thread_notifications"`

	// Mute until timestamp
	MuteUntil *string `form:"mute_until" json:"mute_until"`

	// Whether the room is muted
	IsMuted *bool `form:"is_muted" json:"is_muted"`

	// Custom notification settings
	CustomSettings map[string]interface{} `form:"custom_settings" json:"custom_settings"`
}

// Rules returns the validation rules for updating notification settings
func (r *UpdateNotificationSettingsRequest) Rules(ctx http.Context) map[string]string {
	return map[string]string{
		"email_notifications":    "boolean",
		"push_notifications":     "boolean",
		"desktop_notifications":  "boolean",
		"mention_notifications":  "boolean",
		"reaction_notifications": "boolean",
		"thread_notifications":   "boolean",
		"mute_until":             "date",
		"is_muted":               "boolean",
		"custom_settings":        "array",
	}
}

// Messages returns the validation messages for updating notification settings
func (r *UpdateNotificationSettingsRequest) Messages(ctx http.Context) map[string]string {
	return map[string]string{
		"email_notifications.boolean":    "Email notifications must be a boolean",
		"push_notifications.boolean":     "Push notifications must be a boolean",
		"desktop_notifications.boolean":  "Desktop notifications must be a boolean",
		"mention_notifications.boolean":  "Mention notifications must be a boolean",
		"reaction_notifications.boolean": "Reaction notifications must be a boolean",
		"thread_notifications.boolean":   "Thread notifications must be a boolean",
		"mute_until.date":                "Mute until must be a valid date",
		"is_muted.boolean":               "Is muted must be a boolean",
		"custom_settings.array":          "Custom settings must be an object",
	}
}

// Attributes returns the validation attributes for updating notification settings
func (r *UpdateNotificationSettingsRequest) Attributes(ctx http.Context) map[string]string {
	return map[string]string{
		"email_notifications":    "email notifications",
		"push_notifications":     "push notifications",
		"desktop_notifications":  "desktop notifications",
		"mention_notifications":  "mention notifications",
		"reaction_notifications": "reaction notifications",
		"thread_notifications":   "thread notifications",
		"mute_until":             "mute until",
		"is_muted":               "is muted",
		"custom_settings":        "custom settings",
	}
}
