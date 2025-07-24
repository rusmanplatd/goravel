package models

import (
	"time"
)

// ChatRoom represents a chat room/conversation
// @Description Chat room model for group or direct conversations
type ChatRoom struct {
	BaseModel
	// Room name/title
	// @example General Discussion
	Name string `gorm:"not null" json:"name" example:"General Discussion"`

	// Room description
	// @example Main discussion channel for the team
	Description string `json:"description,omitempty" example:"Main discussion channel for the team"`

	// Room type (direct, group, channel)
	// @example group
	Type string `gorm:"not null;default:'group'" json:"type" example:"group"`

	// Whether the room is active
	// @example true
	IsActive bool `gorm:"default:true" json:"is_active" example:"true"`

	// Room avatar/icon
	// @example https://example.com/avatar.jpg
	Avatar string `json:"avatar,omitempty" example:"https://example.com/avatar.jpg"`

	// Tenant ID for multi-tenant support
	// @example 01HXYZ123456789ABCDEFGHIJK
	TenantID string `gorm:"index;type:char(26)" json:"tenant_id" example:"01HXYZ123456789ABCDEFGHIJK"`

	// Last activity timestamp
	// @example 2024-01-15T10:30:00Z
	LastActivityAt *time.Time `json:"last_activity_at,omitempty" example:"2024-01-15T10:30:00Z"`

	// Relationships
	Tenant   *Tenant          `gorm:"foreignKey:TenantID" json:"tenant,omitempty"`
	Members  []ChatRoomMember `gorm:"foreignKey:ChatRoomID" json:"members,omitempty"`
	Messages []ChatMessage    `gorm:"foreignKey:ChatRoomID" json:"messages,omitempty"`
	Keys     []ChatRoomKey    `gorm:"foreignKey:ChatRoomID" json:"keys,omitempty"`
}

// ChatRoomMember represents a member of a chat room
// @Description Chat room membership with role and permissions
type ChatRoomMember struct {
	BaseModel
	// Chat room ID
	// @example 01HXYZ123456789ABCDEFGHIJK
	ChatRoomID string `gorm:"index;type:char(26)" json:"chat_room_id" example:"01HXYZ123456789ABCDEFGHIJK"`

	// User ID
	// @example 01HXYZ123456789ABCDEFGHIJK
	UserID string `gorm:"index;type:char(26)" json:"user_id" example:"01HXYZ123456789ABCDEFGHIJK"`

	// Member role (admin, moderator, member)
	// @example member
	Role string `gorm:"default:'member'" json:"role" example:"member"`

	// Whether the member is active
	// @example true
	IsActive bool `gorm:"default:true" json:"is_active" example:"true"`

	// When the member joined
	// @example 2024-01-15T10:30:00Z
	JoinedAt time.Time `json:"joined_at" example:"2024-01-15T10:30:00Z"`

	// Last read message timestamp
	// @example 2024-01-15T10:30:00Z
	LastReadAt *time.Time `json:"last_read_at,omitempty" example:"2024-01-15T10:30:00Z"`

	// Member's public key for E2EE
	// @example -----BEGIN PUBLIC KEY-----
	PublicKey string `json:"public_key,omitempty" example:"-----BEGIN PUBLIC KEY-----"`

	// Relationships
	ChatRoom *ChatRoom `gorm:"foreignKey:ChatRoomID" json:"chat_room,omitempty"`
	User     *User     `gorm:"foreignKey:UserID" json:"user,omitempty"`
}

// ChatMessage represents a message in a chat room
// @Description Chat message with E2EE support
type ChatMessage struct {
	BaseModel
	// Chat room ID
	// @example 01HXYZ123456789ABCDEFGHIJK
	ChatRoomID string `gorm:"index;type:char(26)" json:"chat_room_id" example:"01HXYZ123456789ABCDEFGHIJK"`

	// Sender user ID
	// @example 01HXYZ123456789ABCDEFGHIJK
	SenderID string `gorm:"index;type:char(26)" json:"sender_id" example:"01HXYZ123456789ABCDEFGHIJK"`

	// Message type (text, image, file, system)
	// @example text
	Type string `gorm:"default:'text'" json:"type" example:"text"`

	// Encrypted message content
	// @example encrypted_message_data
	EncryptedContent string `gorm:"type:text" json:"encrypted_content" example:"encrypted_message_data"`

	// Message metadata (file info, etc.)
	// @example {"file_size": 1024, "file_name": "document.pdf"}
	Metadata string `gorm:"type:json" json:"metadata,omitempty" example:"{\"file_size\": 1024, \"file_name\": \"document.pdf\"}"`

	// Reply to message ID (for threaded conversations)
	// @example 01HXYZ123456789ABCDEFGHIJK
	ReplyToID *string `gorm:"index;type:char(26)" json:"reply_to_id,omitempty" example:"01HXYZ123456789ABCDEFGHIJK"`

	// Thread ID (for advanced threading)
	// @example 01HXYZ123456789ABCDEFGHIJK
	ThreadID *string `gorm:"index;type:char(26)" json:"thread_id,omitempty" example:"01HXYZ123456789ABCDEFGHIJK"`

	// Whether the message is edited
	// @example false
	IsEdited bool `gorm:"default:false" json:"is_edited" example:"false"`

	// Original message content (for edited messages)
	// @example original_encrypted_content
	OriginalContent string `gorm:"type:text" json:"original_content,omitempty" example:"original_encrypted_content"`

	// Edit timestamp
	// @example 2024-01-15T10:30:00Z
	EditedAt *time.Time `json:"edited_at,omitempty" example:"2024-01-15T10:30:00Z"`

	// Message status (sent, delivered, read)
	// @example sent
	Status string `gorm:"default:'sent'" json:"status" example:"sent"`

	// Message encryption version
	// @example 1
	EncryptionVersion int `gorm:"default:1" json:"encryption_version" example:"1"`

	// Relationships
	ChatRoom *ChatRoom      `gorm:"foreignKey:ChatRoomID" json:"chat_room,omitempty"`
	Sender   *User          `gorm:"foreignKey:SenderID" json:"sender,omitempty"`
	ReplyTo  *ChatMessage   `gorm:"foreignKey:ReplyToID" json:"reply_to,omitempty"`
	Thread   *MessageThread `gorm:"foreignKey:ThreadID" json:"thread,omitempty"`
	ReadBy   []MessageRead  `gorm:"foreignKey:MessageID" json:"read_by,omitempty"`
}

// MessageRead represents message read status by users
// @Description Message read status tracking
type MessageRead struct {
	BaseModel
	// Message ID
	// @example 01HXYZ123456789ABCDEFGHIJK
	MessageID string `gorm:"index;type:char(26)" json:"message_id" example:"01HXYZ123456789ABCDEFGHIJK"`

	// User ID who read the message
	// @example 01HXYZ123456789ABCDEFGHIJK
	UserID string `gorm:"index;type:char(26)" json:"user_id" example:"01HXYZ123456789ABCDEFGHIJK"`

	// When the message was read
	// @example 2024-01-15T10:30:00Z
	ReadAt time.Time `json:"read_at" example:"2024-01-15T10:30:00Z"`

	// Relationships
	Message *ChatMessage `gorm:"foreignKey:MessageID" json:"message,omitempty"`
	User    *User        `gorm:"foreignKey:UserID" json:"user,omitempty"`
}

// ChatRoomKey represents encryption keys for chat rooms
// @Description E2EE keys for chat room encryption
type ChatRoomKey struct {
	BaseModel
	// Chat room ID
	// @example 01HXYZ123456789ABCDEFGHIJK
	ChatRoomID string `gorm:"index;type:char(26)" json:"chat_room_id" example:"01HXYZ123456789ABCDEFGHIJK"`

	// Key type (room_key, user_key)
	// @example room_key
	KeyType string `gorm:"not null" json:"key_type" example:"room_key"`

	// Encrypted key data
	// @example encrypted_key_data
	EncryptedKey string `gorm:"type:text" json:"encrypted_key" example:"encrypted_key_data"`

	// Key version
	// @example 1
	Version int `gorm:"default:1" json:"version" example:"1"`

	// Whether this is the current active key
	// @example true
	IsActive bool `gorm:"default:true" json:"is_active" example:"true"`

	// Key rotation timestamp
	// @example 2024-01-15T10:30:00Z
	RotatedAt *time.Time `json:"rotated_at,omitempty" example:"2024-01-15T10:30:00Z"`

	// Relationships
	ChatRoom *ChatRoom `gorm:"foreignKey:ChatRoomID" json:"chat_room,omitempty"`
}

// UserKey represents user's encryption keys
// @Description User's E2EE key pairs
type UserKey struct {
	BaseModel
	// User ID
	// @example 01HXYZ123456789ABCDEFGHIJK
	UserID string `gorm:"index;type:char(26)" json:"user_id" example:"01HXYZ123456789ABCDEFGHIJK"`

	// Key type (identity, signed_prekey, one_time_prekey)
	// @example identity
	KeyType string `gorm:"not null" json:"key_type" example:"identity"`

	// Public key
	// @example -----BEGIN PUBLIC KEY-----
	PublicKey string `gorm:"type:text" json:"public_key" example:"-----BEGIN PUBLIC KEY-----"`

	// Encrypted private key
	// @example encrypted_private_key_data
	EncryptedPrivateKey string `gorm:"type:text" json:"encrypted_private_key" example:"encrypted_private_key_data"`

	// Key version
	// @example 1
	Version int `gorm:"default:1" json:"version" example:"1"`

	// Whether this is the current active key
	// @example true
	IsActive bool `gorm:"default:true" json:"is_active" example:"true"`

	// Key expiration timestamp (for prekeys)
	// @example 2024-01-15T10:30:00Z
	ExpiresAt *time.Time `json:"expires_at,omitempty" example:"2024-01-15T10:30:00Z"`

	// Relationships
	User *User `gorm:"foreignKey:UserID" json:"user,omitempty"`
}

// ChatInvitation represents chat room invitations
// @Description Chat room invitation system
type ChatInvitation struct {
	BaseModel
	// Chat room ID
	// @example 01HXYZ123456789ABCDEFGHIJK
	ChatRoomID string `gorm:"index;type:char(26)" json:"chat_room_id" example:"01HXYZ123456789ABCDEFGHIJK"`

	// Invited user ID
	// @example 01HXYZ123456789ABCDEFGHIJK
	InvitedUserID string `gorm:"index;type:char(26)" json:"invited_user_id" example:"01HXYZ123456789ABCDEFGHIJK"`

	// Inviter user ID
	// @example 01HXYZ123456789ABCDEFGHIJK
	InviterID string `gorm:"index;type:char(26)" json:"inviter_id" example:"01HXYZ123456789ABCDEFGHIJK"`

	// Invitation status (pending, accepted, declined, expired)
	// @example pending
	Status string `gorm:"default:'pending'" json:"status" example:"pending"`

	// Invitation message
	// @example Join our team discussion!
	Message string `json:"message,omitempty" example:"Join our team discussion!"`

	// Invitation expiration timestamp
	// @example 2024-01-15T10:30:00Z
	ExpiresAt *time.Time `json:"expires_at,omitempty" example:"2024-01-15T10:30:00Z"`

	// When the invitation was accepted/declined
	// @example 2024-01-15T10:30:00Z
	RespondedAt *time.Time `json:"responded_at,omitempty" example:"2024-01-15T10:30:00Z"`

	// Relationships
	ChatRoom    *ChatRoom `gorm:"foreignKey:ChatRoomID" json:"chat_room,omitempty"`
	InvitedUser *User     `gorm:"foreignKey:InvitedUserID" json:"invited_user,omitempty"`
	Inviter     *User     `gorm:"foreignKey:InviterID" json:"inviter,omitempty"`
}

// MessageReaction represents a reaction to a message
// @Description Message reaction with emoji and user info
type MessageReaction struct {
	BaseModel
	// Message ID
	// @example 01HXYZ123456789ABCDEFGHIJK
	MessageID string `gorm:"index;type:char(26)" json:"message_id" example:"01HXYZ123456789ABCDEFGHIJK"`

	// User ID who reacted
	// @example 01HXYZ123456789ABCDEFGHIJK
	UserID string `gorm:"index;type:char(26)" json:"user_id" example:"01HXYZ123456789ABCDEFGHIJK"`

	// Emoji reaction
	// @example 👍
	Emoji string `gorm:"not null" json:"emoji" example:"👍"`

	// Reaction timestamp
	// @example 2024-01-15T10:30:00Z
	ReactedAt time.Time `json:"reacted_at" example:"2024-01-15T10:30:00Z"`

	// Relationships
	Message *ChatMessage `gorm:"foreignKey:MessageID" json:"message,omitempty"`
	User    *User        `gorm:"foreignKey:UserID" json:"user,omitempty"`
}

// MessageThread represents a thread of messages
// @Description Message thread for organizing conversations
type MessageThread struct {
	BaseModel
	// Chat room ID
	// @example 01HXYZ123456789ABCDEFGHIJK
	ChatRoomID string `gorm:"index;type:char(26)" json:"chat_room_id" example:"01HXYZ123456789ABCDEFGHIJK"`

	// Root message ID that started the thread
	// @example 01HXYZ123456789ABCDEFGHIJK
	RootMessageID string `gorm:"index;type:char(26)" json:"root_message_id" example:"01HXYZ123456789ABCDEFGHIJK"`

	// Thread title
	// @example Bug Discussion
	Title string `json:"title,omitempty" example:"Bug Discussion"`

	// Number of messages in the thread
	// @example 5
	MessageCount int `gorm:"default:0" json:"message_count" example:"5"`

	// Last activity timestamp
	// @example 2024-01-15T10:30:00Z
	LastActivityAt *time.Time `json:"last_activity_at,omitempty" example:"2024-01-15T10:30:00Z"`

	// Whether the thread is resolved
	// @example false
	IsResolved bool `gorm:"default:false" json:"is_resolved" example:"false"`

	// User who resolved the thread
	// @example 01HXYZ123456789ABCDEFGHIJK
	ResolvedBy *string `gorm:"index;type:char(26)" json:"resolved_by,omitempty" example:"01HXYZ123456789ABCDEFGHIJK"`

	// When the thread was resolved
	// @example 2024-01-15T10:30:00Z
	ResolvedAt *time.Time `json:"resolved_at,omitempty" example:"2024-01-15T10:30:00Z"`

	// Relationships
	ChatRoom       *ChatRoom     `gorm:"foreignKey:ChatRoomID" json:"chat_room,omitempty"`
	RootMessage    *ChatMessage  `gorm:"foreignKey:RootMessageID" json:"root_message,omitempty"`
	ResolvedByUser *User         `gorm:"foreignKey:ResolvedBy" json:"resolved_by_user,omitempty"`
	Messages       []ChatMessage `gorm:"foreignKey:ThreadID" json:"messages,omitempty"`
}

// ChatNotificationSettings represents user notification preferences for chat rooms
// @Description User notification settings for chat rooms
type ChatNotificationSettings struct {
	BaseModel
	// User ID
	// @example 01HXYZ123456789ABCDEFGHIJK
	UserID string `gorm:"index;type:char(26)" json:"user_id" example:"01HXYZ123456789ABCDEFGHIJK"`

	// Chat room ID (null for global settings)
	// @example 01HXYZ123456789ABCDEFGHIJK
	ChatRoomID *string `gorm:"index;type:char(26)" json:"chat_room_id,omitempty" example:"01HXYZ123456789ABCDEFGHIJK"`

	// Email notifications enabled
	// @example true
	EmailNotifications bool `gorm:"default:true" json:"email_notifications" example:"true"`

	// Push notifications enabled
	// @example true
	PushNotifications bool `gorm:"default:true" json:"push_notifications" example:"true"`

	// Desktop notifications enabled
	// @example true
	DesktopNotifications bool `gorm:"default:true" json:"desktop_notifications" example:"true"`

	// Mention notifications enabled
	// @example true
	MentionNotifications bool `gorm:"default:true" json:"mention_notifications" example:"true"`

	// Reaction notifications enabled
	// @example true
	ReactionNotifications bool `gorm:"default:true" json:"reaction_notifications" example:"true"`

	// Thread notifications enabled
	// @example true
	ThreadNotifications bool `gorm:"default:true" json:"thread_notifications" example:"true"`

	// Mute until timestamp
	// @example 2024-01-15T10:30:00Z
	MuteUntil *time.Time `json:"mute_until,omitempty" example:"2024-01-15T10:30:00Z"`

	// Whether the room is muted
	// @example false
	IsMuted bool `gorm:"default:false" json:"is_muted" example:"false"`

	// Custom notification settings
	// @example {"sound": "default", "vibration": true}
	CustomSettings string `gorm:"type:json" json:"custom_settings,omitempty" example:"{\"sound\": \"default\", \"vibration\": true}"`

	// Relationships
	User     *User     `gorm:"foreignKey:UserID" json:"user,omitempty"`
	ChatRoom *ChatRoom `gorm:"foreignKey:ChatRoomID" json:"chat_room,omitempty"`
}
