# Chat System Advanced Features

This document describes the advanced features implemented in the chat system, including message threading, message editing/deletion, and advanced notification settings.

## Table of Contents

1. [Message Threading](#message-threading)
2. [Message Editing](#message-editing)
3. [Message Deletion](#message-deletion)
4. [Notification Settings](#notification-settings)
5. [API Endpoints](#api-endpoints)
6. [Database Schema](#database-schema)
7. [Usage Examples](#usage-examples)

## Message Threading

Message threading allows users to organize conversations by creating threads from specific messages. This feature is particularly useful for group discussions where multiple topics are being discussed simultaneously.

### Features

- **Thread Creation**: Create threads from any message in a chat room
- **Thread Management**: View, organize, and manage threads within rooms
- **Thread Resolution**: Mark threads as resolved when discussions are complete
- **Thread Activity Tracking**: Track last activity and message count in threads

### Thread Lifecycle

1. **Creation**: A user creates a thread from a root message
2. **Development**: Users can reply to the thread, adding messages
3. **Resolution**: Threads can be marked as resolved when the discussion is complete
4. **Archival**: Resolved threads are archived but remain accessible

## Message Editing

Message editing allows users to correct typos or update information in their messages within a limited time window.

### Features

- **Time-limited Editing**: Messages can only be edited within 15 minutes of posting
- **Edit History**: Original content is preserved for audit purposes
- **Edit Indicators**: Edited messages are clearly marked
- **Permission Control**: Only message authors can edit their messages

### Edit Window

- **Duration**: 15 minutes from message creation
- **Extension**: Not currently supported (can be configured)
- **Audit Trail**: Original content is stored in `original_content` field

## Message Deletion

Message deletion provides users with control over their content while maintaining system integrity.

### Features

- **Soft Deletion**: Messages are soft-deleted (marked as deleted but not physically removed)
- **Permission Control**: Users can delete their own messages or admins can delete any message
- **Audit Trail**: Deletion actions are logged for security purposes

### Deletion Permissions

- **Own Messages**: Users can delete their own messages
- **Admin Override**: Room admins can delete any message in their room
- **System Messages**: System messages have special deletion rules

## Notification Settings

Advanced notification settings provide granular control over how and when users receive notifications.

### Global Settings

Global notification settings apply to all chat rooms unless overridden by room-specific settings.

#### Available Settings

- **Email Notifications**: Receive notifications via email
- **Push Notifications**: Receive push notifications on mobile devices
- **Desktop Notifications**: Receive desktop notifications
- **Mention Notifications**: Notifications when mentioned in messages
- **Reaction Notifications**: Notifications when someone reacts to your messages
- **Thread Notifications**: Notifications for thread activity
- **Custom Settings**: JSON-based custom notification preferences

### Room-Specific Settings

Room-specific settings override global settings for individual chat rooms.

#### Additional Room Settings

- **Mute Room**: Temporarily mute notifications for a specific room
- **Mute Duration**: Set a specific time period for muting
- **Room-Specific Custom Settings**: Custom settings specific to the room

### Custom Settings Examples

```json
{
  "sound": "default",
  "vibration": true,
  "badge": true,
  "quiet_hours": {
    "enabled": true,
    "start": "22:00",
    "end": "08:00"
  },
  "priority": "high"
}
```

## API Endpoints

### Message Editing

#### Edit Message
```
PUT /api/v1/chat/rooms/{id}/messages/{message_id}
```

**Request Body:**
```json
{
  "content": "Updated message content"
}
```

**Response:**
```json
{
  "status": "success",
  "message": "Message edited successfully",
  "data": {
    "id": "01HXYZ123456789ABCDEFGHIJK",
    "content": "Updated message content",
    "is_edited": true,
    "edited_at": "2024-01-15T10:30:00Z"
  }
}
```

### Message Deletion

#### Delete Message
```
DELETE /api/v1/chat/rooms/{id}/messages/{message_id}
```

**Response:**
```json
{
  "status": "success",
  "message": "Message deleted successfully"
}
```

### Thread Management

#### Create Thread
```
POST /api/v1/chat/rooms/{id}/messages/{message_id}/threads
```

**Request Body:**
```json
{
  "title": "Thread Title"
}
```

#### Get Thread
```
GET /api/v1/chat/threads/{thread_id}
```

#### Get Room Threads
```
GET /api/v1/chat/rooms/{id}/threads?limit=20&offset=0
```

#### Resolve Thread
```
POST /api/v1/chat/threads/{thread_id}/resolve
```

**Request Body:**
```json
{
  "note": "Thread resolved"
}
```

### Notification Settings

#### Get Global Settings
```
GET /api/v1/chat/notifications/global
```

#### Update Global Settings
```
PUT /api/v1/chat/notifications/global
```

**Request Body:**
```json
{
  "email_notifications": true,
  "push_notifications": false,
  "desktop_notifications": true,
  "mention_notifications": true,
  "reaction_notifications": false,
  "thread_notifications": true,
  "is_muted": false,
  "custom_settings": {
    "sound": "custom",
    "vibration": true
  }
}
```

#### Get Room Settings
```
GET /api/v1/chat/rooms/{id}/notifications
```

#### Update Room Settings
```
PUT /api/v1/chat/rooms/{id}/notifications
```

**Request Body:**
```json
{
  "email_notifications": true,
  "push_notifications": false,
  "desktop_notifications": true,
  "mention_notifications": true,
  "reaction_notifications": true,
  "thread_notifications": false,
  "is_muted": true,
  "mute_until": "2024-12-31T23:59:59Z",
  "custom_settings": {
    "room_specific": true
  }
}
```

## Database Schema

### New Tables

#### message_threads
```sql
CREATE TABLE message_threads (
    id VARCHAR(26) PRIMARY KEY,
    chat_room_id VARCHAR(26) NOT NULL,
    root_message_id VARCHAR(26) NOT NULL,
    title VARCHAR(255),
    message_count INT DEFAULT 0,
    last_activity_at TIMESTAMP,
    is_resolved BOOLEAN DEFAULT FALSE,
    resolved_by VARCHAR(26),
    resolved_at TIMESTAMP,
    created_at TIMESTAMP,
    updated_at TIMESTAMP,
    deleted_at TIMESTAMP
);
```

#### chat_notification_settings
```sql
CREATE TABLE chat_notification_settings (
    id VARCHAR(26) PRIMARY KEY,
    user_id VARCHAR(26) NOT NULL,
    chat_room_id VARCHAR(26),
    email_notifications BOOLEAN DEFAULT TRUE,
    push_notifications BOOLEAN DEFAULT TRUE,
    desktop_notifications BOOLEAN DEFAULT TRUE,
    mention_notifications BOOLEAN DEFAULT TRUE,
    reaction_notifications BOOLEAN DEFAULT TRUE,
    thread_notifications BOOLEAN DEFAULT TRUE,
    mute_until TIMESTAMP,
    is_muted BOOLEAN DEFAULT FALSE,
    custom_settings JSON,
    created_at TIMESTAMP,
    updated_at TIMESTAMP,
    deleted_at TIMESTAMP
);
```

### Updated Tables

#### chat_messages
Added fields:
- `thread_id VARCHAR(26)` - Reference to thread
- `edited_at TIMESTAMP` - When message was last edited

## Usage Examples

### Creating and Managing Threads

```javascript
// Create a thread from a message
const createThread = async (roomId, messageId, title) => {
  const response = await fetch(`/api/v1/chat/rooms/${roomId}/messages/${messageId}/threads`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${token}`
    },
    body: JSON.stringify({ title })
  });
  return response.json();
};

// Get all threads in a room
const getRoomThreads = async (roomId) => {
  const response = await fetch(`/api/v1/chat/rooms/${roomId}/threads`);
  return response.json();
};

// Resolve a thread
const resolveThread = async (threadId, note) => {
  const response = await fetch(`/api/v1/chat/threads/${threadId}/resolve`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${token}`
    },
    body: JSON.stringify({ note })
  });
  return response.json();
};
```

### Managing Notification Settings

```javascript
// Update global notification settings
const updateGlobalSettings = async (settings) => {
  const response = await fetch('/api/v1/chat/notifications/global', {
    method: 'PUT',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${token}`
    },
    body: JSON.stringify(settings)
  });
  return response.json();
};

// Update room-specific settings
const updateRoomSettings = async (roomId, settings) => {
  const response = await fetch(`/api/v1/chat/rooms/${roomId}/notifications`, {
    method: 'PUT',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${token}`
    },
    body: JSON.stringify(settings)
  });
  return response.json();
};
```

### Message Editing and Deletion

```javascript
// Edit a message
const editMessage = async (roomId, messageId, newContent) => {
  const response = await fetch(`/api/v1/chat/rooms/${roomId}/messages/${messageId}`, {
    method: 'PUT',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${token}`
    },
    body: JSON.stringify({ content: newContent })
  });
  return response.json();
};

// Delete a message
const deleteMessage = async (roomId, messageId) => {
  const response = await fetch(`/api/v1/chat/rooms/${roomId}/messages/${messageId}`, {
    method: 'DELETE',
    headers: {
      'Authorization': `Bearer ${token}`
    }
  });
  return response.json();
};
```

## Security Considerations

### Message Editing
- Only message authors can edit their messages
- Edit window is limited to 15 minutes
- Original content is preserved for audit purposes

### Message Deletion
- Users can only delete their own messages
- Admins can delete any message in their room
- Soft deletion maintains data integrity

### Thread Management
- Users must be room members to create threads
- Thread resolution requires room membership
- Thread activity is tracked for moderation

### Notification Settings
- Settings are user-specific and secure
- Room-specific settings override global settings
- Custom settings are validated before storage

## Performance Considerations

### Database Indexes
- Thread ID indexes on messages table
- User and room indexes on notification settings
- Activity timestamp indexes for efficient queries

### Caching
- Thread lists can be cached for frequently accessed rooms
- Notification settings can be cached per user
- Message edit history can be cached for recent messages

### Scalability
- Threads are designed to handle large numbers of messages
- Notification settings use efficient JSON storage
- Soft deletion maintains performance while preserving data

## Future Enhancements

### Planned Features
- **Thread Categories**: Categorize threads by type (bug, feature, general)
- **Thread Moderation**: Advanced moderation tools for thread management
- **Edit History**: Detailed edit history with diff tracking
- **Bulk Operations**: Bulk edit and delete operations
- **Advanced Notifications**: Smart notification scheduling and filtering

### Integration Opportunities
- **Webhook Support**: Webhooks for thread and notification events
- **Third-party Integrations**: Integration with external notification services
- **Analytics**: Thread and notification analytics
- **Mobile Push**: Enhanced mobile push notification support 