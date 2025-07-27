# Meeting API Documentation

This document provides comprehensive documentation for the Meeting API endpoints in the Goravel Meeting System.

## Table of Contents
- [Authentication](#authentication)
- [Meeting Management](#meeting-management)
- [Participant Management](#participant-management)
- [Real-time Features](#real-time-features)
- [Security & Permissions](#security--permissions)
- [WebSocket API](#websocket-api)
- [Error Handling](#error-handling)
- [Rate Limiting](#rate-limiting)

## Authentication

All meeting API endpoints require authentication. Include the JWT token in the Authorization header:

```
Authorization: Bearer <jwt_token>
```

## Meeting Management

### Start Meeting

Start a scheduled meeting session.

**Endpoint:** `POST /api/v1/meetings/{id}/start`

**Parameters:**
- `id` (path, required): Meeting ID

**Headers:**
```
Authorization: Bearer <jwt_token>
Content-Type: application/json
```

**Response:**
```json
{
  "status": "success",
  "message": "Meeting started successfully",
  "data": {
    "meeting_id": "01HXYZ123456789ABCDEFGHIJK",
    "started_by": "01HXYZ123456789ABCDEFGHIJK",
    "started_at": "2024-01-15T10:00:00Z"
  },
  "timestamp": "2024-01-15T10:00:00Z"
}
```

**Error Responses:**
- `400 Bad Request`: Meeting cannot be started
- `403 Forbidden`: Insufficient permissions (only hosts can start meetings)
- `404 Not Found`: Meeting not found
- `409 Conflict`: Meeting is already active

### End Meeting

End an active meeting session.

**Endpoint:** `POST /api/v1/meetings/{id}/end`

**Parameters:**
- `id` (path, required): Meeting ID

**Response:**
```json
{
  "status": "success",
  "message": "Meeting ended successfully",
  "data": {
    "meeting_id": "01HXYZ123456789ABCDEFGHIJK",
    "ended_by": "01HXYZ123456789ABCDEFGHIJK",
    "ended_at": "2024-01-15T11:00:00Z",
    "duration_minutes": 60
  },
  "timestamp": "2024-01-15T11:00:00Z"
}
```

### Get Meeting Status

Retrieve current meeting status and information.

**Endpoint:** `GET /api/v1/meetings/{id}/status`

**Parameters:**
- `id` (path, required): Meeting ID

**Response:**
```json
{
  "status": "success",
  "message": "Meeting status retrieved successfully",
  "data": {
    "meeting_id": "01HXYZ123456789ABCDEFGHIJK",
    "status": "in_progress",
    "is_active": true,
    "started_at": "2024-01-15T10:00:00Z",
    "ended_at": null,
    "attendance_count": 5,
    "is_recording": false,
    "active_participants": 5
  },
  "timestamp": "2024-01-15T10:30:00Z"
}
```

## Participant Management

### Join Meeting

Join a meeting as a participant.

**Endpoint:** `POST /api/v1/meetings/{id}/join`

**Parameters:**
- `id` (path, required): Meeting ID

**Request Body:**
```json
{
  "connection_id": "conn_123456789",
  "device_type": "desktop",
  "join_muted": true,
  "join_without_video": false
}
```

**Response:**
```json
{
  "status": "success",
  "message": "Joined meeting successfully",
  "data": {
    "participant_id": "01HXYZ123456789ABCDEFGHIJK",
    "meeting_id": "01HXYZ123456789ABCDEFGHIJK",
    "user_id": "01HXYZ123456789ABCDEFGHIJK",
    "role": "attendee",
    "status": "joined",
    "is_muted": true,
    "is_video_enabled": false,
    "joined_at": "2024-01-15T10:05:00Z"
  },
  "timestamp": "2024-01-15T10:05:00Z"
}
```

### Leave Meeting

Leave a meeting session.

**Endpoint:** `POST /api/v1/meetings/{id}/leave`

**Parameters:**
- `id` (path, required): Meeting ID

**Response:**
```json
{
  "status": "success",
  "message": "Left meeting successfully",
  "data": {
    "meeting_id": "01HXYZ123456789ABCDEFGHIJK",
    "left_at": "2024-01-15T10:45:00Z",
    "duration_minutes": 40
  },
  "timestamp": "2024-01-15T10:45:00Z"
}
```

### Get Participants

Retrieve list of current meeting participants.

**Endpoint:** `GET /api/v1/meetings/{id}/participants`

**Parameters:**
- `id` (path, required): Meeting ID

**Response:**
```json
{
  "status": "success",
  "message": "Participants retrieved successfully",
  "data": [
    {
      "participant_id": "01HXYZ123456789ABCDEFGHIJK",
      "user_id": "01HXYZ123456789ABCDEFGHIJK",
      "user_name": "John Doe",
      "role": "host",
      "status": "joined",
      "is_muted": false,
      "is_video_enabled": true,
      "is_screen_sharing": false,
      "is_hand_raised": false,
      "joined_at": "2024-01-15T10:00:00Z",
      "device_type": "desktop"
    }
  ],
  "timestamp": "2024-01-15T10:30:00Z"
}
```

### Update Participant Status

Update participant's real-time status (mute, video, hand raise, etc.).

**Endpoint:** `PUT /api/v1/meetings/{id}/participants/status`

**Parameters:**
- `id` (path, required): Meeting ID

**Request Body:**
```json
{
  "is_muted": false,
  "is_video_enabled": true,
  "is_screen_sharing": false,
  "is_hand_raised": true,
  "is_in_waiting_room": false
}
```

**Response:**
```json
{
  "status": "success",
  "message": "Participant status updated successfully",
  "data": {
    "is_muted": false,
    "is_video_enabled": true,
    "is_screen_sharing": false,
    "is_hand_raised": true,
    "is_in_waiting_room": false
  },
  "timestamp": "2024-01-15T10:15:00Z"
}
```

## Real-time Features

### Send Chat Message

Send a chat message in the meeting.

**Endpoint:** `POST /api/v1/meetings/{id}/chat`

**Parameters:**
- `id` (path, required): Meeting ID

**Request Body:**
```json
{
  "content": "Hello everyone!",
  "message_type": "text",
  "recipient_id": null,
  "file_url": null,
  "file_name": null,
  "file_type": null,
  "file_size": null
}
```

**Response:**
```json
{
  "status": "success",
  "message": "Chat message sent successfully",
  "data": {
    "message_id": "01HXYZ123456789ABCDEFGHIJK",
    "sender_id": "01HXYZ123456789ABCDEFGHIJK",
    "sender_name": "John Doe",
    "content": "Hello everyone!",
    "message_type": "text",
    "is_private": false,
    "timestamp": "2024-01-15T10:20:00Z"
  },
  "timestamp": "2024-01-15T10:20:00Z"
}
```

### Get Chat History

Retrieve chat history for a meeting.

**Endpoint:** `GET /api/v1/meetings/{id}/chat`

**Parameters:**
- `id` (path, required): Meeting ID
- `limit` (query, optional): Number of messages to retrieve (default: 50)
- `offset` (query, optional): Offset for pagination (default: 0)

**Response:**
```json
{
  "status": "success",
  "message": "Chat history retrieved successfully",
  "data": [
    {
      "message_id": "01HXYZ123456789ABCDEFGHIJK",
      "sender_id": "01HXYZ123456789ABCDEFGHIJK",
      "sender_name": "John Doe",
      "content": "Hello everyone!",
      "message_type": "text",
      "is_private": false,
      "timestamp": "2024-01-15T10:20:00Z"
    }
  ],
  "timestamp": "2024-01-15T10:30:00Z"
}
```

### Create Breakout Rooms

Create breakout rooms for a meeting (host only).

**Endpoint:** `POST /api/v1/meetings/{id}/breakout-rooms`

**Parameters:**
- `id` (path, required): Meeting ID

**Request Body:**
```json
{
  "room_count": 3,
  "rooms": [
    {
      "name": "Breakout Room 1",
      "description": "Discussion group for project planning",
      "capacity": 5,
      "settings": {
        "allow_chat": true,
        "allow_screen_share": false
      }
    }
  ],
  "auto_assign": false,
  "allow_participants_to_choose": true,
  "allow_participants_to_return": true,
  "time_limit_minutes": 30
}
```

**Response:**
```json
{
  "status": "success",
  "message": "Breakout rooms created successfully",
  "data": [
    {
      "room_id": "01HXYZ123456789ABCDEFGHIJK",
      "name": "Breakout Room 1",
      "description": "Discussion group for project planning",
      "capacity": 5,
      "current_participants": 0,
      "is_active": true
    }
  ],
  "timestamp": "2024-01-15T10:25:00Z"
}
```

### Assign to Breakout Room

Assign a participant to a breakout room.

**Endpoint:** `POST /api/v1/meetings/{id}/breakout-rooms/assign`

**Parameters:**
- `id` (path, required): Meeting ID

**Request Body:**
```json
{
  "participant_user_id": "01HXYZ123456789ABCDEFGHIJK",
  "breakout_room_id": "01HXYZ123456789ABCDEFGHIJK",
  "assignment_type": "manual"
}
```

**Response:**
```json
{
  "status": "success",
  "message": "Participant assigned to breakout room successfully",
  "data": {
    "participant_user_id": "01HXYZ123456789ABCDEFGHIJK",
    "breakout_room_id": "01HXYZ123456789ABCDEFGHIJK"
  },
  "timestamp": "2024-01-15T10:26:00Z"
}
```

## Security & Permissions

### Generate LiveKit Token

Generate a secure JWT token for LiveKit room access.

**Endpoint:** `POST /api/v1/meetings/{id}/token`

**Parameters:**
- `id` (path, required): Meeting ID

**Request Body:**
```json
{
  "user_id": "01HXYZ123456789ABCDEFGHIJK",
  "user_name": "John Doe"
}
```

**Response:**
```json
{
  "status": "success",
  "message": "LiveKit token generated successfully",
  "data": {
    "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "meeting_id": "01HXYZ123456789ABCDEFGHIJK",
    "user_id": "01HXYZ123456789ABCDEFGHIJK",
    "user_name": "John Doe",
    "is_host": false,
    "livekit_url": "wss://livekit.example.com"
  },
  "timestamp": "2024-01-15T10:05:00Z"
}
```

### Apply Security Policy

Apply security policies to a meeting (host only).

**Endpoint:** `POST /api/v1/meetings/{id}/security/policy`

**Parameters:**
- `id` (path, required): Meeting ID

**Request Body:**
```json
{
  "require_waiting_room": true,
  "require_password": false,
  "allow_anonymous_join": false,
  "max_participants": 50,
  "allowed_domains": ["example.com", "company.com"],
  "blocked_users": [],
  "recording_permissions": "host",
  "screen_share_permissions": "all",
  "chat_permissions": "all",
  "mute_on_entry": true,
  "disable_camera": false,
  "lock_meeting": false
}
```

**Response:**
```json
{
  "status": "success",
  "message": "Security policy applied successfully",
  "data": null,
  "timestamp": "2024-01-15T10:02:00Z"
}
```

## WebSocket API

### Connection

Connect to the meeting WebSocket for real-time updates.

**Endpoint:** `wss://api.example.com/ws/meetings/{id}`

**Authentication:** Include JWT token in connection headers or as query parameter.

### Message Types

#### Join Message
```json
{
  "type": "join",
  "meeting_id": "01HXYZ123456789ABCDEFGHIJK",
  "user_id": "01HXYZ123456789ABCDEFGHIJK",
  "data": {
    "user_id": "01HXYZ123456789ABCDEFGHIJK",
    "user_role": "attendee",
    "device_info": {
      "device_type": "desktop",
      "browser_info": "Chrome/91.0"
    },
    "joined_at": "2024-01-15T10:05:00Z"
  },
  "timestamp": "2024-01-15T10:05:00Z"
}
```

#### Participant Update
```json
{
  "type": "participant_update",
  "meeting_id": "01HXYZ123456789ABCDEFGHIJK",
  "user_id": "01HXYZ123456789ABCDEFGHIJK",
  "data": {
    "is_muted": false,
    "is_video_enabled": true,
    "is_hand_raised": false
  },
  "timestamp": "2024-01-15T10:15:00Z"
}
```

#### Chat Message
```json
{
  "type": "chat",
  "meeting_id": "01HXYZ123456789ABCDEFGHIJK",
  "user_id": "01HXYZ123456789ABCDEFGHIJK",
  "data": {
    "content": "Hello everyone!",
    "sender_id": "01HXYZ123456789ABCDEFGHIJK",
    "sender_name": "John Doe",
    "message_type": "text",
    "is_private": false
  },
  "timestamp": "2024-01-15T10:20:00Z"
}
```

#### Reaction
```json
{
  "type": "reaction",
  "meeting_id": "01HXYZ123456789ABCDEFGHIJK",
  "user_id": "01HXYZ123456789ABCDEFGHIJK",
  "data": {
    "reaction_type": "thumbs_up",
    "duration": 3
  },
  "timestamp": "2024-01-15T10:22:00Z"
}
```

#### Hand Raise
```json
{
  "type": "hand_raise",
  "meeting_id": "01HXYZ123456789ABCDEFGHIJK",
  "user_id": "01HXYZ123456789ABCDEFGHIJK",
  "data": {
    "is_hand_raised": true
  },
  "timestamp": "2024-01-15T10:25:00Z"
}
```

#### Ping/Pong
```json
{
  "type": "ping",
  "meeting_id": "01HXYZ123456789ABCDEFGHIJK",
  "user_id": "01HXYZ123456789ABCDEFGHIJK",
  "data": {},
  "timestamp": "2024-01-15T10:30:00Z"
}
```

## Error Handling

### Error Response Format

All API endpoints return errors in a consistent format:

```json
{
  "status": "error",
  "message": "Human-readable error message",
  "code": "ERROR_CODE",
  "details": {
    "field": "Additional error details"
  },
  "timestamp": "2024-01-15T10:00:00Z"
}
```

### Common Error Codes

| Code | HTTP Status | Description |
|------|-------------|-------------|
| `MEETING_NOT_FOUND` | 404 | Meeting does not exist |
| `MEETING_ALREADY_ACTIVE` | 409 | Meeting is already in progress |
| `MEETING_NOT_ACTIVE` | 400 | Meeting is not currently active |
| `MEETING_ENDED` | 410 | Meeting has already ended |
| `INSUFFICIENT_PERMISSION` | 403 | User lacks required permissions |
| `PARTICIPANT_NOT_FOUND` | 404 | Participant not found in meeting |
| `MAX_PARTICIPANTS_REACHED` | 403 | Meeting has reached participant limit |
| `MEETING_LOCKED` | 403 | Meeting is locked to new participants |
| `WAITING_ROOM_REQUIRED` | 202 | Participant must wait for host approval |
| `CHAT_DISABLED` | 403 | Chat is disabled for this meeting |
| `SCREEN_SHARE_DISABLED` | 403 | Screen sharing is disabled |
| `LIVEKIT_TOKEN_ERROR` | 500 | Failed to generate LiveKit token |

### Error Handling Best Practices

1. **Check HTTP Status Codes**: Always check the HTTP status code first
2. **Parse Error Codes**: Use the `code` field for programmatic error handling
3. **Display User Messages**: Use the `message` field for user-facing error messages
4. **Handle Specific Errors**: Implement specific handling for common error scenarios
5. **Retry Logic**: Implement appropriate retry logic for transient errors

## Rate Limiting

### Limits

| Endpoint Category | Rate Limit | Window |
|-------------------|------------|---------|
| Meeting Management | 100 requests | 1 hour |
| Participant Actions | 1000 requests | 1 hour |
| Chat Messages | 60 requests | 1 minute |
| Status Updates | 120 requests | 1 minute |
| WebSocket Messages | 1000 messages | 1 minute |

### Rate Limit Headers

Rate limit information is included in response headers:

```
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 95
X-RateLimit-Reset: 1642248000
```

### Rate Limit Exceeded Response

```json
{
  "status": "error",
  "message": "Rate limit exceeded",
  "code": "RATE_LIMIT_EXCEEDED",
  "details": {
    "limit": 100,
    "window": 3600,
    "reset_at": "2024-01-15T11:00:00Z"
  },
  "timestamp": "2024-01-15T10:30:00Z"
}
```

## SDK Examples

### JavaScript/TypeScript

```typescript
// Initialize meeting client
const meetingClient = new MeetingClient({
  apiUrl: 'https://api.example.com',
  token: 'your-jwt-token'
});

// Start a meeting
try {
  const result = await meetingClient.startMeeting('meeting-id');
  console.log('Meeting started:', result);
} catch (error) {
  if (error.code === 'MEETING_ALREADY_ACTIVE') {
    console.log('Meeting is already running');
  }
}

// Join a meeting
const participant = await meetingClient.joinMeeting('meeting-id', {
  connectionId: 'conn-123',
  deviceType: 'desktop'
});

// Listen for real-time updates
meetingClient.on('participant_update', (update) => {
  console.log('Participant updated:', update);
});

// Send chat message
await meetingClient.sendChatMessage('meeting-id', {
  content: 'Hello everyone!',
  messageType: 'text'
});
```

### Python

```python
import asyncio
from meeting_sdk import MeetingClient

# Initialize client
client = MeetingClient(
    api_url='https://api.example.com',
    token='your-jwt-token'
)

async def main():
    # Start meeting
    try:
        result = await client.start_meeting('meeting-id')
        print(f"Meeting started: {result}")
    except MeetingError as e:
        if e.code == 'MEETING_ALREADY_ACTIVE':
            print("Meeting is already running")
    
    # Join meeting
    participant = await client.join_meeting('meeting-id', {
        'connection_id': 'conn-123',
        'device_type': 'desktop'
    })
    
    # Send chat message
    await client.send_chat_message('meeting-id', {
        'content': 'Hello from Python!',
        'message_type': 'text'
    })

asyncio.run(main())
```

## Webhooks

### Meeting Events

Configure webhook endpoints to receive meeting event notifications:

#### Meeting Started
```json
{
  "event": "meeting.started",
  "meeting_id": "01HXYZ123456789ABCDEFGHIJK",
  "data": {
    "started_by": "01HXYZ123456789ABCDEFGHIJK",
    "started_at": "2024-01-15T10:00:00Z"
  },
  "timestamp": "2024-01-15T10:00:00Z"
}
```

#### Participant Joined
```json
{
  "event": "participant.joined",
  "meeting_id": "01HXYZ123456789ABCDEFGHIJK",
  "data": {
    "user_id": "01HXYZ123456789ABCDEFGHIJK",
    "role": "attendee",
    "joined_at": "2024-01-15T10:05:00Z"
  },
  "timestamp": "2024-01-15T10:05:00Z"
}
```

#### Meeting Ended
```json
{
  "event": "meeting.ended",
  "meeting_id": "01HXYZ123456789ABCDEFGHIJK",
  "data": {
    "ended_by": "01HXYZ123456789ABCDEFGHIJK",
    "ended_at": "2024-01-15T11:00:00Z",
    "duration_minutes": 60,
    "participant_count": 5
  },
  "timestamp": "2024-01-15T11:00:00Z"
}
```

## Testing

### Test Environment

Use the test environment for development and testing:

- **Base URL**: `https://api-test.example.com`
- **WebSocket URL**: `wss://api-test.example.com/ws`

### Mock Data

Test meetings and users are available for testing purposes. See the test data documentation for available test accounts and meetings.

### Postman Collection

Import our Postman collection for easy API testing:
[Download Postman Collection](./postman/meeting-api.json)

## Support

For API support and questions:

- **Documentation**: [https://docs.example.com/meetings](https://docs.example.com/meetings)
- **Support Email**: api-support@example.com
- **Discord**: [Join our Discord](https://discord.gg/example)
- **GitHub Issues**: [Report issues](https://github.com/example/meeting-api/issues) 