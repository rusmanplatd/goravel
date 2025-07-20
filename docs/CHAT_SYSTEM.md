# Chat System with End-to-End Encryption (E2EE)

This document describes the chat system implementation with end-to-end encryption for the Goravel application.

## Overview

The chat system provides secure messaging capabilities with the following features:

- **End-to-End Encryption**: All messages are encrypted using RSA and AES encryption
- **Perfect Forward Secrecy**: Prekey bundles and one-time prekeys for enhanced security
- **Multi-tenant Support**: Chat rooms are isolated by tenant
- **Room Types**: Direct messages, group chats, and channels
- **Role-based Access**: Admin, moderator, and member roles
- **Message Types**: Text, image, file, and system messages
- **Message Reactions**: Emoji reactions with real-time updates
- **Encrypted File Sharing**: Secure file upload and sharing
- **Encrypted Search**: Search capabilities for encrypted content
- **Read Receipts**: Track message read status
- **Real-time Events**: WebSocket support for live updates
- **Key Management**: Automatic key generation and rotation

## Architecture

### Models

#### ChatRoom
- Represents a chat room/conversation
- Supports different types: direct, group, channel
- Multi-tenant with tenant isolation
- Tracks last activity and member count

#### ChatMessage
- Encrypted message content
- Supports different message types
- Threaded conversations with reply support
- Message status tracking (sent, delivered, read)

#### ChatRoomMember
- Room membership with roles
- Public key storage for E2EE
- Read status tracking
- Join/leave timestamps

#### MessageReaction
- Emoji reactions to messages
- User tracking for reactions
- Real-time reaction updates

#### UserKey
- User's encryption key pairs
- Supports different key types (identity, prekeys)
- Key versioning and rotation
- Secure private key storage

#### ChatRoomKey
- Room-level encryption keys
- Encrypted for each member
- Key rotation support
- Version tracking

### Services

#### E2EEService
Handles all encryption/decryption operations:

- **Key Generation**: RSA key pairs for users
- **Perfect Forward Secrecy**: Prekey bundles and one-time prekeys
- **Message Encryption**: AES-256-GCM for message content
- **File Encryption**: AES-256-GCM for file content
- **Room Key Management**: ChaCha20-Poly1305 for group messages
- **Key Rotation**: Automatic key updates
- **Signature Verification**: Message authenticity
- **Encrypted Search**: Searchable encryption for messages

#### ChatService
Manages chat operations:

- **Room Management**: Create, update, delete rooms
- **Message Handling**: Send, retrieve, decrypt messages
- **Reaction Management**: Add, remove, track reactions
- **File Sharing**: Encrypted file upload and download
- **Member Management**: Add, remove, role management
- **Read Status**: Track message read receipts
- **Real-time Events**: WebSocket event broadcasting

## API Endpoints

### Chat Rooms

```
GET    /api/v1/chat/rooms              # Get user's chat rooms
POST   /api/v1/chat/rooms              # Create new chat room
GET    /api/v1/chat/rooms/{id}         # Get specific chat room
PUT    /api/v1/chat/rooms/{id}         # Update chat room
DELETE /api/v1/chat/rooms/{id}         # Delete chat room
```

### Messages

```
GET    /api/v1/chat/rooms/{id}/messages    # Get room messages
POST   /api/v1/chat/rooms/{id}/messages    # Send message
POST   /api/v1/chat/rooms/{id}/read        # Mark room as read
```

### Message Reactions

```
POST   /api/v1/chat/rooms/{id}/messages/{message_id}/reactions     # Add reaction
DELETE /api/v1/chat/rooms/{id}/messages/{message_id}/reactions     # Remove reaction
GET    /api/v1/chat/rooms/{id}/messages/{message_id}/reactions     # Get reactions
GET    /api/v1/chat/rooms/{id}/messages/{message_id}/reactions/summary  # Get reaction summary
```

### Members

```
GET    /api/v1/chat/rooms/{id}/members         # Get room members
POST   /api/v1/chat/rooms/{id}/members         # Add member
DELETE /api/v1/chat/rooms/{id}/members/{user}  # Remove member
```

### Encryption Keys

```
GET    /api/v1/chat/keys                       # Get user keys
POST   /api/v1/chat/keys                       # Generate key pair
POST   /api/v1/chat/rooms/{id}/rotate-key      # Rotate room key
```

## Encryption Flow

### Perfect Forward Secrecy (PFS)
1. User generates identity key pair
2. User generates signed prekey and one-time prekeys
3. Prekey bundle shared with other users
4. Messages use ephemeral keys for each session
5. Keys are rotated regularly for security

### Direct Messages
1. Sender generates random AES key
2. Message encrypted with AES-256-GCM
3. AES key encrypted with recipient's public RSA key
4. Encrypted message + encrypted key sent to server
5. Recipient decrypts AES key with private RSA key
6. Recipient decrypts message with AES key

### Group Messages
1. Room has shared ChaCha20-Poly1305 key
2. Key encrypted for each member with their public RSA key
3. Messages encrypted with room key
4. Members decrypt room key with private RSA key
5. Members decrypt messages with room key

### File Sharing
1. File encrypted with AES-256-GCM
2. File key encrypted for each recipient
3. Encrypted file stored on server
4. Recipients decrypt file key and file content

### Key Rotation
1. Admin triggers key rotation
2. New room key generated
3. Old key deactivated
4. New key encrypted for all members
5. Future messages use new key

## Real-time Events

### Event Types
- `message_sent`: New message sent
- `message_received`: Message received
- `message_read`: Message marked as read
- `member_joined`: New member joined room
- `member_left`: Member left room
- `reaction_added`: Reaction added to message
- `reaction_removed`: Reaction removed from message
- `room_updated`: Room information updated
- `key_rotated`: Room key rotated

### WebSocket Events
```json
{
  "type": "message_sent",
  "room_id": "room_123",
  "user_id": "user_456",
  "data": {
    "message_id": "msg_789",
    "content": "Hello, world!",
    "timestamp": "2024-01-15T10:30:00Z"
  },
  "timestamp": "2024-01-15T10:30:00Z"
}
```

## Security Features

### End-to-End Encryption
- Messages encrypted on client before transmission
- Server cannot decrypt message content
- Only intended recipients can decrypt messages

### Perfect Forward Secrecy
- Ephemeral keys for each session
- Prekey bundles for key exchange
- One-time prekeys for enhanced security
- Regular key rotation

### Key Management
- RSA-2048 for key exchange
- AES-256-GCM for message encryption
- ChaCha20-Poly1305 for group messages
- Automatic key rotation

### Access Control
- Multi-tenant isolation
- Role-based permissions
- Member-only access to rooms
- Admin-only room management

### Message Integrity
- Cryptographic signatures
- Message tampering detection
- Version tracking for encryption

### Encrypted Search
- Searchable symmetric encryption
- Content hashing for integrity
- Privacy-preserving search

## Database Schema

### Tables
- `chat_rooms`: Room information and metadata
- `chat_room_members`: Room membership and roles
- `chat_messages`: Encrypted message content
- `message_reactions`: Message reactions
- `message_reads`: Read receipt tracking
- `user_keys`: User encryption keys
- `chat_room_keys`: Room encryption keys
- `chat_invitations`: Room invitation system

### Indexes
- Optimized for message retrieval
- User membership queries
- Room activity tracking
- Key lookups
- Reaction queries

## Usage Examples

### Creating a Chat Room

```go
chatService := services.NewChatService()

chatRoom, err := chatService.CreateChatRoom(
    "Team Discussion",
    "Main team channel",
    "group",
    tenantID,
    userID,
    []string{"user1", "user2", "user3"},
)
```

### Sending a Message

```go
message, err := chatService.SendMessageWithNotification(
    roomID,
    senderID,
    "text",
    "Hello, team!",
    nil,
    nil,
)
```

### Adding a Reaction

```go
reaction, err := chatService.AddMessageReactionWithNotification(
    messageID,
    userID,
    "👍",
)
```

### Sharing an Encrypted File

```go
e2eeService := services.NewE2EEService()

fileData := []byte("sensitive file content")
encryptedFile, err := e2eeService.EncryptFile(
    fileData,
    "document.pdf",
    "application/pdf",
    []string{recipientPublicKey},
)
```

### Generating PFS Keys

```go
e2eeService := services.NewE2EEService()

prekeyBundle, err := e2eeService.GeneratePrekeyBundle(userID, deviceID)
if err != nil {
    // Handle error
}

// Save keys to database
for _, prekey := range prekeyBundle.OneTimePrekeys {
    userKey := &models.UserKey{
        UserID:             userID,
        KeyType:            "one_time_prekey",
        PublicKey:          prekey.PublicKey,
        EncryptedPrivateKey: prekey.PrivateKey,
        Version:            1,
        IsActive:           true,
    }
    e2eeService.SaveUserKey(userKey)
}
```

## Testing

Run the chat system tests:

```bash
go test ./tests/feature/chat_test.go -v
```

Tests cover:
- E2EE encryption/decryption
- Perfect Forward Secrecy
- Message reactions
- Encrypted file sharing
- Encrypted search
- Real-time events
- Chat room operations
- Message handling
- Key management
- API endpoints

## Security Considerations

### Key Storage
- Private keys should be encrypted with user password
- Consider hardware security modules (HSM)
- Implement key backup and recovery

### Key Rotation
- Regular key rotation for security
- Graceful key transition
- Backward compatibility for old messages

### Perfect Forward Secrecy
- Use ephemeral keys for each session
- Implement prekey bundle rotation
- Secure key deletion after use

### Message Retention
- Consider message expiration
- Implement secure deletion
- Audit trail for compliance

### Network Security
- Use HTTPS for all API calls
- Implement certificate pinning
- Rate limiting for API endpoints
- WebSocket over WSS

### File Security
- Encrypt files before upload
- Implement file size limits
- Scan for malware
- Secure file deletion

## Future Enhancements

### Planned Features
- Voice/video call support
- Advanced message threading
- Message editing and deletion
- Advanced search capabilities
- Message reactions with custom emojis
- File preview and thumbnails
- Message translation
- Advanced notification settings

### Performance Optimizations
- Message caching
- Pagination improvements
- WebSocket connection pooling
- Database query optimization
- CDN integration for files

### Security Improvements
- Post-quantum cryptography
- Advanced key management
- Security audit tools
- Penetration testing
- Compliance certifications

## Troubleshooting

### Common Issues

1. **Message Decryption Fails**
   - Check user key validity
   - Verify encryption version
   - Ensure proper key rotation

2. **Room Access Denied**
   - Verify user membership
   - Check tenant isolation
   - Validate user permissions

3. **Key Generation Errors**
   - Check cryptographic libraries
   - Verify system entropy
   - Review key storage permissions

4. **Reaction Not Working**
   - Check message exists
   - Verify user membership
   - Check emoji format

5. **File Upload Fails**
   - Check file size limits
   - Verify encryption keys
   - Check storage permissions

### Debug Mode

Enable debug logging for troubleshooting:

```go
facades.Log().SetLevel("debug")
```

## Support

For issues and questions:
- Check the test suite for examples
- Review API documentation
- Consult security best practices
- Contact the development team 