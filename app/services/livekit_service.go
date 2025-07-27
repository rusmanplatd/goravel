package services

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"goravel/app/models"

	"github.com/golang-jwt/jwt/v5"
	"github.com/goravel/framework/facades"
	"github.com/livekit/protocol/livekit"
	lksdk "github.com/livekit/server-sdk-go/v2"
)

// LiveKitService handles LiveKit integration
type LiveKitService struct {
	client    *lksdk.RoomServiceClient
	apiKey    string
	apiSecret string
	serverURL string
}

// LiveKitTokenClaims represents the claims for LiveKit JWT tokens
type LiveKitTokenClaims struct {
	jwt.RegisteredClaims
	Video *VideoGrant `json:"video,omitempty"`
}

// VideoGrant represents video permissions for LiveKit
type VideoGrant struct {
	Room                 string `json:"room,omitempty"`
	RoomJoin             bool   `json:"roomJoin,omitempty"`
	RoomList             bool   `json:"roomList,omitempty"`
	RoomRecord           bool   `json:"roomRecord,omitempty"`
	RoomAdmin            bool   `json:"roomAdmin,omitempty"`
	RoomCreate           bool   `json:"roomCreate,omitempty"`
	IngressAdmin         bool   `json:"ingressAdmin,omitempty"`
	Hidden               bool   `json:"hidden,omitempty"`
	Recorder             bool   `json:"recorder,omitempty"`
	CanPublish           bool   `json:"canPublish,omitempty"`
	CanSubscribe         bool   `json:"canSubscribe,omitempty"`
	CanPublishData       bool   `json:"canPublishData,omitempty"`
	CanUpdateOwnMetadata bool   `json:"canUpdateOwnMetadata,omitempty"`
}

// LiveKitRoomInfo represents room information
type LiveKitRoomInfo struct {
	Name            string                 `json:"name"`
	DisplayName     string                 `json:"display_name"`
	Metadata        string                 `json:"metadata"`
	MaxParticipants uint32                 `json:"max_participants"`
	EmptyTimeout    uint32                 `json:"empty_timeout"`
	CreationTime    time.Time              `json:"creation_time"`
	TurnPassword    string                 `json:"turn_password"`
	EnabledCodecs   []string               `json:"enabled_codecs"`
	Settings        map[string]interface{} `json:"settings"`
}

// LiveKitParticipantInfo represents participant information
type LiveKitParticipantInfo struct {
	Identity    string                         `json:"identity"`
	Name        string                         `json:"name"`
	Metadata    string                         `json:"metadata"`
	Permission  *livekit.ParticipantPermission `json:"permission"`
	Region      string                         `json:"region"`
	IsPublisher bool                           `json:"is_publisher"`
	Kind        livekit.ParticipantInfo_Kind   `json:"kind"`
}

// NewLiveKitService creates a new LiveKit service
func NewLiveKitService() *LiveKitService {
	apiKey := facades.Config().GetString("livekit.server.api_key")
	apiSecret := facades.Config().GetString("livekit.server.api_secret")
	serverURL := facades.Config().GetString("livekit.server.url")

	if apiKey == "" || apiSecret == "" {
		facades.Log().Warning("LiveKit API key or secret not configured")
		return &LiveKitService{}
	}

	client := lksdk.NewRoomServiceClient(serverURL, apiKey, apiSecret)

	return &LiveKitService{
		client:    client,
		apiKey:    apiKey,
		apiSecret: apiSecret,
		serverURL: serverURL,
	}
}

// GenerateAccessToken generates a JWT token for LiveKit room access
func (s *LiveKitService) GenerateAccessToken(meetingID, userID, userName string, isHost bool) (string, error) {
	if s.apiKey == "" || s.apiSecret == "" {
		return "", fmt.Errorf("LiveKit not configured")
	}

	// Set token expiration
	ttl := time.Duration(facades.Config().GetInt("livekit.security.token_ttl", 3600)) * time.Second
	expiresAt := time.Now().Add(ttl)

	// Create video grant with appropriate permissions
	grant := &VideoGrant{
		Room:                 meetingID,
		RoomJoin:             true,
		RoomList:             isHost,
		RoomRecord:           isHost,
		RoomAdmin:            isHost,
		RoomCreate:           isHost,
		IngressAdmin:         isHost,
		Hidden:               false,
		Recorder:             false,
		CanPublish:           true,
		CanSubscribe:         true,
		CanPublishData:       true,
		CanUpdateOwnMetadata: true,
	}

	// Create JWT claims
	claims := &LiveKitTokenClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    s.apiKey,
			Subject:   userID,
			Audience:  []string{meetingID},
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			NotBefore: jwt.NewNumericDate(time.Now()),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ID:        generateJTI(),
		},
		Video: grant,
	}

	// Sign the token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(s.apiSecret))
	if err != nil {
		return "", fmt.Errorf("failed to sign token: %v", err)
	}

	facades.Log().Info("Generated LiveKit access token", map[string]interface{}{
		"meeting_id": meetingID,
		"user_id":    userID,
		"user_name":  userName,
		"is_host":    isHost,
		"expires_at": expiresAt,
	})

	return tokenString, nil
}

// CreateRoom creates a new LiveKit room
func (s *LiveKitService) CreateRoom(ctx context.Context, meetingID string, meeting *models.Meeting) (*LiveKitRoomInfo, error) {
	if s.client == nil {
		return nil, fmt.Errorf("LiveKit client not initialized")
	}

	// Prepare room metadata
	metadata := map[string]interface{}{
		"meeting_id":   meetingID,
		"title":        meeting.Event.Title,
		"description":  meeting.Event.Description,
		"created_at":   time.Now(),
		"recording":    meeting.RecordMeeting,
		"waiting_room": meeting.WaitingRoom,
	}

	metadataJSON, _ := json.Marshal(metadata)

	// Create room request
	req := &livekit.CreateRoomRequest{
		Name:            meetingID,
		EmptyTimeout:    uint32(facades.Config().GetInt("livekit.room.empty_timeout", 300)),
		MaxParticipants: uint32(facades.Config().GetInt("livekit.room.max_participants", 100)),
		Metadata:        string(metadataJSON),
	}

	// Create the room
	room, err := s.client.CreateRoom(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("failed to create LiveKit room: %v", err)
	}

	roomInfo := &LiveKitRoomInfo{
		Name:            room.Name,
		DisplayName:     meeting.Event.Title,
		Metadata:        room.Metadata,
		MaxParticipants: room.MaxParticipants,
		EmptyTimeout:    room.EmptyTimeout,
		CreationTime:    time.Unix(room.CreationTime, 0),
		TurnPassword:    room.TurnPassword,
		EnabledCodecs:   []string{}, // Convert from []*livekit.Codec if needed
		Settings:        metadata,
	}

	facades.Log().Info("Created LiveKit room", map[string]interface{}{
		"room_name":        room.Name,
		"meeting_id":       meetingID,
		"max_participants": room.MaxParticipants,
		"empty_timeout":    room.EmptyTimeout,
	})

	return roomInfo, nil
}

// GetRoom retrieves room information
func (s *LiveKitService) GetRoom(ctx context.Context, roomName string) (*LiveKitRoomInfo, error) {
	if s.client == nil {
		return nil, fmt.Errorf("LiveKit client not initialized")
	}

	rooms, err := s.client.ListRooms(ctx, &livekit.ListRoomsRequest{
		Names: []string{roomName},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get room: %v", err)
	}

	if len(rooms.Rooms) == 0 {
		return nil, fmt.Errorf("room not found")
	}

	room := rooms.Rooms[0]
	var metadata map[string]interface{}
	if room.Metadata != "" {
		json.Unmarshal([]byte(room.Metadata), &metadata)
	}

	return &LiveKitRoomInfo{
		Name:            room.Name,
		DisplayName:     room.Metadata,
		Metadata:        room.Metadata,
		MaxParticipants: room.MaxParticipants,
		EmptyTimeout:    room.EmptyTimeout,
		CreationTime:    time.Unix(room.CreationTime, 0),
		TurnPassword:    room.TurnPassword,
		EnabledCodecs:   []string{}, // Convert from []*livekit.Codec if needed
		Settings:        metadata,
	}, nil
}

// DeleteRoom deletes a LiveKit room
func (s *LiveKitService) DeleteRoom(ctx context.Context, roomName string) error {
	if s.client == nil {
		return fmt.Errorf("LiveKit client not initialized")
	}

	_, err := s.client.DeleteRoom(ctx, &livekit.DeleteRoomRequest{
		Room: roomName,
	})
	if err != nil {
		return fmt.Errorf("failed to delete room: %v", err)
	}

	facades.Log().Info("Deleted LiveKit room", map[string]interface{}{
		"room_name": roomName,
	})

	return nil
}

// ListParticipants lists participants in a room
func (s *LiveKitService) ListParticipants(ctx context.Context, roomName string) ([]*LiveKitParticipantInfo, error) {
	if s.client == nil {
		return nil, fmt.Errorf("LiveKit client not initialized")
	}

	resp, err := s.client.ListParticipants(ctx, &livekit.ListParticipantsRequest{
		Room: roomName,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to list participants: %v", err)
	}

	var participants []*LiveKitParticipantInfo
	for _, p := range resp.Participants {
		participants = append(participants, &LiveKitParticipantInfo{
			Identity:    p.Identity,
			Name:        p.Name,
			Metadata:    p.Metadata,
			Permission:  p.Permission,
			Region:      p.Region,
			IsPublisher: p.IsPublisher,
			Kind:        p.Kind,
		})
	}

	return participants, nil
}

// UpdateParticipant updates participant permissions
func (s *LiveKitService) UpdateParticipant(ctx context.Context, roomName, identity string, metadata string, permission *livekit.ParticipantPermission) error {
	if s.client == nil {
		return fmt.Errorf("LiveKit client not initialized")
	}

	req := &livekit.UpdateParticipantRequest{
		Room:       roomName,
		Identity:   identity,
		Metadata:   metadata,
		Permission: permission,
	}

	_, err := s.client.UpdateParticipant(ctx, req)
	if err != nil {
		return fmt.Errorf("failed to update participant: %v", err)
	}

	facades.Log().Info("Updated LiveKit participant", map[string]interface{}{
		"room_name": roomName,
		"identity":  identity,
	})

	return nil
}

// RemoveParticipant removes a participant from the room
func (s *LiveKitService) RemoveParticipant(ctx context.Context, roomName, identity string) error {
	if s.client == nil {
		return fmt.Errorf("LiveKit client not initialized")
	}

	_, err := s.client.RemoveParticipant(ctx, &livekit.RoomParticipantIdentity{
		Room:     roomName,
		Identity: identity,
	})
	if err != nil {
		return fmt.Errorf("failed to remove participant: %v", err)
	}

	facades.Log().Info("Removed LiveKit participant", map[string]interface{}{
		"room_name": roomName,
		"identity":  identity,
	})

	return nil
}

// MuteParticipant mutes a participant's track
func (s *LiveKitService) MuteParticipant(ctx context.Context, roomName, identity string, trackSid string, muted bool) error {
	if s.client == nil {
		return fmt.Errorf("LiveKit client not initialized")
	}

	_, err := s.client.MutePublishedTrack(ctx, &livekit.MuteRoomTrackRequest{
		Room:     roomName,
		Identity: identity,
		TrackSid: trackSid,
		Muted:    muted,
	})
	if err != nil {
		return fmt.Errorf("failed to mute participant: %v", err)
	}

	action := "muted"
	if !muted {
		action = "unmuted"
	}

	facades.Log().Info("Participant "+action, map[string]interface{}{
		"room_name": roomName,
		"identity":  identity,
		"track_sid": trackSid,
	})

	return nil
}

// StartRecording starts room recording
func (s *LiveKitService) StartRecording(ctx context.Context, roomName string, template string) (*livekit.EgressInfo, error) {
	if s.client == nil {
		return nil, fmt.Errorf("LiveKit client not initialized")
	}

	// Get recording template settings
	templateConfig := facades.Config().Get("livekit.recording.templates." + template)
	if templateConfig == nil {
		templateConfig = facades.Config().Get("livekit.recording.templates.default")
	}

	// Create egress client for recording
	egressClient := lksdk.NewEgressClient(s.serverURL, s.apiKey, s.apiSecret)

	// Configure recording output
	output := &livekit.EncodedFileOutput{
		FileType: livekit.EncodedFileType_MP4,
		Filepath: fmt.Sprintf("recordings/%s/%s.mp4", roomName, time.Now().Format("2006-01-02-15-04-05")),
	}

	// Get layout from template config
	layout := "grid"
	if templateMap, ok := templateConfig.(map[string]interface{}); ok {
		if layoutStr, ok := templateMap["layout"].(string); ok {
			layout = layoutStr
		}
	}

	// Start room composite recording
	req := &livekit.RoomCompositeEgressRequest{
		RoomName: roomName,
		Layout:   layout,
		Output: &livekit.RoomCompositeEgressRequest_File{
			File: output,
		},
	}

	resp, err := egressClient.StartRoomCompositeEgress(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("failed to start recording: %v", err)
	}

	facades.Log().Info("Started LiveKit recording", map[string]interface{}{
		"room_name": roomName,
		"egress_id": resp.EgressId,
		"template":  template,
		"file_path": output.Filepath,
	})

	return resp, nil
}

// StopRecording stops room recording
func (s *LiveKitService) StopRecording(ctx context.Context, egressID string) error {
	if s.client == nil {
		return fmt.Errorf("LiveKit client not initialized")
	}

	egressClient := lksdk.NewEgressClient(s.serverURL, s.apiKey, s.apiSecret)

	_, err := egressClient.StopEgress(ctx, &livekit.StopEgressRequest{
		EgressId: egressID,
	})
	if err != nil {
		return fmt.Errorf("failed to stop recording: %v", err)
	}

	facades.Log().Info("Stopped LiveKit recording", map[string]interface{}{
		"egress_id": egressID,
	})

	return nil
}

// CreateBreakoutRoom creates a breakout room
func (s *LiveKitService) CreateBreakoutRoom(ctx context.Context, parentRoomName, breakoutRoomName string, maxParticipants uint32) (*LiveKitRoomInfo, error) {
	if s.client == nil {
		return nil, fmt.Errorf("LiveKit client not initialized")
	}

	// Create metadata for breakout room
	metadata := map[string]interface{}{
		"type":             "breakout",
		"parent_room":      parentRoomName,
		"created_at":       time.Now(),
		"max_participants": maxParticipants,
	}

	metadataJSON, _ := json.Marshal(metadata)

	// Create breakout room
	req := &livekit.CreateRoomRequest{
		Name:            breakoutRoomName,
		EmptyTimeout:    300, // 5 minutes
		MaxParticipants: maxParticipants,
		Metadata:        string(metadataJSON),
	}

	room, err := s.client.CreateRoom(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("failed to create breakout room: %v", err)
	}

	roomInfo := &LiveKitRoomInfo{
		Name:            room.Name,
		DisplayName:     breakoutRoomName,
		Metadata:        room.Metadata,
		MaxParticipants: room.MaxParticipants,
		EmptyTimeout:    room.EmptyTimeout,
		CreationTime:    time.Unix(room.CreationTime, 0),
		Settings:        metadata,
	}

	facades.Log().Info("Created LiveKit breakout room", map[string]interface{}{
		"parent_room":      parentRoomName,
		"breakout_room":    breakoutRoomName,
		"max_participants": maxParticipants,
	})

	return roomInfo, nil
}

// MoveParticipantToBreakoutRoom moves a participant to a breakout room
func (s *LiveKitService) MoveParticipantToBreakoutRoom(ctx context.Context, fromRoom, toRoom, identity string) error {
	// This would require custom signaling through data messages
	// For now, we'll use the room's data channel to send move instructions
	if s.client == nil {
		return fmt.Errorf("LiveKit client not initialized")
	}

	// Send data message to participant
	data := map[string]interface{}{
		"type":        "move_to_breakout",
		"target_room": toRoom,
		"timestamp":   time.Now(),
	}

	dataJSON, _ := json.Marshal(data)

	_, err := s.client.SendData(ctx, &livekit.SendDataRequest{
		Room:            fromRoom,
		Data:            dataJSON,
		Kind:            livekit.DataPacket_RELIABLE,
		DestinationSids: []string{identity},
	})

	if err != nil {
		return fmt.Errorf("failed to send breakout room move instruction: %v", err)
	}

	facades.Log().Info("Sent breakout room move instruction", map[string]interface{}{
		"from_room": fromRoom,
		"to_room":   toRoom,
		"identity":  identity,
	})

	return nil
}

// GetRoomStats gets room statistics
func (s *LiveKitService) GetRoomStats(ctx context.Context, roomName string) (map[string]interface{}, error) {
	if s.client == nil {
		return nil, fmt.Errorf("LiveKit client not initialized")
	}

	// Get room info
	room, err := s.GetRoom(ctx, roomName)
	if err != nil {
		return nil, err
	}

	// Get participants
	participants, err := s.ListParticipants(ctx, roomName)
	if err != nil {
		return nil, err
	}

	stats := map[string]interface{}{
		"room_name":         room.Name,
		"participant_count": len(participants),
		"max_participants":  room.MaxParticipants,
		"creation_time":     room.CreationTime,
		"duration":          time.Since(room.CreationTime).Seconds(),
		"participants":      participants,
	}

	return stats, nil
}

// IsHealthy checks if LiveKit service is healthy
func (s *LiveKitService) IsHealthy(ctx context.Context) bool {
	if s.client == nil {
		return false
	}

	// Try to list rooms as a health check
	_, err := s.client.ListRooms(ctx, &livekit.ListRoomsRequest{})
	return err == nil
}

// generateJTI generates a unique JWT ID
func generateJTI() string {
	bytes := make([]byte, 16)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}
