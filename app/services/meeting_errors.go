package services

import (
	"fmt"
	"net/http"
)

// MeetingError represents a meeting-specific error with code and HTTP status
type MeetingError struct {
	Code       string                 `json:"code"`
	Message    string                 `json:"message"`
	HTTPStatus int                    `json:"-"`
	Details    map[string]interface{} `json:"details,omitempty"`
}

func (e *MeetingError) Error() string {
	return e.Message
}

// Meeting error codes and constructors
const (
	ErrMeetingNotFound        = "MEETING_NOT_FOUND"
	ErrMeetingAlreadyActive   = "MEETING_ALREADY_ACTIVE"
	ErrMeetingNotActive       = "MEETING_NOT_ACTIVE"
	ErrMeetingEnded           = "MEETING_ENDED"
	ErrInsufficientPermission = "INSUFFICIENT_PERMISSION"
	ErrParticipantNotFound    = "PARTICIPANT_NOT_FOUND"
	ErrParticipantExists      = "PARTICIPANT_EXISTS"
	ErrMaxParticipantsReached = "MAX_PARTICIPANTS_REACHED"
	ErrMeetingLocked          = "MEETING_LOCKED"
	ErrWaitingRoomRequired    = "WAITING_ROOM_REQUIRED"
	ErrRecordingFailed        = "RECORDING_FAILED"
	ErrInvalidMeetingState    = "INVALID_MEETING_STATE"
	ErrWebSocketConnection    = "WEBSOCKET_CONNECTION_ERROR"
	ErrLiveKitToken           = "LIVEKIT_TOKEN_ERROR"
	ErrBreakoutRoomFull       = "BREAKOUT_ROOM_FULL"
	ErrChatDisabled           = "CHAT_DISABLED"
	ErrScreenShareDisabled    = "SCREEN_SHARE_DISABLED"
)

// NewMeetingError creates a new meeting error
func NewMeetingError(code, message string, httpStatus int, details ...map[string]interface{}) *MeetingError {
	var det map[string]interface{}
	if len(details) > 0 {
		det = details[0]
	}
	return &MeetingError{
		Code:       code,
		Message:    message,
		HTTPStatus: httpStatus,
		Details:    det,
	}
}

// Predefined error constructors
func ErrMeetingNotFoundError(meetingID string) *MeetingError {
	return NewMeetingError(
		ErrMeetingNotFound,
		"Meeting not found",
		http.StatusNotFound,
		map[string]interface{}{"meeting_id": meetingID},
	)
}

func ErrMeetingAlreadyActiveError(meetingID string) *MeetingError {
	return NewMeetingError(
		ErrMeetingAlreadyActive,
		"Meeting is already active",
		http.StatusConflict,
		map[string]interface{}{"meeting_id": meetingID},
	)
}

func ErrMeetingNotActiveError(meetingID string) *MeetingError {
	return NewMeetingError(
		ErrMeetingNotActive,
		"Meeting is not active",
		http.StatusBadRequest,
		map[string]interface{}{"meeting_id": meetingID},
	)
}

func ErrMeetingEndedError(meetingID string) *MeetingError {
	return NewMeetingError(
		ErrMeetingEnded,
		"Meeting has already ended",
		http.StatusGone,
		map[string]interface{}{"meeting_id": meetingID},
	)
}

func ErrInsufficientPermissionError(action, requiredRole string) *MeetingError {
	return NewMeetingError(
		ErrInsufficientPermission,
		fmt.Sprintf("Insufficient permissions to %s", action),
		http.StatusForbidden,
		map[string]interface{}{
			"action":        action,
			"required_role": requiredRole,
		},
	)
}

func ErrParticipantNotFoundError(userID, meetingID string) *MeetingError {
	return NewMeetingError(
		ErrParticipantNotFound,
		"Participant not found in meeting",
		http.StatusNotFound,
		map[string]interface{}{
			"user_id":    userID,
			"meeting_id": meetingID,
		},
	)
}

func ErrParticipantExistsError(userID, meetingID string) *MeetingError {
	return NewMeetingError(
		ErrParticipantExists,
		"Participant already exists in meeting",
		http.StatusConflict,
		map[string]interface{}{
			"user_id":    userID,
			"meeting_id": meetingID,
		},
	)
}

func ErrMaxParticipantsReachedError(meetingID string, maxParticipants int) *MeetingError {
	return NewMeetingError(
		ErrMaxParticipantsReached,
		"Maximum number of participants reached",
		http.StatusForbidden,
		map[string]interface{}{
			"meeting_id":       meetingID,
			"max_participants": maxParticipants,
		},
	)
}

func ErrMeetingLockedError(meetingID string) *MeetingError {
	return NewMeetingError(
		ErrMeetingLocked,
		"Meeting is locked",
		http.StatusForbidden,
		map[string]interface{}{"meeting_id": meetingID},
	)
}

func ErrWaitingRoomRequiredError(meetingID string) *MeetingError {
	return NewMeetingError(
		ErrWaitingRoomRequired,
		"Waiting room approval required",
		http.StatusAccepted,
		map[string]interface{}{"meeting_id": meetingID},
	)
}

func ErrRecordingFailedError(meetingID, reason string) *MeetingError {
	return NewMeetingError(
		ErrRecordingFailed,
		"Recording failed",
		http.StatusInternalServerError,
		map[string]interface{}{
			"meeting_id": meetingID,
			"reason":     reason,
		},
	)
}

func ErrInvalidMeetingStateError(meetingID, currentState, expectedState string) *MeetingError {
	return NewMeetingError(
		ErrInvalidMeetingState,
		"Invalid meeting state",
		http.StatusBadRequest,
		map[string]interface{}{
			"meeting_id":     meetingID,
			"current_state":  currentState,
			"expected_state": expectedState,
		},
	)
}

func ErrWebSocketConnectionError(reason string) *MeetingError {
	return NewMeetingError(
		ErrWebSocketConnection,
		"WebSocket connection error",
		http.StatusInternalServerError,
		map[string]interface{}{"reason": reason},
	)
}

func ErrLiveKitTokenError(reason string) *MeetingError {
	return NewMeetingError(
		ErrLiveKitToken,
		"Failed to generate LiveKit token",
		http.StatusInternalServerError,
		map[string]interface{}{"reason": reason},
	)
}

func ErrBreakoutRoomFullError(roomID string, capacity int) *MeetingError {
	return NewMeetingError(
		ErrBreakoutRoomFull,
		"Breakout room is full",
		http.StatusForbidden,
		map[string]interface{}{
			"room_id":  roomID,
			"capacity": capacity,
		},
	)
}

func ErrChatDisabledError(meetingID string) *MeetingError {
	return NewMeetingError(
		ErrChatDisabled,
		"Chat is disabled for this meeting",
		http.StatusForbidden,
		map[string]interface{}{"meeting_id": meetingID},
	)
}

func ErrScreenShareDisabledError(meetingID string) *MeetingError {
	return NewMeetingError(
		ErrScreenShareDisabled,
		"Screen sharing is disabled for this meeting",
		http.StatusForbidden,
		map[string]interface{}{"meeting_id": meetingID},
	)
}

// IsMeetingError checks if an error is a MeetingError
func IsMeetingError(err error) (*MeetingError, bool) {
	if meetingErr, ok := err.(*MeetingError); ok {
		return meetingErr, true
	}
	return nil, false
}
