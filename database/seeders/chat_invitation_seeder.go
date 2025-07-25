package seeders

import (
	"fmt"
	"goravel/app/models"
	"time"

	"github.com/goravel/framework/facades"
)

type ChatInvitationSeeder struct{}

func (s *ChatInvitationSeeder) Signature() string {
	return "ChatInvitationSeeder"
}

func (s *ChatInvitationSeeder) Run() error {
	facades.Log().Info(fmt.Sprintf("%s started", s.Signature()))
	defer facades.Log().Info(fmt.Sprintf("%s completed", s.Signature()))
	var user models.User
	var room models.ChatRoom
	err := facades.Orm().Query().First(&user)
	if err != nil {
		return nil
	}
	err = facades.Orm().Query().First(&room)
	if err != nil {
		return nil
	}
	invitation := models.ChatInvitation{
		ChatRoomID:    room.ID,
		InvitedUserID: user.ID,
		InviterID:     user.ID,
		Status:        "pending",
		Message:       "Join our chat!",
		ExpiresAt:     func() *time.Time { t := time.Now().Add(24 * time.Hour); return &t }(),
	}
	facades.Orm().Query().Create(&invitation)
	return nil
}
