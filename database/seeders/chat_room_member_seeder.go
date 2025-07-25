package seeders

import (
	"fmt"
	"goravel/app/models"
	"time"

	"github.com/goravel/framework/facades"
)

type ChatRoomMemberSeeder struct{}

func (s *ChatRoomMemberSeeder) Signature() string {
	return "ChatRoomMemberSeeder"
}

func (s *ChatRoomMemberSeeder) Run() error {
	facades.Log().Info(fmt.Sprintf("%s started", s.Signature()))
	defer facades.Log().Info(fmt.Sprintf("%s completed", s.Signature()))
	// Example: assign first user to first chat room if both exist
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
	member := models.ChatRoomMember{
		ChatRoomID: room.ID,
		UserID:     user.ID,
		Role:       "member",
		IsActive:   true,
		JoinedAt:   time.Now(),
	}
	facades.Orm().Query().Create(&member)
	return nil
}
