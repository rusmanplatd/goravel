package seeders

import (
	"fmt"
	"goravel/app/models"

	"github.com/goravel/framework/facades"
)

type ChatMessageSeeder struct{}

func (s *ChatMessageSeeder) Signature() string {
	return "ChatMessageSeeder"
}

func (s *ChatMessageSeeder) Run() error {
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
	msg := models.ChatMessage{
		ChatRoomID:       room.ID,
		SenderID:         user.ID,
		Type:             "text",
		EncryptedContent: "encrypted_hello_world",
	}
	facades.Orm().Query().Create(&msg)
	return nil
}
