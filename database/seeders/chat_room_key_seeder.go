package seeders

import (
	"fmt"
	"goravel/app/models"

	"github.com/goravel/framework/facades"
)

type ChatRoomKeySeeder struct{}

func (s *ChatRoomKeySeeder) Signature() string {
	return "ChatRoomKeySeeder"
}

func (s *ChatRoomKeySeeder) Run() error {
	facades.Log().Info(fmt.Sprintf("%s started", s.Signature()))
	defer facades.Log().Info(fmt.Sprintf("%s completed", s.Signature()))
	var room models.ChatRoom
	err := facades.Orm().Query().First(&room)
	if err != nil {
		return nil
	}
	key := models.ChatRoomKey{
		ChatRoomID:   room.ID,
		KeyType:      "room_key",
		EncryptedKey: "sample_encrypted_key",
	}
	facades.Orm().Query().Create(&key)
	return nil
}
