package seeders

import (
	"fmt"
	"goravel/app/models"

	"github.com/goravel/framework/facades"
)

type ChatRoomSeeder struct{}

func (s *ChatRoomSeeder) Signature() string {
	return "ChatRoomSeeder"
}

func (s *ChatRoomSeeder) Run() error {
	facades.Log().Info(fmt.Sprintf("%s started", s.Signature()))
	defer facades.Log().Info(fmt.Sprintf("%s completed", s.Signature()))
	var user models.User
	err := facades.Orm().Query().First(&user)
	if err != nil {
		return nil
	}
	room := models.ChatRoom{
		Name:        "General",
		Type:        "group",
		IsActive:    true,
		Description: "Main discussion channel",
	}
	facades.Orm().Query().Create(&room)
	return nil
}
