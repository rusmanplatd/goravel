package seeders

import (
	"fmt"
	"goravel/app/models"
	"time"

	"github.com/goravel/framework/facades"
)

type MessageReadSeeder struct{}

func (s *MessageReadSeeder) Signature() string {
	return "MessageReadSeeder"
}

func (s *MessageReadSeeder) Run() error {
	facades.Log().Info(fmt.Sprintf("%s started", s.Signature()))
	defer facades.Log().Info(fmt.Sprintf("%s completed", s.Signature()))
	var user models.User
	var msg models.ChatMessage
	err := facades.Orm().Query().First(&user)
	if err != nil {
		return nil
	}
	err = facades.Orm().Query().First(&msg)
	if err != nil {
		return nil
	}
	read := models.MessageRead{
		MessageID: msg.ID,
		UserID:    user.ID,
		ReadAt:    time.Now(),
	}
	facades.Orm().Query().Create(&read)
	return nil
}
