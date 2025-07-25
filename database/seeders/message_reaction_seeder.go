package seeders

import (
	"fmt"
	"goravel/app/models"
	"time"

	"github.com/goravel/framework/facades"
)

type MessageReactionSeeder struct{}

func (s *MessageReactionSeeder) Signature() string {
	return "MessageReactionSeeder"
}

func (s *MessageReactionSeeder) Run() error {
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
	reaction := models.MessageReaction{
		MessageID: msg.ID,
		UserID:    user.ID,
		Emoji:     "👍",
		ReactedAt: time.Now(),
	}
	facades.Orm().Query().Create(&reaction)
	return nil
}
