package seeders

import (
	"fmt"
	"goravel/app/models"

	"github.com/goravel/framework/facades"
)

type ChatNotificationSettingsSeeder struct{}

func (s *ChatNotificationSettingsSeeder) Signature() string {
	return "ChatNotificationSettingsSeeder"
}

func (s *ChatNotificationSettingsSeeder) Run() error {
	facades.Log().Info(fmt.Sprintf("%s started", s.Signature()))
	defer facades.Log().Info(fmt.Sprintf("%s completed", s.Signature()))
	var user models.User
	err := facades.Orm().Query().First(&user)
	if err != nil {
		return nil
	}
	setting := models.ChatNotificationSettings{
		UserID:                user.ID,
		EmailNotifications:    true,
		PushNotifications:     true,
		DesktopNotifications:  true,
		MentionNotifications:  true,
		ReactionNotifications: true,
		ThreadNotifications:   true,
		IsMuted:               false,
	}
	facades.Orm().Query().Create(&setting)
	return nil
}
