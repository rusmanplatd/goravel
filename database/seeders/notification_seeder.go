package seeders

import (
	"fmt"
	"goravel/app/models"
	"time"

	"github.com/goravel/framework/facades"
)

type NotificationSeeder struct{}

func (s *NotificationSeeder) Signature() string {
	return "NotificationSeeder"
}

func (s *NotificationSeeder) Run() error {
	facades.Log().Info(fmt.Sprintf("%s started", s.Signature()))
	defer facades.Log().Info(fmt.Sprintf("%s completed", s.Signature()))

	// Get some users to send notifications to
	var users []models.User
	err := facades.Orm().Query().Limit(5).Find(&users)
	if err != nil {
		return err
	}
	if len(users) == 0 {
		facades.Log().Warning("No users found for notification seeding")
		return nil
	}

	notificationTypes := []string{"welcome", "reminder", "alert", "system", "chat"}
	channels := []string{"database", "mail", "push"}

	for i, user := range users {
		n := models.Notification{
			Type:           notificationTypes[i%len(notificationTypes)],
			Data:           map[string]interface{}{"message": fmt.Sprintf("This is a %s notification for %s", notificationTypes[i%len(notificationTypes)], user.Name)},
			NotifiableID:   user.ID,
			NotifiableType: "User",
			Channel:        channels[i%len(channels)],
			ReadAt:         nil,
			SentAt:         func() *time.Time { t := time.Now().Add(-time.Duration(i) * time.Hour); return &t }(),
		}
		err := facades.Orm().Query().Create(&n)
		if err != nil {
			facades.Log().Error("Failed to create notification", map[string]interface{}{"error": err.Error(), "user_id": user.ID})
			return err
		}
		facades.Log().Info(fmt.Sprintf("Created notification for user: %s", user.Name))
	}

	return nil
}
