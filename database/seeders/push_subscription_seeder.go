package seeders

import (
	"fmt"
	"goravel/app/models"

	"github.com/goravel/framework/facades"
)

type PushSubscriptionSeeder struct {
}

// Signature The name and signature of the seeder.
func (s *PushSubscriptionSeeder) Signature() string {
	return "PushSubscriptionSeeder"
}

// Run executes the seeder logic.
func (s *PushSubscriptionSeeder) Run() error {
	facades.Log().Info(fmt.Sprintf("%s started", s.Signature()))
	defer facades.Log().Info(fmt.Sprintf("%s completed", s.Signature()))

	// Get users to associate subscriptions with
	var users []models.User
	err := facades.Orm().Query().Limit(10).Find(&users)
	if err != nil {
		return err
	}

	if len(users) == 0 {
		facades.Log().Warning("No users found, skipping push subscription seeding")
		return nil
	}

	// Create sample push subscriptions
	for i, user := range users {
		// Create 1-2 subscriptions per user
		numSubscriptions := 1
		if i%3 == 0 { // Every 3rd user gets 2 subscriptions
			numSubscriptions = 2
		}

		for j := 0; j < numSubscriptions; j++ {
			// Generate different endpoint and keys for each subscription
			endpoint := "https://fcm.googleapis.com/fcm/send/" + user.ID + "_" + string(rune('a'+j))
			authKey := "auth_key_" + user.ID + "_" + string(rune('a'+j))
			p256dhKey := "p256dh_key_" + user.ID + "_" + string(rune('a'+j))

			// Check if subscription already exists
			var existingSubscription models.PushSubscription
			err := facades.Orm().Query().Where("endpoint = ?", endpoint).First(&existingSubscription)
			if err == nil {
				continue // Subscription already exists
			}

			subscription := models.PushSubscription{
				UserID:          user.ID,
				Endpoint:        endpoint,
				P256dhKey:       p256dhKey,
				AuthToken:       authKey,
				ContentEncoding: "aes128gcm",
				IsActive:        true,
			}

			err = facades.Orm().Query().Create(&subscription)
			if err != nil {
				facades.Log().Error("Failed to create push subscription: " + err.Error())
				return err
			}

			facades.Log().Info("Created push subscription for user: " + user.Name)
		}
	}

	return nil
}
