package seeders

import (
	"fmt"
	"goravel/app/models"

	"github.com/goravel/framework/facades"
)

type UserKeySeeder struct{}

func (s *UserKeySeeder) Signature() string {
	return "UserKeySeeder"
}

func (s *UserKeySeeder) Run() error {
	facades.Log().Info(fmt.Sprintf("%s started", s.Signature()))
	defer facades.Log().Info(fmt.Sprintf("%s completed", s.Signature()))
	var user models.User
	err := facades.Orm().Query().First(&user)
	if err != nil {
		return nil
	}
	key := models.UserKey{
		UserID:              user.ID,
		KeyType:             "identity",
		PublicKey:           "-----BEGIN PUBLIC KEY-----...",
		EncryptedPrivateKey: "encrypted_private_key_data",
	}
	facades.Orm().Query().Create(&key)
	return nil
}
