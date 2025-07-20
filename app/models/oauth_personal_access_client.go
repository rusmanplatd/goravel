package models

import (
	"time"

	"github.com/goravel/framework/facades"
)

// OAuthPersonalAccessClient represents a personal access client
type OAuthPersonalAccessClient struct {
	ID        string    `json:"id" gorm:"primaryKey;type:varchar(26)"`
	ClientID  string    `json:"client_id" gorm:"type:varchar(26);index"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`

	// Relationships
	Client *OAuthClient `json:"client,omitempty" gorm:"foreignKey:ClientID"`
}

// TableName specifies the table name for OAuthPersonalAccessClient
func (OAuthPersonalAccessClient) TableName() string {
	return "oauth_personal_access_clients"
}

// GetClient returns the client associated with this personal access client
func (pac *OAuthPersonalAccessClient) GetClient() *OAuthClient {
	var client OAuthClient
	if err := facades.Orm().Query().Where("id", pac.ClientID).First(&client); err != nil {
		return nil
	}
	return &client
}
