package entity

import (
	"github.com/google/uuid"
	"time"
)

// OAuthClient представляет клиента OAuth 2.0.
type OAuthClient struct {
	ID           uuid.UUID `json:"id"`
	ClinetID     string    `json:"clinet_id"`
	ClinetSecret string    `json:"clinet_secret"`
	RedirectURIs string    `json:"redirect_uris"`
	GrantTypes   string    `json:"grant_types"`
	Scopes       []string  `json:"scopes"`
	IsActive     bool      `json:"is_active"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}
