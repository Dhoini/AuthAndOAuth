package entity

import (
	"time"
	"github.com/google/uuid"
)

// GrantType определяет тип авторизации OAuth
type GrantType string

const (
	GrantTypeAuthCode     GrantType = "authorization_code"
	GrantTypeClientCreds  GrantType = "client_credentials"
	GrantTypeRefreshToken GrantType = "refresh_token"
	GrantTypePassword     GrantType = "password"
)

// Client представляет OAuth клиента
type Client struct {
	ID           uuid.UUID   `json:"id" validate:"required"`
	ClientID     string      `json:"client_id" validate:"required"`
	ClientSecret string      `json:"-" validate:"required"`
	Name         string      `json:"name" validate:"required"`
	Description  string      `json:"description,omitempty"`
	RedirectURIs []string    `json:"redirect_uris" validate:"required,dive,url"`
	GrantTypes   []GrantType `json:"grant_types" validate:"required,dive,oneof=authorization_code client_credentials refresh_token password"`
	Scopes       []string    `json:"scopes" validate:"required,dive,required"`
	Active       bool        `json:"active"`
	CreatedAt    time.Time   `json:"created_at" validate:"required"`
	UpdatedAt    time.Time   `json:"updated_at" validate:"required"`
}

// NewClient создает нового OAuth клиента
func NewClient(name, description string, redirectURIs []string, grantTypes []GrantType, scopes []string) *Client {
	now := time.Now()
	return &Client{
		ID:           uuid.New(),
		ClientID:     uuid.New().String(),
		ClientSecret: uuid.New().String(),
		Name:         name,
		Description:  description,
		RedirectURIs: redirectURIs,
		GrantTypes:   grantTypes,
		Scopes:       scopes,
		Active:       true,
		CreatedAt:    now,
		UpdatedAt:    now,
	}
}

// IsGrantTypeAllowed проверяет, разрешен ли тип авторизации
func (c *Client) IsGrantTypeAllowed(grantType GrantType) bool {
	for _, gt := range c.GrantTypes {
		if gt == grantType {
			return true
		}
	}
	return false
}

// IsScopeAllowed проверяет, разрешена ли область действия
func (c *Client) IsScopeAllowed(scope string) bool {
	for _, s := range c.Scopes {
		if s == scope {
			return true
		}
	}
	return false
}

// IsRedirectURIAllowed проверяет, разрешен ли URI перенаправления
func (c *Client) IsRedirectURIAllowed(uri string) bool {
	for _, redirectURI := range c.RedirectURIs {
		if redirectURI == uri {
			return true
		}
	}
	return false
}

// Deactivate деактивирует клиента
func (c *Client) Deactivate() {
	c.Active = false
	c.UpdatedAt = time.Now()
}

// Activate активирует клиента
func (c *Client) Activate() {
	c.Active = true
	c.UpdatedAt = time.Now()
} 