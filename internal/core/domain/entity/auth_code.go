package entity

import (
	"github.com/google/uuid"
	"time"
)

// AuthCode представляет код авторизации OAuth
type AuthCode struct {
	ID            uuid.UUID `json:"id" validate:"required,uuid"`
	Code          string    `json:"code" validate:"required"`
	UserID        uuid.UUID `json:"user_id" validate:"required,uuid"`
	ClientID      uuid.UUID `json:"client_id" validate:"required"`
	RedirectURI   string    `json:"redirect_uri" validate:"required,url"`
	Scopes        []string  `json:"scopes" validate:"required,dive,required"`
	CodeChallenge string    `json:"code_challenge,omitempty" validate:"omitempty,min=43,max=128"`
	CodeMethod    string    `json:"code_method,omitempty" validate:"omitempty,oneof=plain S256"`
	ExpiresAt     time.Time `json:"expires_at" validate:"required,gt=now"`
	CreatedAt     time.Time `json:"created_at" validate:"required"`
	Used          bool      `json:"used"`
}

// IsExpired проверяет, истек ли срок действия кода авторизации
func (ac *AuthCode) IsExpired() bool {
	return time.Now().After(ac.ExpiresAt)
}

// IsValid проверяет, действителен ли код авторизации
func (ac *AuthCode) IsValid() bool {
	return !ac.IsExpired() && !ac.Used
}

// MarkAsUsed помечает код авторизации как использованный
func (ac *AuthCode) MarkAsUsed() {
	ac.Used = true
}
