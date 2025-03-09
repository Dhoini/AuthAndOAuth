package entity

import (
	"time"
	"github.com/google/uuid"
)

// TokenType определяет тип токена
type TokenType string

const (
	AccessToken  TokenType = "access_token"
	RefreshToken TokenType = "refresh_token"
)

// Token представляет токен аутентификации
type Token struct {
	ID        uuid.UUID `json:"id" validate:"required"`
	UserID    uuid.UUID `json:"user_id" validate:"required"`
	ClientID  uuid.UUID `json:"client_id" validate:"required"`
	Type      TokenType `json:"type" validate:"required,oneof=access_token refresh_token"`
	Value     string    `json:"value" validate:"required"`
	Scopes    []string  `json:"scopes" validate:"required,dive,required"`
	ExpiresAt time.Time `json:"expires_at" validate:"required,gt=now"`
	CreatedAt time.Time `json:"created_at" validate:"required"`
	RevokedAt *time.Time `json:"revoked_at,omitempty"`
	IsRevoked bool      `json:"is_revoked"`
}

// NewToken создает новый токен
func NewToken(userID, clientID uuid.UUID, tokenType TokenType, scopes []string, expiresIn time.Duration) *Token {
	now := time.Now()
	return &Token{
		ID:        uuid.New(),
		UserID:    userID,
		ClientID:  clientID,
		Type:      tokenType,
		Value:     uuid.New().String(),
		Scopes:    scopes,
		ExpiresAt: now.Add(expiresIn),
		CreatedAt: now,
		IsRevoked: false,
	}
}

// IsExpired проверяет, истек ли срок действия токена
func (t *Token) IsExpired() bool {
	return time.Now().After(t.ExpiresAt)
}

// IsValid проверяет, действителен ли токен
func (t *Token) IsValid() bool {
	return !t.IsExpired() && !t.IsRevoked
}

// Revoke отзывает токен
func (t *Token) Revoke() {
	now := time.Now()
	t.RevokedAt = &now
	t.IsRevoked = true
}
