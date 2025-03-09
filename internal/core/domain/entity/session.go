package entity

import (
	"time"
)

// SessionStatus определяет статус сессии
type SessionStatus string

const (
	SessionStatusActive   SessionStatus = "active"
	SessionStatusExpired SessionStatus = "expired"
	SessionStatusRevoked SessionStatus = "revoked"
)

// Session представляет сессию пользователя
type Session struct {
	ID           string        `json:"id" validate:"required,uuid"`
	UserID       string        `json:"user_id" validate:"required,uuid"`
	RefreshToken string        `json:"refresh_token" validate:"required"`
	UserAgent    string        `json:"user_agent" validate:"required"`
	ClientIP     string        `json:"client_ip" validate:"required,ip"`
	ExpiresAt    time.Time     `json:"expires_at" validate:"required,gt=now"`
	CreatedAt    time.Time     `json:"created_at" validate:"required"`
	LastUsedAt   time.Time     `json:"last_used_at" validate:"required"`
	Status       SessionStatus `json:"status" validate:"required,oneof=active expired revoked"`
}

// IsExpired проверяет, истекла ли сессия
func (s *Session) IsExpired() bool {
	return time.Now().After(s.ExpiresAt)
}

// IsActive проверяет, активна ли сессия
func (s *Session) IsActive() bool {
	return s.Status == SessionStatusActive && !s.IsExpired()
}

// UpdateLastUsed обновляет время последнего использования сессии
func (s *Session) UpdateLastUsed() {
	s.LastUsedAt = time.Now()
}

// Revoke отзывает сессию
func (s *Session) Revoke() {
	s.Status = SessionStatusRevoked
}

// Expire помечает сессию как истекшую
func (s *Session) Expire() {
	s.Status = SessionStatusExpired
} 