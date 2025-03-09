package entity

import (
	"time"
)

// AuditEventType определяет тип события аудита
type AuditEventType string

const (
	AuditEventLogin          AuditEventType = "login"
	AuditEventLogout         AuditEventType = "logout"
	AuditEventTokenIssued    AuditEventType = "token_issued"
	AuditEventTokenRevoked   AuditEventType = "token_revoked"
	AuditEventPasswordChange AuditEventType = "password_change"
	AuditEventRoleChange     AuditEventType = "role_change"
)

// AuditLog представляет запись аудита безопасности
type AuditLog struct {
	ID          string                 `json:"id" validate:"required,uuid"`
	UserID      string                 `json:"user_id" validate:"required,uuid"`
	ClientID    *string                `json:"client_id,omitempty" validate:"omitempty,uuid"`
	EventType   AuditEventType         `json:"event_type" validate:"required,oneof=login logout token_issued token_revoked password_change role_change"`
	Description string                 `json:"description" validate:"required"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
	IP          string                 `json:"ip" validate:"required,ip"`
	UserAgent   string                 `json:"user_agent" validate:"required"`
	CreatedAt   time.Time             `json:"created_at" validate:"required"`
	Success     bool                   `json:"success"`
}

// NewAuditLog создает новую запись аудита
func NewAuditLog(
	userID string,
	eventType AuditEventType,
	description string,
	ip string,
	userAgent string,
	success bool,
) *AuditLog {
	return &AuditLog{
		UserID:      userID,
		EventType:   eventType,
		Description: description,
		IP:          ip,
		UserAgent:   userAgent,
		CreatedAt:   time.Now(),
		Success:     success,
		Metadata:    make(map[string]interface{}),
	}
}

// AddMetadata добавляет метаданные к записи аудита
func (a *AuditLog) AddMetadata(key string, value interface{}) {
	if a.Metadata == nil {
		a.Metadata = make(map[string]interface{})
	}
	a.Metadata[key] = value
} 