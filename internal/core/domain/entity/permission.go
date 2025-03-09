package entity

import (
	"time"
	"github.com/google/uuid"
)

// ResourceType определяет тип ресурса
type ResourceType string

const (
	ResourceUser       ResourceType = "user"
	ResourceRole      ResourceType = "role"
	ResourcePermission ResourceType = "permission"
	ResourceClient    ResourceType = "client"
)

// Action определяет действие над ресурсом
type Action string

const (
	ActionCreate Action = "create"
	ActionRead   Action = "read"
	ActionUpdate Action = "update"
	ActionDelete Action = "delete"
	ActionList   Action = "list"
)

// Permission представляет разрешение в системе
type Permission struct {
	ID          uuid.UUID    `json:"id" validate:"required"`
	Name        string       `json:"name" validate:"required"`
	Resource    ResourceType `json:"resource" validate:"required,oneof=user role permission client"`
	Action      Action      `json:"action" validate:"required,oneof=create read update delete list"`
	Description string       `json:"description,omitempty"`
	CreatedAt   time.Time    `json:"created_at" validate:"required"`
	UpdatedAt   time.Time    `json:"updated_at" validate:"required"`
}

// NewPermission создает новое разрешение
func NewPermission(name string, resource ResourceType, action Action, description string) *Permission {
	now := time.Now()
	return &Permission{
		ID:          uuid.New(),
		Name:        name,
		Resource:    resource,
		Action:      action,
		Description: description,
		CreatedAt:   now,
		UpdatedAt:   now,
	}
}

// String возвращает строковое представление разрешения
func (p *Permission) String() string {
	return string(p.Resource) + ":" + string(p.Action)
}
