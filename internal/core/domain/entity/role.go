package entity

import (
	"github.com/google/uuid"
	"time"
)

// Role представляет роль в системе.
type Role struct {
	ID          uuid.UUID   `json:"id" validate:"required"`
	Name        string      `json:"name" validate:"required"`
	Description string      `json:"description,omitempty"`
	Permissions []Permission `json:"permissions" validate:"required,dive,required"`
	CreatedAt   time.Time   `json:"created_at" validate:"required"`
	UpdatedAt   time.Time   `json:"updated_at" validate:"required"`
}

// NewRole создает новую роль
func NewRole(name, description string) *Role {
	now := time.Now()
	return &Role{
		ID:          uuid.New(),
		Name:        name,
		Description: description,
		Permissions: make([]Permission, 0),
		CreatedAt:   now,
		UpdatedAt:   now,
	}
}

// AddPermission добавляет разрешение к роли
func (r *Role) AddPermission(permission Permission) {
	for _, existingPerm := range r.Permissions {
		if existingPerm.ID == permission.ID {
			return
		}
	}
	r.Permissions = append(r.Permissions, permission)
	r.UpdatedAt = time.Now()
}

// RemovePermission удаляет разрешение из роли
func (r *Role) RemovePermission(permissionID uuid.UUID) {
	for i, perm := range r.Permissions {
		if perm.ID == permissionID {
			r.Permissions = append(r.Permissions[:i], r.Permissions[i+1:]...)
			r.UpdatedAt = time.Now()
			return
		}
	}
}

// HasPermission проверяет наличие разрешения у роли
func (r *Role) HasPermission(permissionID uuid.UUID) bool {
	for _, perm := range r.Permissions {
		if perm.ID == permissionID {
			return true
		}
	}
	return false
}
