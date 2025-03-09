package entity

import (
	"github.com/google/uuid"
	"time"
)

// User представляет пользователя системы
type User struct {
	ID          uuid.UUID  `json:"id" validate:"required"`
	Email       string     `json:"email" validate:"required,email"`
	Password    string     `json:"-" validate:"required,min=8"`
	FirstName   string     `json:"first_name" validate:"required"`
	LastName    string     `json:"last_name" validate:"required"`
	Active      bool       `json:"active"`
	Roles       []Role     `json:"roles" validate:"required,dive,required"`
	Permissions []string   `json:"permissions,omitempty"`
	CreatedAt   time.Time  `json:"created_at" validate:"required"`
	UpdatedAt   time.Time  `json:"updated_at" validate:"required"`
	LastLoginAt *time.Time `json:"last_login_at,omitempty"`
}

// NewUser создает нового пользователя
func NewUser(email, firstName, lastName, password string) *User {
	now := time.Now()
	return &User{
		ID:        uuid.New(),
		Email:     email,
		Password:  password,
		FirstName: firstName,
		LastName:  lastName,
		Active:    true,
		Roles:     make([]Role, 0),
		CreatedAt: now,
		UpdatedAt: now,
	}
}

// AddRole добавляет роль пользователю
func (u *User) AddRole(role Role) {
	for _, existingRole := range u.Roles {
		if existingRole.ID == role.ID {
			return
		}
	}
	u.Roles = append(u.Roles, role)
	u.UpdatedAt = time.Now()
}

// RemoveRole удаляет роль у пользователя
func (u *User) RemoveRole(roleID uuid.UUID) {
	for i, role := range u.Roles {
		if role.ID == roleID {
			u.Roles = append(u.Roles[:i], u.Roles[i+1:]...)
			u.UpdatedAt = time.Now()
			return
		}
	}
}

// HasRole проверяет наличие роли у пользователя
func (u *User) HasRole(roleID uuid.UUID) bool {
	for _, role := range u.Roles {
		if role.ID == roleID {
			return true
		}
	}
	return false
}

// UpdateLastLogin обновляет время последнего входа
func (u *User) UpdateLastLogin() {
	now := time.Now()
	u.LastLoginAt = &now
	u.UpdatedAt = now
}

// Deactivate деактивирует пользователя
func (u *User) Deactivate() {
	u.Active = false
	u.UpdatedAt = time.Now()
}

// Activate активирует пользователя
func (u *User) Activate() {
	u.Active = true
	u.UpdatedAt = time.Now()
}

// FullName возвращает полное имя пользователя
func (u *User) FullName() string {
	return u.FirstName + " " + u.LastName
}
