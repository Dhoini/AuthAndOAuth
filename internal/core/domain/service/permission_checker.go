package service

import (
	"AuthAndOauth/internal/core/domain/entity"
	"fmt"
	"go.uber.org/zap"
)

// PermissionChecker сервис для проверки прав доступа
type PermissionChecker struct{}

// NewPermissionChecker создает новый экземпляр PermissionChecker
func NewPermissionChecker() *PermissionChecker {
	return &PermissionChecker{}
}

// HasPermission проверяет наличие разрешения у пользователя
func (pc *PermissionChecker) HasPermission(user *entity.User, resource entity.ResourceType, action entity.Action) bool {
	log.Debug("checking user permission",
		zap.String("user_id", user.ID.String()),
		zap.String("resource", string(resource)),
		zap.String("action", string(action)),
	)

	if user == nil {
		log.Warn("user is nil during permission check")
		return false
	}

	// Проверяем разрешения в ролях пользователя
	for _, role := range user.Roles {
		for _, permission := range role.Permissions {
			if permission.Resource == resource && permission.Action == action {
				log.Debug("permission found",
					zap.String("user_id", user.ID.String()),
					zap.String("role_id", role.ID.String()),
					zap.String("permission_id", permission.ID.String()),
				)
				return true
			}
		}
	}

	log.Debug("permission not found",
		zap.String("user_id", user.ID.String()),
		zap.String("resource", string(resource)),
		zap.String("action", string(action)),
	)
	return false
}

// HasAnyPermission проверяет наличие любого из разрешений у пользователя
func (pc *PermissionChecker) HasAnyPermission(user *entity.User, permissions []entity.Permission) bool {
	log.Debug("checking any permission",
		zap.String("user_id", user.ID.String()),
		zap.Int("permissions_count", len(permissions)),
	)

	if user == nil {
		log.Warn("user is nil during permission check")
		return false
	}

	for _, requiredPerm := range permissions {
		if pc.HasPermission(user, requiredPerm.Resource, requiredPerm.Action) {
			log.Debug("found matching permission",
				zap.String("user_id", user.ID.String()),
				zap.String("resource", string(requiredPerm.Resource)),
				zap.String("action", string(requiredPerm.Action)),
			)
			return true
		}
	}

	log.Debug("no matching permissions found",
		zap.String("user_id", user.ID.String()),
	)
	return false
}

// ValidateUserAccess проверяет доступ пользователя к ресурсу
func (pc *PermissionChecker) ValidateUserAccess(user *entity.User, resource entity.ResourceType, action entity.Action) error {
	log.Debug("validating user access",
		zap.String("user_id", user.ID.String()),
		zap.String("resource", string(resource)),
		zap.String("action", string(action)),
	)

	if !pc.HasPermission(user, resource, action) {
		log.Warn("access denied",
			zap.String("user_id", user.ID.String()),
			zap.String("resource", string(resource)),
			zap.String("action", string(action)),
		)
		return fmt.Errorf("user does not have permission: %s:%s", resource, action)
	}

	log.Debug("access granted",
		zap.String("user_id", user.ID.String()),
		zap.String("resource", string(resource)),
		zap.String("action", string(action)),
	)
	return nil
}

// GetUserPermissions возвращает все разрешения пользователя
func (pc *PermissionChecker) GetUserPermissions(user *entity.User) []entity.Permission {
	log.Debug("getting user permissions",
		zap.String("user_id", user.ID.String()),
	)

	if user == nil {
		log.Warn("user is nil while getting permissions")
		return nil
	}

	// Используем map для исключения дубликатов
	permMap := make(map[string]entity.Permission)

	for _, role := range user.Roles {
		log.Debug("processing role permissions",
			zap.String("user_id", user.ID.String()),
			zap.String("role_id", role.ID.String()),
			zap.String("role_name", role.Name),
			zap.Int("permissions_count", len(role.Permissions)),
		)

		for _, perm := range role.Permissions {
			key := perm.String()
			permMap[key] = perm
		}
	}

	// Преобразуем map в slice
	permissions := make([]entity.Permission, 0, len(permMap))
	for _, perm := range permMap {
		permissions = append(permissions, perm)
	}

	log.Debug("user permissions collected",
		zap.String("user_id", user.ID.String()),
		zap.Int("unique_permissions_count", len(permissions)),
	)

	return permissions
}

// HasRole проверяет наличие роли у пользователя
func (pc *PermissionChecker) HasRole(user *entity.User, roleName string) bool {
	log.Debug("checking user role",
		zap.String("user_id", user.ID.String()),
		zap.String("role_name", roleName),
	)

	if user == nil {
		log.Warn("user is nil during role check")
		return false
	}

	for _, role := range user.Roles {
		if role.Name == roleName {
			log.Debug("role found",
				zap.String("user_id", user.ID.String()),
				zap.String("role_id", role.ID.String()),
				zap.String("role_name", roleName),
			)
			return true
		}
	}

	log.Debug("role not found",
		zap.String("user_id", user.ID.String()),
		zap.String("role_name", roleName),
	)
	return false
}
