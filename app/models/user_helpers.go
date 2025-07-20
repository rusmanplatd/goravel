package models

import (
	"time"

	"github.com/goravel/framework/facades"
)

// HasRole checks if user has a specific role in a tenant
func (u *User) HasRole(roleName string, tenantID string) bool {
	var count int64
	err := facades.Orm().Query().
		Table("user_roles ur").
		Select("count(*)").
		Where("ur.user_id = ? AND ur.tenant_id = ?", u.ID, tenantID).
		Where("EXISTS (SELECT 1 FROM roles r WHERE r.id = ur.role_id AND r.name = ?)", roleName).
		Scan(&count)

	if err != nil {
		return false
	}

	return count > 0
}

// HasPermission checks if user has a specific permission in a tenant
func (u *User) HasPermission(permissionName string, tenantID string) bool {
	var count int64
	err := facades.Orm().Query().
		Table("user_roles ur").
		Select("count(*)").
		Where("ur.user_id = ? AND ur.tenant_id = ?", u.ID, tenantID).
		Where("EXISTS (SELECT 1 FROM role_permissions rp JOIN permissions p ON rp.permission_id = p.id WHERE rp.role_id = ur.role_id AND p.name = ?)", permissionName).
		Scan(&count)

	if err != nil {
		return false
	}

	return count > 0
}

// GetRolesForTenant returns all roles for user in a specific tenant
func (u *User) GetRolesForTenant(tenantID string) ([]Role, error) {
	var roles []Role
	err := facades.Orm().Query().
		Where("id IN (SELECT role_id FROM user_roles WHERE user_id = ? AND tenant_id = ?)", u.ID, tenantID).
		Find(&roles)

	return roles, err
}

// GetPermissionsForTenant returns all permissions for user in a specific tenant
func (u *User) GetPermissionsForTenant(tenantID string) ([]Permission, error) {
	var permissions []Permission
	err := facades.Orm().Query().
		Where("id IN (SELECT permission_id FROM role_permissions rp JOIN user_roles ur ON rp.role_id = ur.role_id WHERE ur.user_id = ? AND ur.tenant_id = ?)", u.ID, tenantID).
		Find(&permissions)

	return permissions, err
}

// BelongsToTenant checks if user belongs to a specific tenant
func (u *User) BelongsToTenant(tenantID string) bool {
	var count int64
	facades.Orm().Query().
		Raw("SELECT COUNT(*) FROM user_tenants WHERE user_id = ? AND tenant_id = ? AND is_active = ?", u.ID, tenantID, true).
		Scan(&count)

	return count > 0
}

// AssignRole assigns a role to user in a specific tenant
func (u *User) AssignRole(roleID string, tenantID string) error {
	userRole := UserRole{
		UserID:   u.ID,
		RoleID:   roleID,
		TenantID: &tenantID,
	}

	return facades.Orm().Query().Create(&userRole)
}

// RemoveRole removes a role from user in a specific tenant
func (u *User) RemoveRole(roleID string, tenantID string) error {
	_, err := facades.Orm().Query().
		Where("user_id = ? AND role_id = ? AND tenant_id = ?", u.ID, roleID, tenantID).
		Delete(&UserRole{})

	return err
}

// AddToTenant adds user to a tenant
func (u *User) AddToTenant(tenantID string) error {
	userTenant := UserTenant{
		UserID:   u.ID,
		TenantID: tenantID,
		IsActive: true,
		JoinedAt: time.Now(),
	}

	return facades.Orm().Query().Create(&userTenant)
}

// RemoveFromTenant removes user from a tenant
func (u *User) RemoveFromTenant(tenantID string) error {
	_, err := facades.Orm().Query().
		Where("user_id = ? AND tenant_id = ?", u.ID, tenantID).
		Delete(&UserTenant{})

	return err
}
