package middleware

import (
	"github.com/goravel/framework/contracts/http"
	"github.com/goravel/framework/facades"

	"goravel/app/models"
)

type PermissionMiddleware struct {
	permission string
}

func NewPermissionMiddleware(permission string) *PermissionMiddleware {
	return &PermissionMiddleware{
		permission: permission,
	}
}

func (m *PermissionMiddleware) Handle(ctx http.Context) http.Response {
	// For now, we'll implement a basic version without full auth integration
	// This can be enhanced once proper auth is set up

	// Get tenant from context
	tenantID := ctx.Value("tenant_id")
	if tenantID == nil {
		return ctx.Response().Status(400).Json(http.Json{
			"error": "Tenant context required",
		})
	}

	// For now, we'll just proceed - this should be enhanced with actual user auth
	ctx.Request().Next()
	return nil
}

func (m *PermissionMiddleware) userHasPermission(user *models.User, permission string, tenantID uint) bool {
	// Check if user has permission through roles in this tenant
	var count int64
	err := facades.Orm().Query().
		Table("user_roles ur").
		Select("count(*)").
		Where("ur.user_id = ? AND ur.tenant_id = ?", user.ID, tenantID).
		Where("EXISTS (SELECT 1 FROM role_permissions rp JOIN permissions p ON rp.permission_id = p.id WHERE rp.role_id = ur.role_id AND p.name = ?)", permission).
		Scan(&count)

	if err != nil {
		return false
	}

	return count > 0
}

// Permission helper functions
func Permission(permission string) func(ctx http.Context) http.Response {
	middleware := NewPermissionMiddleware(permission)
	return middleware.Handle
}

func HasRole(role string) func(ctx http.Context) http.Response {
	return func(ctx http.Context) http.Response {
		// Get tenant from context
		tenantID := ctx.Value("tenant_id")
		if tenantID == nil {
			return ctx.Response().Status(400).Json(http.Json{
				"error": "Tenant context required",
			})
		}

		// For now, we'll just proceed - this should be enhanced with actual user auth
		ctx.Request().Next()
		return nil
	}
}
