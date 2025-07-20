package middleware

import (
	"strings"

	"github.com/goravel/framework/contracts/http"
	"github.com/goravel/framework/facades"

	"goravel/app/models"
)

type TenantMiddleware struct{}

func NewTenantMiddleware() *TenantMiddleware {
	return &TenantMiddleware{}
}

func (m *TenantMiddleware) Handle(ctx http.Context) http.Response {
	// Try to get tenant from various sources
	var tenant *models.Tenant
	var err error

	// 1. Try from subdomain
	host := ctx.Request().Header("Host", "")
	if host != "" {
		subdomain := strings.Split(host, ".")[0]
		if subdomain != "www" && subdomain != "" {
			tenant, err = m.getTenantBySlug(subdomain)
			if err == nil && tenant != nil {
				ctx.WithValue("tenant", tenant)
				ctx.WithValue("tenant_id", tenant.ID)
				ctx.Request().Next()
				return nil
			}
		}
	}

	// 2. Try from custom domain
	if host != "" {
		tenant, err = m.getTenantByDomain(host)
		if err == nil && tenant != nil {
			ctx.WithValue("tenant", tenant)
			ctx.WithValue("tenant_id", tenant.ID)
			ctx.Request().Next()
			return nil
		}
	}

	// 3. Try from header
	tenantHeader := ctx.Request().Header("X-Tenant-ID", "")
	if tenantHeader != "" {
		tenant, err = m.getTenantByID(tenantHeader)
		if err == nil && tenant != nil {
			ctx.WithValue("tenant", tenant)
			ctx.WithValue("tenant_id", tenant.ID)
			ctx.Request().Next()
			return nil
		}
	}

	// 4. Try from query parameter
	tenantParam := ctx.Request().Query("tenant_id", "")
	if tenantParam != "" {
		tenant, err = m.getTenantByID(tenantParam)
		if err == nil && tenant != nil {
			ctx.WithValue("tenant", tenant)
			ctx.WithValue("tenant_id", tenant.ID)
			ctx.Request().Next()
			return nil
		}
	}

	// If no tenant found, return error
	return ctx.Response().Status(400).Json(http.Json{
		"error": "Tenant not found or not specified",
	})
}

func (m *TenantMiddleware) getTenantBySlug(slug string) (*models.Tenant, error) {
	var tenant models.Tenant
	err := facades.Orm().Query().Where("slug = ? AND is_active = ?", slug, true).First(&tenant)
	if err != nil {
		return nil, err
	}
	return &tenant, nil
}

func (m *TenantMiddleware) getTenantByDomain(domain string) (*models.Tenant, error) {
	var tenant models.Tenant
	err := facades.Orm().Query().Where("domain = ? AND is_active = ?", domain, true).First(&tenant)
	if err != nil {
		return nil, err
	}
	return &tenant, nil
}

func (m *TenantMiddleware) getTenantByID(id string) (*models.Tenant, error) {
	var tenant models.Tenant
	err := facades.Orm().Query().Where("id = ? AND is_active = ?", id, true).First(&tenant)
	if err != nil {
		return nil, err
	}
	return &tenant, nil
}
