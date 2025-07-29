package middleware

import (
	"strings"

	"github.com/goravel/framework/contracts/http"
	"github.com/goravel/framework/facades"

	"goravel/app/models"
)

type OrganizationMiddleware struct{}

func NewOrganizationMiddleware() *OrganizationMiddleware {
	return &OrganizationMiddleware{}
}

func (m *OrganizationMiddleware) Handle(ctx http.Context) http.Response {
	// Try to get organization from various sources
	var organization *models.Organization
	var err error

	// 1. Try from subdomain
	host := ctx.Request().Header("Host", "")
	if host != "" {
		subdomain := strings.Split(host, ".")[0]
		if subdomain != "www" && subdomain != "" {
			organization, err = m.getOrganizationBySlug(subdomain)
			if err == nil && organization != nil {
				ctx.WithValue("organization", organization)
				ctx.WithValue("organization_id", organization.ID)
				ctx.Request().Next()
				return nil
			}
		}
	}

	// 2. Try from custom domain
	if host != "" {
		organization, err = m.getOrganizationByDomain(host)
		if err == nil && organization != nil {
			ctx.WithValue("organization", organization)
			ctx.WithValue("organization_id", organization.ID)
			ctx.Request().Next()
			return nil
		}
	}

	// 3. Try from header
	organizationHeader := ctx.Request().Header("X-Organization-ID", "")
	if organizationHeader != "" {
		organization, err = m.getOrganizationByID(organizationHeader)
		if err == nil && organization != nil {
			ctx.WithValue("organization", organization)
			ctx.WithValue("organization_id", organization.ID)
			ctx.Request().Next()
			return nil
		}
	}

	// 4. Try from query parameter
	organizationParam := ctx.Request().Query("organization_id", "")
	if organizationParam != "" {
		organization, err = m.getOrganizationByID(organizationParam)
		if err == nil && organization != nil {
			ctx.WithValue("organization", organization)
			ctx.WithValue("organization_id", organization.ID)
			ctx.Request().Next()
			return nil
		}
	}

	// If no organization found, return error
	return ctx.Response().Status(400).Json(http.Json{
		"error": "Organization not found or not specified",
	})
}

func (m *OrganizationMiddleware) getOrganizationBySlug(slug string) (*models.Organization, error) {
	var organization models.Organization
	err := facades.Orm().Query().Where("slug = ? AND is_active = ?", slug, true).First(&organization)
	if err != nil {
		return nil, err
	}
	return &organization, nil
}

func (m *OrganizationMiddleware) getOrganizationByDomain(domain string) (*models.Organization, error) {
	var organization models.Organization
	err := facades.Orm().Query().Where("domain = ? AND is_active = ?", domain, true).First(&organization)
	if err != nil {
		return nil, err
	}
	return &organization, nil
}

func (m *OrganizationMiddleware) getOrganizationByID(id string) (*models.Organization, error) {
	var organization models.Organization
	err := facades.Orm().Query().Where("id = ? AND is_active = ?", id, true).First(&organization)
	if err != nil {
		return nil, err
	}
	return &organization, nil
}
