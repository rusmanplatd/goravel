package feature

import (
	"testing"

	"github.com/goravel/framework/facades"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"

	"goravel/app/models"
	"goravel/tests"
)

type OrganizationTenantTestSuite struct {
	suite.Suite
	tests.TestCase
}

func TestOrganizationTenantTestSuite(t *testing.T) {
	suite.Run(t, new(OrganizationTenantTestSuite))
}

// SetupTest will run before each test in the suite.
func (s *OrganizationTenantTestSuite) SetupTest() {
}

// TearDownTest will run after each test in the suite.
func (s *OrganizationTenantTestSuite) TearDownTest() {
}

func (s *OrganizationTenantTestSuite) TestOrganizationTenantRelationship() {
	// Create a tenant
	tenant := &models.Tenant{
		Name:        "Test Tenant",
		Slug:        "test-tenant",
		Domain:      "test.com",
		Description: "Test tenant for organization relationship",
		IsActive:    true,
		Settings:    "{}", // Empty JSON object
	}
	err := facades.Orm().Query().Create(tenant)
	assert.NoError(s.T(), err)

	// Create an organization that belongs to the tenant
	organization := &models.Organization{
		Name:        "Test Organization",
		Slug:        "test-org",
		Domain:      "org.test.com",
		Description: "Test organization",
		Type:        "company",
		Industry:    "Technology",
		Size:        "medium",
		IsActive:    true,
		TenantID:    &tenant.ID,
		Settings:    "{}", // Empty JSON object
		Path:        "/",
	}
	err = facades.Orm().Query().Create(organization)
	assert.NoError(s.T(), err)

	// Verify the relationship
	var retrievedOrg models.Organization
	err = facades.Orm().Query().Where("id = ?", organization.ID).First(&retrievedOrg)
	assert.NoError(s.T(), err)
	assert.Equal(s.T(), tenant.ID, *retrievedOrg.TenantID)

	// Test loading organizations for a tenant
	var tenantOrgs []models.Organization
	err = facades.Orm().Query().Where("tenant_id = ?", tenant.ID).Find(&tenantOrgs)
	assert.NoError(s.T(), err)
	assert.Len(s.T(), tenantOrgs, 1)
	assert.Equal(s.T(), organization.ID, tenantOrgs[0].ID)
}

func (s *OrganizationTenantTestSuite) TestOrganizationWithoutTenant() {
	// Create an organization without a tenant
	organization := &models.Organization{
		Name:        "Independent Organization",
		Slug:        "independent-org",
		Domain:      "independent.com",
		Description: "Organization without tenant",
		Type:        "company",
		Industry:    "Technology",
		Size:        "small",
		IsActive:    true,
		TenantID:    nil,  // No tenant
		Settings:    "{}", // Empty JSON object
		Path:        "/",
	}
	err := facades.Orm().Query().Create(organization)
	assert.NoError(s.T(), err)

	// Verify the organization has no tenant
	var retrievedOrg models.Organization
	err = facades.Orm().Query().Where("id = ?", organization.ID).First(&retrievedOrg)
	assert.NoError(s.T(), err)
	assert.Nil(s.T(), retrievedOrg.TenantID)

	// Test filtering organizations without tenant
	var orgsWithoutTenant []models.Organization
	err = facades.Orm().Query().Where("tenant_id IS NULL").Find(&orgsWithoutTenant)
	assert.NoError(s.T(), err)
	assert.GreaterOrEqual(s.T(), len(orgsWithoutTenant), 1)

	// Verify our organization is in the list
	found := false
	for _, org := range orgsWithoutTenant {
		if org.ID == organization.ID {
			found = true
			break
		}
	}
	assert.True(s.T(), found)
}
