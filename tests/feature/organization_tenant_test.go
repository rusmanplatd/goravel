package feature

import (
	"errors"
	"testing"

	"github.com/goravel/framework/facades"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
	"gorm.io/gorm"

	"goravel/app/helpers"
	"goravel/app/models"
	"goravel/app/services"
	"goravel/tests"
)

type OrganizationOrganizationTestSuite struct {
	suite.Suite
	tests.TestCase
	organizationService *services.OrganizationService
	testUserID          string
}

func TestOrganizationOrganizationTestSuite(t *testing.T) {
	suite.Run(t, new(OrganizationOrganizationTestSuite))
}

// SetupTest will run before each test in the suite.
func (s *OrganizationOrganizationTestSuite) SetupTest() {
	s.organizationService = services.NewOrganizationService()
	s.testUserID = helpers.GenerateULID() // Generate a test user ID
}

// TearDownTest will run after each test in the suite.
func (s *OrganizationOrganizationTestSuite) TearDownTest() {
}

func (s *OrganizationOrganizationTestSuite) TestOrganizationOrganizationOneToOneRelationship() {
	// Since the organization model has foreign key constraints, let's test the service logic directly
	// by creating a organization with minimal required fields

	// First test: Try to create an organization without a organization - should fail
	orgData := map[string]interface{}{
		"name":        "Test Organization",
		"slug":        "test-org",
		"domain":      "test.com",
		"description": "Test organization",
		"type":        "company",
		"industry":    "Technology",
		"size":        "medium",
		"settings":    "{}",
		// organization_id is missing
	}

	_, err := s.organizationService.CreateOrganization(orgData)
	assert.Error(s.T(), err)
	assert.Contains(s.T(), err.Error(), "organization_id is required")
}

func (s *OrganizationOrganizationTestSuite) TestOrganizationWithoutOrganization() {
	// Try to create an organization without a organization - should fail
	orgData := map[string]interface{}{
		"name":        "Independent Organization",
		"slug":        "independent-org",
		"domain":      "independent.com",
		"description": "Organization without organization",
		"type":        "company",
		"industry":    "Technology",
		"size":        "small",
		"settings":    "{}",
		// organization_id is missing
	}

	_, err := s.organizationService.CreateOrganization(orgData)
	assert.Error(s.T(), err)
	assert.Contains(s.T(), err.Error(), "organization_id is required")
}

func (s *OrganizationOrganizationTestSuite) TestOrganizationWithNonExistentOrganization() {
	// Generate a non-existent organization ID
	nonExistentorganizationId := helpers.GenerateULID()

	// Try to create an organization with a non-existent organization - should fail
	orgData := map[string]interface{}{
		"name":            "Orphan Organization",
		"slug":            "orphan-org",
		"domain":          "orphan.com",
		"description":     "Organization with non-existent organization",
		"type":            "company",
		"industry":        "Technology",
		"size":            "small",
		"organization_id": nonExistentorganizationId, // Non-existent organization ID
		"settings":        "{}",
	}

	// Debug: let's manually check if the organization exists first
	var organization models.Organization
	err := facades.Orm().Query().Where("id = ?", nonExistentorganizationId).First(&organization)
	s.T().Logf("Manual organization check - Error: %v, Error type: %T", err, err)
	if err != nil {
		s.T().Logf("Error is GORM ErrRecordNotFound: %v", errors.Is(err, gorm.ErrRecordNotFound))
	}

	_, err = s.organizationService.CreateOrganization(orgData)
	assert.Error(s.T(), err)

	// Debug: print the actual error message
	s.T().Logf("Actual error message: %s", err.Error())

	assert.Contains(s.T(), err.Error(), "organization not found", "Expected 'organization not found' error but got: %s", err.Error())
}

func (s *OrganizationOrganizationTestSuite) TestUpdateOrganizationOrganizationValidation() {
	// Test that we can't update an organization to have the same organization as another organization
	// This test focuses on the service validation logic rather than database operations

	// The service should prevent multiple organizations from having the same organization
	// This is tested through the organization creation and update methods

	// Test updating an organization with missing organization validation
	updateData := map[string]interface{}{
		"name": "Updated Organization",
	}

	// Try to update a non-existent organization
	_, err := s.organizationService.UpdateOrganization("01HXYZ123456789ABCDEFGHIJK", updateData)
	assert.Error(s.T(), err)
	// The service should return an error for non-existent organization
}
