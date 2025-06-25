package handlers

import (
	"net/http"
	"testing"

	"adc-sso-service/internal/models"
	"adc-sso-service/internal/testutils"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/suite"
	"gorm.io/gorm"
)

// OrganizationHandlerTestSuite defines the test suite for organization handler
type OrganizationHandlerTestSuite struct {
	suite.Suite
	ctx          *testutils.TestContext
	testUser     *models.User
	testAdmin    *models.User
	testOrg      *models.Organization
	otherUser    *models.User
	otherOrg     *models.Organization
}

// SetupTest runs before each test
func (suite *OrganizationHandlerTestSuite) SetupTest() {
	suite.ctx = testutils.SetupTestContext(suite.T())
	
	// Create test users
	suite.testUser = testutils.CreateTestRegularUser(suite.ctx.DB)
	suite.testAdmin = testutils.CreateTestAdmin(suite.ctx.DB)
	suite.otherUser = testutils.CreateTestUser(suite.ctx.DB, "other@test.com", models.UserRoleUser)
	
	// Create test organizations
	suite.testOrg = testutils.CreateTestOrganization(suite.ctx.DB, suite.testUser, "Test Org")
	suite.otherOrg = testutils.CreateTestOrganization(suite.ctx.DB, suite.otherUser, "Other Org")
	
	// Load users with organizations
	suite.testUser = testutils.LoadUserWithOrganizations(suite.ctx.DB, suite.testUser.ID)
	suite.testAdmin = testutils.LoadUserWithOrganizations(suite.ctx.DB, suite.testAdmin.ID)
}

// TearDownTest runs after each test
func (suite *OrganizationHandlerTestSuite) TearDownTest() {
	suite.ctx.Cleanup()
}

// TestOrganizationHandlerTestSuite runs the test suite
func TestOrganizationHandlerTestSuite(t *testing.T) {
	suite.Run(t, new(OrganizationHandlerTestSuite))
}

// Test creating an organization
func (suite *OrganizationHandlerTestSuite) TestCreateOrganization_Success() {
	reqBody := map[string]interface{}{
		"name":        "New Organization",
		"slug":        "new-org",
		"description": "A new test organization",
		"website":     "https://neworg.com",
		"settings": map[string]interface{}{
			"timezone": "UTC",
		},
	}

	w := testutils.AuthenticatedRequest(suite.ctx, suite.testUser, "POST", "/api/v1/organizations", reqBody)

	response := testutils.AssertJSONResponse(suite.T(), w, http.StatusCreated, "organization")
	
	org := response["organization"].(map[string]interface{})
	suite.Equal("New Organization", org["name"])
	suite.Equal("new-org", org["slug"])
	suite.Equal("A new test organization", org["description"])
	suite.Equal("https://neworg.com", org["website"])
	suite.Equal(string(models.UserRoleOwner), org["user_role"])

	// Verify organization was created in database
	var dbOrg models.Organization
	err := suite.ctx.DB.Where("name = ?", "New Organization").First(&dbOrg).Error
	suite.NoError(err)
	suite.Equal(suite.testUser.ID, dbOrg.OwnerID)

	// Verify user-organization relationship was created
	var userOrg models.UserOrganization
	err = suite.ctx.DB.Where("user_id = ? AND organization_id = ?", suite.testUser.ID, dbOrg.ID).First(&userOrg).Error
	suite.NoError(err)
	suite.Equal(models.UserRoleOwner, userOrg.Role)
}

// Test creating organization with auto-generated slug
func (suite *OrganizationHandlerTestSuite) TestCreateOrganization_AutoSlug() {
	reqBody := map[string]interface{}{
		"name":        "Auto Slug Organization",
		"description": "Organization with auto-generated slug",
	}

	w := testutils.AuthenticatedRequest(suite.ctx, suite.testUser, "POST", "/api/v1/organizations", reqBody)

	response := testutils.AssertJSONResponse(suite.T(), w, http.StatusCreated, "organization")
	
	org := response["organization"].(map[string]interface{})
	suite.Equal("Auto Slug Organization", org["name"])
	suite.Equal("auto-slug-organization", org["slug"])
}

// Test creating organization with duplicate slug
func (suite *OrganizationHandlerTestSuite) TestCreateOrganization_DuplicateSlug() {
	reqBody := map[string]interface{}{
		"name": "Duplicate Org",
		"slug": suite.testOrg.Slug, // Use existing slug
	}

	w := testutils.AuthenticatedRequest(suite.ctx, suite.testUser, "POST", "/api/v1/organizations", reqBody)

	testutils.AssertErrorResponse(suite.T(), w, http.StatusConflict, "slug already exists")
}

// Test creating organization with missing name
func (suite *OrganizationHandlerTestSuite) TestCreateOrganization_MissingName() {
	reqBody := map[string]interface{}{
		"description": "Organization without name",
	}

	w := testutils.AuthenticatedRequest(suite.ctx, suite.testUser, "POST", "/api/v1/organizations", reqBody)

	testutils.AssertErrorResponse(suite.T(), w, http.StatusBadRequest, "")
}

// Test creating organization without authentication
func (suite *OrganizationHandlerTestSuite) TestCreateOrganization_Unauthenticated() {
	reqBody := map[string]interface{}{
		"name": "Unauthenticated Org",
	}

	w := testutils.PerformRequest(suite.ctx.Router, "POST", "/api/v1/organizations", reqBody, nil)

	testutils.AssertErrorResponse(suite.T(), w, http.StatusUnauthorized, "Authentication required")
}

// Test listing organizations for regular user
func (suite *OrganizationHandlerTestSuite) TestListOrganizations_RegularUser() {
	w := testutils.AuthenticatedRequest(suite.ctx, suite.testUser, "GET", "/api/v1/organizations", nil)

	response := testutils.AssertJSONResponse(suite.T(), w, http.StatusOK, "organizations", "pagination")
	
	organizations := response["organizations"].([]interface{})
	suite.Len(organizations, 1)
	
	org := organizations[0].(map[string]interface{})
	suite.Equal(suite.testOrg.ID.String(), org["id"])
	suite.Equal(suite.testOrg.Name, org["name"])
	suite.Equal(string(models.UserRoleOwner), org["user_role"])
	
	pagination := response["pagination"].(map[string]interface{})
	suite.Equal(float64(1), pagination["total"])
	suite.Equal(false, pagination["has_more"])
}

// Test listing organizations for admin user
func (suite *OrganizationHandlerTestSuite) TestListOrganizations_AdminUser() {
	w := testutils.AuthenticatedRequest(suite.ctx, suite.testAdmin, "GET", "/api/v1/organizations", nil)

	response := testutils.AssertJSONResponse(suite.T(), w, http.StatusOK, "organizations", "pagination")
	
	organizations := response["organizations"].([]interface{})
	suite.GreaterOrEqual(len(organizations), 2) // Should see all organizations
	
	pagination := response["pagination"].(map[string]interface{})
	suite.GreaterOrEqual(pagination["total"], float64(2))
}

// Test listing organizations with pagination
func (suite *OrganizationHandlerTestSuite) TestListOrganizations_Pagination() {
	// Add user to another organization as member
	testutils.AddUserToOrganization(suite.ctx.DB, suite.testUser, suite.otherOrg, models.UserRoleMember)

	w := testutils.AuthenticatedRequest(suite.ctx, suite.testUser, "GET", "/api/v1/organizations?limit=1&offset=0", nil)

	response := testutils.AssertJSONResponse(suite.T(), w, http.StatusOK, "organizations", "pagination")
	
	organizations := response["organizations"].([]interface{})
	suite.Len(organizations, 1)
	
	pagination := response["pagination"].(map[string]interface{})
	suite.Equal(float64(2), pagination["total"])
	suite.Equal(float64(1), pagination["limit"])
	suite.Equal(float64(0), pagination["offset"])
	suite.Equal(true, pagination["has_more"])
}

// Test getting specific organization
func (suite *OrganizationHandlerTestSuite) TestGetOrganization_Success() {
	path := "/api/v1/organizations/" + suite.testOrg.ID.String()
	w := testutils.AuthenticatedRequest(suite.ctx, suite.testUser, "GET", path, nil)

	response := testutils.AssertJSONResponse(suite.T(), w, http.StatusOK, "organization")
	
	org := response["organization"].(map[string]interface{})
	suite.Equal(suite.testOrg.ID.String(), org["id"])
	suite.Equal(suite.testOrg.Name, org["name"])
	suite.Equal(suite.testOrg.Slug, org["slug"])
	suite.Equal(string(models.UserRoleOwner), org["user_role"])
	
	// Should include owner information
	owner := org["owner"].(map[string]interface{})
	suite.Equal(suite.testUser.ID.String(), owner["id"])
	suite.Equal(suite.testUser.Username, owner["username"])
}

// Test getting organization without access
func (suite *OrganizationHandlerTestSuite) TestGetOrganization_NoAccess() {
	path := "/api/v1/organizations/" + suite.otherOrg.ID.String()
	w := testutils.AuthenticatedRequest(suite.ctx, suite.testUser, "GET", path, nil)

	testutils.AssertErrorResponse(suite.T(), w, http.StatusForbidden, "Access denied to organization")
}

// Test getting organization as admin
func (suite *OrganizationHandlerTestSuite) TestGetOrganization_AdminAccess() {
	path := "/api/v1/organizations/" + suite.testOrg.ID.String()
	w := testutils.AuthenticatedRequest(suite.ctx, suite.testAdmin, "GET", path, nil)

	response := testutils.AssertJSONResponse(suite.T(), w, http.StatusOK, "organization")
	
	org := response["organization"].(map[string]interface{})
	suite.Equal(suite.testOrg.ID.String(), org["id"])
	suite.Equal(string(models.UserRoleAdmin), org["user_role"]) // Admin role
}

// Test getting non-existent organization
func (suite *OrganizationHandlerTestSuite) TestGetOrganization_NotFound() {
	path := "/api/v1/organizations/" + uuid.New().String()
	w := testutils.AuthenticatedRequest(suite.ctx, suite.testUser, "GET", path, nil)

	testutils.AssertErrorResponse(suite.T(), w, http.StatusNotFound, "Organization not found")
}

// Test updating organization
func (suite *OrganizationHandlerTestSuite) TestUpdateOrganization_Success() {
	reqBody := map[string]interface{}{
		"name":        "Updated Organization",
		"description": "Updated description",
		"website":     "https://updated.com",
		"settings": map[string]interface{}{
			"theme": "dark",
		},
	}

	path := "/api/v1/organizations/" + suite.testOrg.ID.String()
	w := testutils.AuthenticatedRequest(suite.ctx, suite.testUser, "PUT", path, reqBody)

	response := testutils.AssertJSONResponse(suite.T(), w, http.StatusOK, "organization")
	
	org := response["organization"].(map[string]interface{})
	suite.Equal("Updated Organization", org["name"])
	suite.Equal("Updated description", org["description"])
	suite.Equal("https://updated.com", org["website"])

	// Verify database was updated
	var dbOrg models.Organization
	err := suite.ctx.DB.First(&dbOrg, suite.testOrg.ID).Error
	suite.NoError(err)
	suite.Equal("Updated Organization", dbOrg.Name)
}

// Test updating organization without permission
func (suite *OrganizationHandlerTestSuite) TestUpdateOrganization_NoPermission() {
	reqBody := map[string]interface{}{
		"name": "Unauthorized Update",
	}

	path := "/api/v1/organizations/" + suite.otherOrg.ID.String()
	w := testutils.AuthenticatedRequest(suite.ctx, suite.testUser, "PUT", path, reqBody)

	testutils.AssertErrorResponse(suite.T(), w, http.StatusForbidden, "Access denied to organization")
}

// Test updating organization status as non-admin
func (suite *OrganizationHandlerTestSuite) TestUpdateOrganization_StatusChangeAsUser() {
	reqBody := map[string]interface{}{
		"status": string(models.OrganizationStatusInactive),
	}

	path := "/api/v1/organizations/" + suite.testOrg.ID.String()
	w := testutils.AuthenticatedRequest(suite.ctx, suite.testUser, "PUT", path, reqBody)

	testutils.AssertErrorResponse(suite.T(), w, http.StatusForbidden, "Only system administrators can change organization status")
}

// Test updating organization status as admin
func (suite *OrganizationHandlerTestSuite) TestUpdateOrganization_StatusChangeAsAdmin() {
	reqBody := map[string]interface{}{
		"status": string(models.OrganizationStatusInactive),
	}

	path := "/api/v1/organizations/" + suite.testOrg.ID.String()
	w := testutils.AuthenticatedRequest(suite.ctx, suite.testAdmin, "PUT", path, reqBody)

	response := testutils.AssertJSONResponse(suite.T(), w, http.StatusOK, "organization")
	
	org := response["organization"].(map[string]interface{})
	suite.Equal(string(models.OrganizationStatusInactive), org["status"])
}

// Test deleting organization
func (suite *OrganizationHandlerTestSuite) TestDeleteOrganization_Success() {
	path := "/api/v1/organizations/" + suite.testOrg.ID.String()
	w := testutils.AuthenticatedRequest(suite.ctx, suite.testUser, "DELETE", path, nil)

	testutils.AssertJSONResponse(suite.T(), w, http.StatusOK, "message")

	// Verify organization was deleted
	var org models.Organization
	err := suite.ctx.DB.First(&org, suite.testOrg.ID).Error
	suite.Error(err)
	suite.Equal(gorm.ErrRecordNotFound, err)

	// Verify related records were deleted
	var userOrg models.UserOrganization
	err = suite.ctx.DB.Where("organization_id = ?", suite.testOrg.ID).First(&userOrg).Error
	suite.Error(err)
}

// Test deleting organization without permission
func (suite *OrganizationHandlerTestSuite) TestDeleteOrganization_NoPermission() {
	path := "/api/v1/organizations/" + suite.otherOrg.ID.String()
	w := testutils.AuthenticatedRequest(suite.ctx, suite.testUser, "DELETE", path, nil)

	testutils.AssertErrorResponse(suite.T(), w, http.StatusForbidden, "Only organization owner or system administrator can delete")
}

// Test deleting organization as admin
func (suite *OrganizationHandlerTestSuite) TestDeleteOrganization_AdminAccess() {
	path := "/api/v1/organizations/" + suite.testOrg.ID.String()
	w := testutils.AuthenticatedRequest(suite.ctx, suite.testAdmin, "DELETE", path, nil)

	testutils.AssertJSONResponse(suite.T(), w, http.StatusOK, "message")
}

// Test listing organization members
func (suite *OrganizationHandlerTestSuite) TestListOrganizationMembers_Success() {
	// Add another user to the organization
	testutils.AddUserToOrganization(suite.ctx.DB, suite.otherUser, suite.testOrg, models.UserRoleMember)

	path := "/api/v1/organizations/" + suite.testOrg.ID.String() + "/members"
	w := testutils.AuthenticatedRequest(suite.ctx, suite.testUser, "GET", path, nil)

	response := testutils.AssertJSONResponse(suite.T(), w, http.StatusOK, "members")
	
	members := response["members"].([]interface{})
	suite.Len(members, 2) // Owner + Member

	// Find owner and member
	var owner, member map[string]interface{}
	for _, m := range members {
		memberData := m.(map[string]interface{})
		if memberData["role"] == string(models.UserRoleOwner) {
			owner = memberData
		} else if memberData["role"] == string(models.UserRoleMember) {
			member = memberData
		}
	}

	suite.NotNil(owner)
	suite.NotNil(member)

	ownerUser := owner["user"].(map[string]interface{})
	suite.Equal(suite.testUser.ID.String(), ownerUser["id"])

	memberUser := member["user"].(map[string]interface{})
	suite.Equal(suite.otherUser.ID.String(), memberUser["id"])
}

// Test listing organization members without access
func (suite *OrganizationHandlerTestSuite) TestListOrganizationMembers_NoAccess() {
	path := "/api/v1/organizations/" + suite.otherOrg.ID.String() + "/members"
	w := testutils.AuthenticatedRequest(suite.ctx, suite.testUser, "GET", path, nil)

	testutils.AssertErrorResponse(suite.T(), w, http.StatusForbidden, "Access denied to organization")
}

// Test invalid UUID in organization ID
func (suite *OrganizationHandlerTestSuite) TestOrganizationInvalidUUID() {
	path := "/api/v1/organizations/invalid-uuid"
	w := testutils.AuthenticatedRequest(suite.ctx, suite.testUser, "GET", path, nil)

	testutils.AssertErrorResponse(suite.T(), w, http.StatusBadRequest, "Invalid organization ID")
}

// Test organization operations with API key authentication
func (suite *OrganizationHandlerTestSuite) TestOrganizationWithAPIKey() {
	// Create API key for the organization
	apiKey := testutils.CreateTestAPIKey(suite.ctx.DB, suite.testUser, suite.testOrg, "Test API Key")

	path := "/api/v1/organizations/" + suite.testOrg.ID.String()
	w := testutils.APIKeyRequest(suite.ctx, apiKey, "GET", path, nil)

	response := testutils.AssertJSONResponse(suite.T(), w, http.StatusOK, "organization")
	
	org := response["organization"].(map[string]interface{})
	suite.Equal(suite.testOrg.ID.String(), org["id"])
}

// Test concurrent organization operations
func (suite *OrganizationHandlerTestSuite) TestConcurrentOrganizationOperations() {
	numRequests := 10
	results := make(chan int, numRequests)

	path := "/api/v1/organizations/" + suite.testOrg.ID.String()

	// Make concurrent GET requests
	for i := 0; i < numRequests; i++ {
		go func() {
			w := testutils.AuthenticatedRequest(suite.ctx, suite.testUser, "GET", path, nil)
			results <- w.Code
		}()
	}

	// Collect results
	successCount := 0
	for i := 0; i < numRequests; i++ {
		statusCode := <-results
		if statusCode == http.StatusOK {
			successCount++
		}
	}

	// All requests should succeed
	suite.Equal(numRequests, successCount)
}