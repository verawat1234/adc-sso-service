package handlers

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"adc-sso-service/internal/models"
	"adc-sso-service/internal/testutils"

	"github.com/google/uuid"
	"github.com/stretchr/testify/suite"
)

// APIKeyHandlerTestSuite defines the test suite for API key handler
type APIKeyHandlerTestSuite struct {
	suite.Suite
	ctx          *testutils.TestContext
	testUser     *models.User
	testAdmin    *models.User
	testOrg      *models.Organization
	otherUser    *models.User
	otherOrg     *models.Organization
	testAPIKey   *models.APIKey
}

// SetupTest runs before each test
func (suite *APIKeyHandlerTestSuite) SetupTest() {
	suite.ctx = testutils.SetupTestContext(suite.T())
	
	// Create test users
	suite.testUser = testutils.CreateTestRegularUser(suite.ctx.DB)
	suite.testAdmin = testutils.CreateTestAdmin(suite.ctx.DB)
	suite.otherUser = testutils.CreateTestUser(suite.ctx.DB, "other@test.com", models.UserRoleUser)
	
	// Create test organizations
	suite.testOrg = testutils.CreateTestOrganization(suite.ctx.DB, suite.testUser, "Test Org")
	suite.otherOrg = testutils.CreateTestOrganization(suite.ctx.DB, suite.otherUser, "Other Org")
	
	// Create test API key
	suite.testAPIKey = testutils.CreateTestAPIKey(suite.ctx.DB, suite.testUser, suite.testOrg, "Test API Key")
	
	// Load users with organizations
	suite.testUser = testutils.LoadUserWithOrganizations(suite.ctx.DB, suite.testUser.ID)
	suite.testAdmin = testutils.LoadUserWithOrganizations(suite.ctx.DB, suite.testAdmin.ID)
}

// TearDownTest runs after each test
func (suite *APIKeyHandlerTestSuite) TearDownTest() {
	suite.ctx.Cleanup()
}

// TestAPIKeyHandlerTestSuite runs the test suite
func TestAPIKeyHandlerTestSuite(t *testing.T) {
	suite.Run(t, new(APIKeyHandlerTestSuite))
}

// Test creating an API key
func (suite *APIKeyHandlerTestSuite) TestCreateAPIKey_Success() {
	reqBody := map[string]interface{}{
		"name":        "New API Key",
		"permissions": []string{"read", "write"},
		"scopes":      []string{"api", "webhooks"},
	}

	path := "/api/v1/organizations/" + suite.testOrg.ID.String() + "/api-keys"
	w := testutils.AuthenticatedRequest(suite.ctx, suite.testUser, "POST", path, reqBody)

	response := testutils.AssertJSONResponse(suite.T(), w, http.StatusCreated, "api_key", "warning")
	
	apiKey := response["api_key"].(map[string]interface{})
	suite.Equal("New API Key", apiKey["name"])
	suite.Contains(apiKey, "key") // Full key should be present
	suite.Contains(apiKey, "key_prefix")
	suite.Equal([]interface{}{"read", "write"}, apiKey["permissions"])
	suite.Equal([]interface{}{"api", "webhooks"}, apiKey["scopes"])

	// Verify key format
	fullKey := apiKey["key"].(string)
	suite.True(strings.HasPrefix(fullKey, "adc_"))
	suite.Greater(len(fullKey), 40) // Should be reasonably long

	keyPrefix := apiKey["key_prefix"].(string)
	suite.True(strings.HasSuffix(keyPrefix, "..."))

	// Verify warning message
	warning := response["warning"].(string)
	suite.Contains(warning, "only time")

	// Verify API key was created in database
	var dbKey models.APIKey
	err := suite.ctx.DB.Where("name = ?", "New API Key").First(&dbKey).Error
	suite.NoError(err)
	suite.Equal(suite.testUser.ID, dbKey.UserID)
	suite.Equal(suite.testOrg.ID, dbKey.OrganizationID)
	suite.True(dbKey.IsActive)
}

// Test creating API key with expiration
func (suite *APIKeyHandlerTestSuite) TestCreateAPIKey_WithExpiration() {
	expiresAt := time.Now().Add(30 * 24 * time.Hour) // 30 days
	
	reqBody := map[string]interface{}{
		"name":        "Expiring API Key",
		"permissions": []string{"read"},
		"expires_at":  expiresAt.Format(time.RFC3339),
	}

	path := "/api/v1/organizations/" + suite.testOrg.ID.String() + "/api-keys"
	w := testutils.AuthenticatedRequest(suite.ctx, suite.testUser, "POST", path, reqBody)

	response := testutils.AssertJSONResponse(suite.T(), w, http.StatusCreated, "api_key")
	
	apiKey := response["api_key"].(map[string]interface{})
	suite.Equal("Expiring API Key", apiKey["name"])
	suite.NotNil(apiKey["expires_at"])
}

// Test creating API key without permission
func (suite *APIKeyHandlerTestSuite) TestCreateAPIKey_NoPermission() {
	reqBody := map[string]interface{}{
		"name": "Unauthorized Key",
	}

	path := "/api/v1/organizations/" + suite.otherOrg.ID.String() + "/api-keys"
	w := testutils.AuthenticatedRequest(suite.ctx, suite.testUser, "POST", path, reqBody)

	testutils.AssertErrorResponse(suite.T(), w, http.StatusForbidden, "Access denied to organization")
}

// Test creating API key with missing name
func (suite *APIKeyHandlerTestSuite) TestCreateAPIKey_MissingName() {
	reqBody := map[string]interface{}{
		"permissions": []string{"read"},
	}

	path := "/api/v1/organizations/" + suite.testOrg.ID.String() + "/api-keys"
	w := testutils.AuthenticatedRequest(suite.ctx, suite.testUser, "POST", path, reqBody)

	testutils.AssertErrorResponse(suite.T(), w, http.StatusBadRequest, "")
}

// Test listing API keys
func (suite *APIKeyHandlerTestSuite) TestListAPIKeys_Success() {
	// Create another API key
	testutils.CreateTestAPIKey(suite.ctx.DB, suite.testUser, suite.testOrg, "Second Key")

	path := "/api/v1/organizations/" + suite.testOrg.ID.String() + "/api-keys"
	w := testutils.AuthenticatedRequest(suite.ctx, suite.testUser, "GET", path, nil)

	response := testutils.AssertJSONResponse(suite.T(), w, http.StatusOK, "api_keys", "pagination")
	
	apiKeys := response["api_keys"].([]interface{})
	suite.Len(apiKeys, 2)

	// Verify API key structure (should not include full key)
	firstKey := apiKeys[0].(map[string]interface{})
	suite.Contains(firstKey, "id")
	suite.Contains(firstKey, "name")
	suite.Contains(firstKey, "key_prefix")
	suite.Contains(firstKey, "permissions")
	suite.Contains(firstKey, "is_active")
	suite.Contains(firstKey, "created_by")
	suite.NotContains(firstKey, "key") // Full key should not be present

	pagination := response["pagination"].(map[string]interface{})
	suite.Equal(float64(2), pagination["total"])
	suite.Equal(false, pagination["has_more"])
}

// Test listing API keys with pagination
func (suite *APIKeyHandlerTestSuite) TestListAPIKeys_Pagination() {
	// Create multiple API keys
	for i := 0; i < 3; i++ {
		testutils.CreateTestAPIKey(suite.ctx.DB, suite.testUser, suite.testOrg, "Key "+string(rune(i+'A')))
	}

	path := "/api/v1/organizations/" + suite.testOrg.ID.String() + "/api-keys?limit=2&offset=0"
	w := testutils.AuthenticatedRequest(suite.ctx, suite.testUser, "GET", path, nil)

	response := testutils.AssertJSONResponse(suite.T(), w, http.StatusOK, "api_keys", "pagination")
	
	apiKeys := response["api_keys"].([]interface{})
	suite.Len(apiKeys, 2)

	pagination := response["pagination"].(map[string]interface{})
	suite.Equal(float64(4), pagination["total"]) // 1 existing + 3 new
	suite.Equal(float64(2), pagination["limit"])
	suite.Equal(float64(0), pagination["offset"])
	suite.Equal(true, pagination["has_more"])
}

// Test listing API keys including inactive
func (suite *APIKeyHandlerTestSuite) TestListAPIKeys_IncludeInactive() {
	// Deactivate the test API key
	suite.testAPIKey.IsActive = false
	suite.ctx.DB.Save(suite.testAPIKey)

	// Test without include_inactive (should not show inactive)
	path := "/api/v1/organizations/" + suite.testOrg.ID.String() + "/api-keys"
	w := testutils.AuthenticatedRequest(suite.ctx, suite.testUser, "GET", path, nil)

	response := testutils.AssertJSONResponse(suite.T(), w, http.StatusOK, "api_keys")
	apiKeys := response["api_keys"].([]interface{})
	suite.Len(apiKeys, 0)

	// Test with include_inactive (should show inactive)
	path = "/api/v1/organizations/" + suite.testOrg.ID.String() + "/api-keys?include_inactive=true"
	w = testutils.AuthenticatedRequest(suite.ctx, suite.testUser, "GET", path, nil)

	response = testutils.AssertJSONResponse(suite.T(), w, http.StatusOK, "api_keys")
	apiKeys = response["api_keys"].([]interface{})
	suite.Len(apiKeys, 1)

	apiKey := apiKeys[0].(map[string]interface{})
	suite.Equal(false, apiKey["is_active"])
}

// Test getting specific API key
func (suite *APIKeyHandlerTestSuite) TestGetAPIKey_Success() {
	path := "/api/v1/organizations/" + suite.testOrg.ID.String() + "/api-keys/" + suite.testAPIKey.ID.String()
	w := testutils.AuthenticatedRequest(suite.ctx, suite.testUser, "GET", path, nil)

	response := testutils.AssertJSONResponse(suite.T(), w, http.StatusOK, "api_key")
	
	apiKey := response["api_key"].(map[string]interface{})
	suite.Equal(suite.testAPIKey.ID.String(), apiKey["id"])
	suite.Equal(suite.testAPIKey.Name, apiKey["name"])
	suite.Equal(suite.testAPIKey.KeyPrefix, apiKey["key_prefix"])
	suite.NotContains(apiKey, "key") // Full key should not be present

	// Verify created_by information
	createdBy := apiKey["created_by"].(map[string]interface{})
	suite.Equal(suite.testUser.ID.String(), createdBy["id"])
	suite.Equal(suite.testUser.Username, createdBy["username"])
}

// Test getting API key without access
func (suite *APIKeyHandlerTestSuite) TestGetAPIKey_NoAccess() {
	path := "/api/v1/organizations/" + suite.otherOrg.ID.String() + "/api-keys/" + uuid.New().String()
	w := testutils.AuthenticatedRequest(suite.ctx, suite.testUser, "GET", path, nil)

	testutils.AssertErrorResponse(suite.T(), w, http.StatusForbidden, "Access denied to organization")
}

// Test getting non-existent API key
func (suite *APIKeyHandlerTestSuite) TestGetAPIKey_NotFound() {
	path := "/api/v1/organizations/" + suite.testOrg.ID.String() + "/api-keys/" + uuid.New().String()
	w := testutils.AuthenticatedRequest(suite.ctx, suite.testUser, "GET", path, nil)

	testutils.AssertErrorResponse(suite.T(), w, http.StatusNotFound, "API key not found")
}

// Test updating API key
func (suite *APIKeyHandlerTestSuite) TestUpdateAPIKey_Success() {
	reqBody := map[string]interface{}{
		"name":        "Updated API Key",
		"permissions": []string{"read", "admin"},
		"scopes":      []string{"api"},
		"is_active":   false,
	}

	path := "/api/v1/organizations/" + suite.testOrg.ID.String() + "/api-keys/" + suite.testAPIKey.ID.String()
	w := testutils.AuthenticatedRequest(suite.ctx, suite.testUser, "PUT", path, reqBody)

	response := testutils.AssertJSONResponse(suite.T(), w, http.StatusOK, "api_key")
	
	apiKey := response["api_key"].(map[string]interface{})
	suite.Equal("Updated API Key", apiKey["name"])
	suite.Equal([]interface{}{"read", "admin"}, apiKey["permissions"])
	suite.Equal([]interface{}{"api"}, apiKey["scopes"])
	suite.Equal(false, apiKey["is_active"])

	// Verify database was updated
	var dbKey models.APIKey
	err := suite.ctx.DB.First(&dbKey, suite.testAPIKey.ID).Error
	suite.NoError(err)
	suite.Equal("Updated API Key", dbKey.Name)
	suite.False(dbKey.IsActive)
}

// Test updating API key without permission
func (suite *APIKeyHandlerTestSuite) TestUpdateAPIKey_NoPermission() {
	reqBody := map[string]interface{}{
		"name": "Unauthorized Update",
	}

	path := "/api/v1/organizations/" + suite.otherOrg.ID.String() + "/api-keys/" + uuid.New().String()
	w := testutils.AuthenticatedRequest(suite.ctx, suite.testUser, "PUT", path, reqBody)

	testutils.AssertErrorResponse(suite.T(), w, http.StatusForbidden, "Access denied to organization")
}

// Test deleting API key
func (suite *APIKeyHandlerTestSuite) TestDeleteAPIKey_Success() {
	path := "/api/v1/organizations/" + suite.testOrg.ID.String() + "/api-keys/" + suite.testAPIKey.ID.String()
	w := testutils.AuthenticatedRequest(suite.ctx, suite.testUser, "DELETE", path, nil)

	testutils.AssertJSONResponse(suite.T(), w, http.StatusOK, "message")

	// Verify API key was deleted
	var dbKey models.APIKey
	err := suite.ctx.DB.First(&dbKey, suite.testAPIKey.ID).Error
	suite.Error(err)
}

// Test deleting non-existent API key
func (suite *APIKeyHandlerTestSuite) TestDeleteAPIKey_NotFound() {
	path := "/api/v1/organizations/" + suite.testOrg.ID.String() + "/api-keys/" + uuid.New().String()
	w := testutils.AuthenticatedRequest(suite.ctx, suite.testUser, "DELETE", path, nil)

	testutils.AssertErrorResponse(suite.T(), w, http.StatusNotFound, "API key not found")
}

// Test regenerating API key
func (suite *APIKeyHandlerTestSuite) TestRegenerateAPIKey_Success() {
	originalKeyHash := suite.testAPIKey.KeyHash
	originalUsageCount := suite.testAPIKey.UsageCount

	path := "/api/v1/organizations/" + suite.testOrg.ID.String() + "/api-keys/" + suite.testAPIKey.ID.String() + "/regenerate"
	w := testutils.AuthenticatedRequest(suite.ctx, suite.testUser, "POST", path, nil)

	response := testutils.AssertJSONResponse(suite.T(), w, http.StatusOK, "api_key", "warning")
	
	apiKey := response["api_key"].(map[string]interface{})
	suite.Equal(suite.testAPIKey.Name, apiKey["name"])
	suite.Contains(apiKey, "key") // New full key should be present
	suite.Contains(apiKey, "key_prefix")

	// Verify new key is different
	newKey := apiKey["key"].(string)
	suite.NotEqual(originalKeyHash, newKey)
	suite.True(strings.HasPrefix(newKey, "adc_"))

	// Verify warning message
	warning := response["warning"].(string)
	suite.Contains(warning, "only time")

	// Verify database was updated
	var dbKey models.APIKey
	err := suite.ctx.DB.First(&dbKey, suite.testAPIKey.ID).Error
	suite.NoError(err)
	suite.NotEqual(originalKeyHash, dbKey.KeyHash)
	suite.Equal(int64(0), dbKey.UsageCount) // Should reset usage count
	suite.Nil(dbKey.LastUsedAt)             // Should reset last used
}

// Test regenerating non-existent API key
func (suite *APIKeyHandlerTestSuite) TestRegenerateAPIKey_NotFound() {
	path := "/api/v1/organizations/" + suite.testOrg.ID.String() + "/api-keys/" + uuid.New().String() + "/regenerate"
	w := testutils.AuthenticatedRequest(suite.ctx, suite.testUser, "POST", path, nil)

	testutils.AssertErrorResponse(suite.T(), w, http.StatusNotFound, "API key not found")
}

// Test API key operations with member role
func (suite *APIKeyHandlerTestSuite) TestAPIKeyOperations_MemberRole() {
	// Add otherUser as member to testOrg
	testutils.AddUserToOrganization(suite.ctx.DB, suite.otherUser, suite.testOrg, models.UserRoleMember)

	reqBody := map[string]interface{}{
		"name": "Member Key",
	}

	path := "/api/v1/organizations/" + suite.testOrg.ID.String() + "/api-keys"
	w := testutils.AuthenticatedRequest(suite.ctx, suite.otherUser, "POST", path, reqBody)

	testutils.AssertErrorResponse(suite.T(), w, http.StatusForbidden, "Insufficient permissions to create API keys")
}

// Test API key operations with admin role in organization
func (suite *APIKeyHandlerTestSuite) TestAPIKeyOperations_OrgAdminRole() {
	// Add otherUser as admin to testOrg
	testutils.AddUserToOrganization(suite.ctx.DB, suite.otherUser, suite.testOrg, models.UserRoleAdmin)

	reqBody := map[string]interface{}{
		"name": "Admin Key",
	}

	path := "/api/v1/organizations/" + suite.testOrg.ID.String() + "/api-keys"
	w := testutils.AuthenticatedRequest(suite.ctx, suite.otherUser, "POST", path, reqBody)

	response := testutils.AssertJSONResponse(suite.T(), w, http.StatusCreated, "api_key")
	
	apiKey := response["api_key"].(map[string]interface{})
	suite.Equal("Admin Key", apiKey["name"])
}

// Test invalid UUID in API key ID
func (suite *APIKeyHandlerTestSuite) TestAPIKeyInvalidUUID() {
	path := "/api/v1/organizations/" + suite.testOrg.ID.String() + "/api-keys/invalid-uuid"
	w := testutils.AuthenticatedRequest(suite.ctx, suite.testUser, "GET", path, nil)

	testutils.AssertErrorResponse(suite.T(), w, http.StatusBadRequest, "Invalid API key ID")
}

// Test API key operations without authentication
func (suite *APIKeyHandlerTestSuite) TestAPIKeyUnauthenticated() {
	path := "/api/v1/organizations/" + suite.testOrg.ID.String() + "/api-keys"
	w := testutils.PerformRequest(suite.ctx.Router, "GET", path, nil, nil)

	testutils.AssertErrorResponse(suite.T(), w, http.StatusUnauthorized, "Authentication required")
}

// Test concurrent API key operations
func (suite *APIKeyHandlerTestSuite) TestConcurrentAPIKeyOperations() {
	numRequests := 10
	results := make(chan int, numRequests)

	path := "/api/v1/organizations/" + suite.testOrg.ID.String() + "/api-keys"

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

// Test API key creation with various edge cases
func (suite *APIKeyHandlerTestSuite) TestAPIKeyCreationEdgeCases() {
	// Test with empty permissions and scopes
	reqBody := map[string]interface{}{
		"name":        "Empty Permissions Key",
		"permissions": []string{},
		"scopes":      []string{},
	}

	path := "/api/v1/organizations/" + suite.testOrg.ID.String() + "/api-keys"
	w := testutils.AuthenticatedRequest(suite.ctx, suite.testUser, "POST", path, reqBody)

	response := testutils.AssertJSONResponse(suite.T(), w, http.StatusCreated, "api_key")
	
	apiKey := response["api_key"].(map[string]interface{})
	suite.Equal("Empty Permissions Key", apiKey["name"])
	suite.Equal([]interface{}{}, apiKey["permissions"])
	suite.Equal([]interface{}{}, apiKey["scopes"])
}

// Test API key usage statistics
func (suite *APIKeyHandlerTestSuite) TestAPIKeyUsageStatistics() {
	// Update usage statistics
	suite.testAPIKey.UsageCount = 10
	now := time.Now()
	suite.testAPIKey.LastUsedAt = &now
	suite.ctx.DB.Save(suite.testAPIKey)

	path := "/api/v1/organizations/" + suite.testOrg.ID.String() + "/api-keys/" + suite.testAPIKey.ID.String()
	w := testutils.AuthenticatedRequest(suite.ctx, suite.testUser, "GET", path, nil)

	response := testutils.AssertJSONResponse(suite.T(), w, http.StatusOK, "api_key")
	
	apiKey := response["api_key"].(map[string]interface{})
	suite.Equal(float64(10), apiKey["usage_count"])
	suite.NotNil(apiKey["last_used_at"])
}