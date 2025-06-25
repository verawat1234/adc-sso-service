package main

import (
	"net/http"
	"testing"

	"adc-sso-service/internal/models"
	"adc-sso-service/internal/testutils"
	"adc-sso-service/internal/types"

	"github.com/stretchr/testify/suite"
)

// E2ETestSuite defines the end-to-end test suite
type E2ETestSuite struct {
	suite.Suite
	ctx *testutils.TestContext
}

// SetupSuite runs once before all tests
func (suite *E2ETestSuite) SetupSuite() {
	suite.ctx = testutils.SetupTestContext(suite.T())
}

// TearDownSuite runs once after all tests
func (suite *E2ETestSuite) TearDownSuite() {
	suite.ctx.Cleanup()
}

// SetupTest runs before each test
func (suite *E2ETestSuite) SetupTest() {
	// Clean database between tests
	testutils.TruncateAllTables(suite.ctx.DB)
}

// TestE2ETestSuite runs the test suite
func TestE2ETestSuite(t *testing.T) {
	suite.Run(t, new(E2ETestSuite))
}

// Test complete SSO authentication flow
func (suite *E2ETestSuite) TestCompleteSSOFlow() {
	// Step 1: Initiate SSO login
	w := testutils.PerformRequest(suite.ctx.Router, "GET", "/sso/login", nil, nil)
	response := testutils.AssertSuccessResponse(suite.T(), w, "data")
	
	data := response["data"].(map[string]interface{})
	redirectURL := data["redirect_url"].(string)
	state := data["state"].(string)
	
	suite.NotEmpty(redirectURL)
	suite.NotEmpty(state)
	
	// Step 2: Mock successful Keycloak authentication
	suite.ctx.MockKeycloak.Reset()
	suite.ctx.MockKeycloak.SetUserInfo(map[string]interface{}{
		"sub":             "keycloak-user-123",
		"email":           "e2e@example.com",
		"email_verified":  true,
		"name":            "E2E Test User",
		"given_name":      "E2E",
		"family_name":     "User",
		"preferred_username": "e2euser",
	})

	// Step 3: Handle SSO callback
	callbackURL := "/sso/callback?code=test_code&state=" + state
	headers := map[string]string{
		"Cookie": "sso_state=" + state,
	}
	
	w = testutils.PerformRequest(suite.ctx.Router, "GET", callbackURL, nil, headers)
	response = testutils.AssertSuccessResponse(suite.T(), w, "data")
	
	data = response["data"].(map[string]interface{})
	accessToken := data["access_token"].(string)
	refreshToken := data["refresh_token"].(string)
	userID := data["user_id"].(string)
	
	suite.NotEmpty(accessToken)
	suite.NotEmpty(refreshToken)
	suite.NotEmpty(userID)
	suite.Equal("e2e@example.com", data["email"])
	suite.Equal(true, data["is_new_user"])
	
	// Step 4: Use access token to make authenticated requests
	authHeaders := map[string]string{
		"Authorization": "Bearer " + accessToken,
	}
	
	// Test creating an organization
	orgData := map[string]interface{}{
		"name":        "E2E Test Organization",
		"description": "Created during E2E test",
	}
	
	w = testutils.PerformRequest(suite.ctx.Router, "POST", "/api/v1/organizations", orgData, authHeaders)
	orgResponse := testutils.AssertJSONResponse(suite.T(), w, http.StatusCreated, "organization")
	
	org := orgResponse["organization"].(map[string]interface{})
	orgID := org["id"].(string)
	suite.Equal("E2E Test Organization", org["name"])
	
	// Step 5: Test API key creation
	apiKeyData := map[string]interface{}{
		"name":        "E2E API Key",
		"permissions": []string{"read", "write"},
	}
	
	w = testutils.PerformRequest(suite.ctx.Router, "POST", "/api/v1/organizations/"+orgID+"/api-keys", apiKeyData, authHeaders)
	keyResponse := testutils.AssertJSONResponse(suite.T(), w, http.StatusCreated, "api_key")
	
	apiKey := keyResponse["api_key"].(map[string]interface{})
	fullAPIKey := apiKey["key"].(string)
	suite.Equal("E2E API Key", apiKey["name"])
	
	// Step 6: Test API key authentication
	apiKeyHeaders := map[string]string{
		"X-API-Key": fullAPIKey,
	}
	
	w = testutils.PerformRequest(suite.ctx.Router, "GET", "/api/v1/organizations/"+orgID, nil, apiKeyHeaders)
	testutils.AssertJSONResponse(suite.T(), w, http.StatusOK, "organization")
	
	// Step 7: Test token refresh
	refreshData := types.TokenRefreshRequest{
		RefreshToken: refreshToken,
	}
	
	w = testutils.PerformRequest(suite.ctx.Router, "POST", "/sso/refresh", refreshData, nil)
	refreshResponse := testutils.AssertSuccessResponse(suite.T(), w, "data")
	
	refreshData2 := refreshResponse["data"].(map[string]interface{})
	newAccessToken := refreshData2["access_token"].(string)
	suite.NotEmpty(newAccessToken)
	suite.NotEqual(accessToken, newAccessToken)
	
	// Step 8: Verify new token works
	newAuthHeaders := map[string]string{
		"Authorization": "Bearer " + newAccessToken,
	}
	
	w = testutils.PerformRequest(suite.ctx.Router, "GET", "/api/v1/organizations", nil, newAuthHeaders)
	testutils.AssertJSONResponse(suite.T(), w, http.StatusOK, "organizations")
}

// Test complete organization management workflow
func (suite *E2ETestSuite) TestCompleteOrganizationWorkflow() {
	// Setup: Create test user
	user := testutils.CreateTestRegularUser(suite.ctx.DB)
	
	// Step 1: Create access token for user
	token, err := suite.ctx.AuthService.GenerateToken(
		user.ID.String(),
		user.Username,
		user.Email,
		string(user.Role),
	)
	suite.NoError(err)
	
	authHeaders := map[string]string{
		"Authorization": "Bearer " + token,
	}
	
	// Step 2: Create organization
	orgData := map[string]interface{}{
		"name":        "Workflow Test Org",
		"description": "Organization for workflow testing",
		"website":     "https://workflow.test",
	}
	
	w := testutils.PerformRequest(suite.ctx.Router, "POST", "/api/v1/organizations", orgData, authHeaders)
	orgResponse := testutils.AssertJSONResponse(suite.T(), w, http.StatusCreated, "organization")
	
	org := orgResponse["organization"].(map[string]interface{})
	orgID := org["id"].(string)
	
	// Step 3: List organizations (should show the created one)
	w = testutils.PerformRequest(suite.ctx.Router, "GET", "/api/v1/organizations", nil, authHeaders)
	listResponse := testutils.AssertJSONResponse(suite.T(), w, http.StatusOK, "organizations")
	
	organizations := listResponse["organizations"].([]interface{})
	suite.Len(organizations, 1)
	
	// Step 4: Get specific organization
	w = testutils.PerformRequest(suite.ctx.Router, "GET", "/api/v1/organizations/"+orgID, nil, authHeaders)
	getResponse := testutils.AssertJSONResponse(suite.T(), w, http.StatusOK, "organization")
	
	orgDetails := getResponse["organization"].(map[string]interface{})
	suite.Equal("Workflow Test Org", orgDetails["name"])
	suite.Equal("https://workflow.test", orgDetails["website"])
	
	// Step 5: Create multiple API keys
	for i := 1; i <= 3; i++ {
		keyData := map[string]interface{}{
			"name":        "Workflow Key " + string(rune(i+48)),
			"permissions": []string{"read"},
		}
		
		w = testutils.PerformRequest(suite.ctx.Router, "POST", "/api/v1/organizations/"+orgID+"/api-keys", keyData, authHeaders)
		testutils.AssertJSONResponse(suite.T(), w, http.StatusCreated, "api_key")
	}
	
	// Step 6: List API keys
	w = testutils.PerformRequest(suite.ctx.Router, "GET", "/api/v1/organizations/"+orgID+"/api-keys", nil, authHeaders)
	keysResponse := testutils.AssertJSONResponse(suite.T(), w, http.StatusOK, "api_keys")
	
	apiKeys := keysResponse["api_keys"].([]interface{})
	suite.Len(apiKeys, 3)
	
	// Step 7: Update organization
	updateData := map[string]interface{}{
		"description": "Updated during workflow test",
		"website":     "https://updated.workflow.test",
	}
	
	w = testutils.PerformRequest(suite.ctx.Router, "PUT", "/api/v1/organizations/"+orgID, updateData, authHeaders)
	updateResponse := testutils.AssertJSONResponse(suite.T(), w, http.StatusOK, "organization")
	
	updatedOrg := updateResponse["organization"].(map[string]interface{})
	suite.Equal("Updated during workflow test", updatedOrg["description"])
	
	// Step 8: Delete an API key
	firstKey := apiKeys[0].(map[string]interface{})
	keyID := firstKey["id"].(string)
	
	w = testutils.PerformRequest(suite.ctx.Router, "DELETE", "/api/v1/organizations/"+orgID+"/api-keys/"+keyID, nil, authHeaders)
	testutils.AssertJSONResponse(suite.T(), w, http.StatusOK, "message")
	
	// Step 9: Verify API key was deleted
	w = testutils.PerformRequest(suite.ctx.Router, "GET", "/api/v1/organizations/"+orgID+"/api-keys", nil, authHeaders)
	keysResponse2 := testutils.AssertJSONResponse(suite.T(), w, http.StatusOK, "api_keys")
	
	remainingKeys := keysResponse2["api_keys"].([]interface{})
	suite.Len(remainingKeys, 2)
	
	// Step 10: List organization members
	w = testutils.PerformRequest(suite.ctx.Router, "GET", "/api/v1/organizations/"+orgID+"/members", nil, authHeaders)
	membersResponse := testutils.AssertJSONResponse(suite.T(), w, http.StatusOK, "members")
	
	members := membersResponse["members"].([]interface{})
	suite.Len(members, 1) // Only the owner
	
	ownerMember := members[0].(map[string]interface{})
	suite.Equal(string(models.UserRoleOwner), ownerMember["role"])
}

// Test multi-tenant security boundaries
func (suite *E2ETestSuite) TestMultiTenantSecurity() {
	// Create two users with their organizations
	user1 := testutils.CreateTestUser(suite.ctx.DB, "user1@test.com", models.UserRoleUser)
	user2 := testutils.CreateTestUser(suite.ctx.DB, "user2@test.com", models.UserRoleUser)
	
	org1 := testutils.CreateTestOrganization(suite.ctx.DB, user1, "User1 Org")
	org2 := testutils.CreateTestOrganization(suite.ctx.DB, user2, "User2 Org")
	
	// Create API keys for each organization
	apiKey1 := testutils.CreateTestAPIKey(suite.ctx.DB, user1, org1, "User1 Key")
	apiKey2 := testutils.CreateTestAPIKey(suite.ctx.DB, user2, org2, "User2 Key")
	
	// Test 1: User1 should not access User2's organization with JWT
	token1, _ := suite.ctx.AuthService.GenerateToken(
		user1.ID.String(), user1.Username, user1.Email, string(user1.Role),
	)
	
	authHeaders1 := map[string]string{
		"Authorization": "Bearer " + token1,
	}
	
	// Try to access user2's organization
	w := testutils.PerformRequest(suite.ctx.Router, "GET", "/api/v1/organizations/"+org2.ID.String(), nil, authHeaders1)
	testutils.AssertErrorResponse(suite.T(), w, http.StatusForbidden, "Access denied")
	
	// Test 2: User1's API key should not work with User2's organization
	apiKeyHeaders1 := map[string]string{
		"X-API-Key": apiKey1.KeyHash,
	}
	
	w = testutils.PerformRequest(suite.ctx.Router, "GET", "/api/v1/organizations/"+org2.ID.String(), nil, apiKeyHeaders1)
	testutils.AssertErrorResponse(suite.T(), w, http.StatusForbidden, "Access denied")
	
	// Test 3: Cross-organization API key creation should fail
	keyData := map[string]interface{}{
		"name": "Cross Tenant Key",
	}
	
	w = testutils.PerformRequest(suite.ctx.Router, "POST", "/api/v1/organizations/"+org2.ID.String()+"/api-keys", keyData, authHeaders1)
	testutils.AssertErrorResponse(suite.T(), w, http.StatusForbidden, "Access denied")
	
	// Test 4: Verify users can access their own resources
	w = testutils.PerformRequest(suite.ctx.Router, "GET", "/api/v1/organizations/"+org1.ID.String(), nil, authHeaders1)
	testutils.AssertJSONResponse(suite.T(), w, http.StatusOK, "organization")
	
	apiKeyHeaders2 := map[string]string{
		"X-API-Key": apiKey2.KeyHash,
	}
	
	w = testutils.PerformRequest(suite.ctx.Router, "GET", "/api/v1/organizations/"+org2.ID.String(), nil, apiKeyHeaders2)
	testutils.AssertJSONResponse(suite.T(), w, http.StatusOK, "organization")
}

// Test admin access privileges
func (suite *E2ETestSuite) TestAdminAccessPrivileges() {
	// Create regular user and admin
	user := testutils.CreateTestRegularUser(suite.ctx.DB)
	admin := testutils.CreateTestAdmin(suite.ctx.DB)
	
	// Create user's organization
	org := testutils.CreateTestOrganization(suite.ctx.DB, user, "User Org")
	
	// Create admin token
	adminToken, _ := suite.ctx.AuthService.GenerateToken(
		admin.ID.String(), admin.Username, admin.Email, string(admin.Role),
	)
	
	adminHeaders := map[string]string{
		"Authorization": "Bearer " + adminToken,
	}
	
	// Test 1: Admin should see all organizations
	w := testutils.PerformRequest(suite.ctx.Router, "GET", "/api/v1/organizations", nil, adminHeaders)
	response := testutils.AssertJSONResponse(suite.T(), w, http.StatusOK, "organizations")
	
	organizations := response["organizations"].([]interface{})
	suite.GreaterOrEqual(len(organizations), 1)
	
	// Test 2: Admin should access any organization
	w = testutils.PerformRequest(suite.ctx.Router, "GET", "/api/v1/organizations/"+org.ID.String(), nil, adminHeaders)
	orgResponse := testutils.AssertJSONResponse(suite.T(), w, http.StatusOK, "organization")
	
	orgData := orgResponse["organization"].(map[string]interface{})
	suite.Equal(string(models.UserRoleAdmin), orgData["user_role"])
	
	// Test 3: Admin should be able to update any organization status
	updateData := map[string]interface{}{
		"status": string(models.OrganizationStatusInactive),
	}
	
	w = testutils.PerformRequest(suite.ctx.Router, "PUT", "/api/v1/organizations/"+org.ID.String(), updateData, adminHeaders)
	testutils.AssertJSONResponse(suite.T(), w, http.StatusOK, "organization")
	
	// Test 4: Admin should be able to delete any organization
	w = testutils.PerformRequest(suite.ctx.Router, "DELETE", "/api/v1/organizations/"+org.ID.String(), nil, adminHeaders)
	testutils.AssertJSONResponse(suite.T(), w, http.StatusOK, "message")
}

// Test error handling and edge cases
func (suite *E2ETestSuite) TestErrorHandlingAndEdgeCases() {
	// Test 1: Invalid UUIDs
	user := testutils.CreateTestRegularUser(suite.ctx.DB)
	token, _ := suite.ctx.AuthService.GenerateToken(
		user.ID.String(), user.Username, user.Email, string(user.Role),
	)
	
	authHeaders := map[string]string{
		"Authorization": "Bearer " + token,
	}
	
	w := testutils.PerformRequest(suite.ctx.Router, "GET", "/api/v1/organizations/invalid-uuid", nil, authHeaders)
	testutils.AssertErrorResponse(suite.T(), w, http.StatusBadRequest, "Invalid organization ID")
	
	// Test 2: Malformed JSON
	w = testutils.PerformRequest(suite.ctx.Router, "POST", "/api/v1/organizations", "invalid json", authHeaders)
	testutils.AssertErrorResponse(suite.T(), w, http.StatusBadRequest, "")
	
	// Test 3: Missing required fields
	emptyOrgData := map[string]interface{}{}
	w = testutils.PerformRequest(suite.ctx.Router, "POST", "/api/v1/organizations", emptyOrgData, authHeaders)
	testutils.AssertErrorResponse(suite.T(), w, http.StatusBadRequest, "")
	
	// Test 4: Unauthenticated requests
	w = testutils.PerformRequest(suite.ctx.Router, "GET", "/api/v1/organizations", nil, nil)
	testutils.AssertErrorResponse(suite.T(), w, http.StatusUnauthorized, "Authentication required")
	
	// Test 5: Invalid token format
	invalidAuthHeaders := map[string]string{
		"Authorization": "InvalidTokenFormat",
	}
	
	w = testutils.PerformRequest(suite.ctx.Router, "GET", "/api/v1/organizations", nil, invalidAuthHeaders)
	testutils.AssertErrorResponse(suite.T(), w, http.StatusUnauthorized, "Authentication required")
}

// Test concurrent operations
func (suite *E2ETestSuite) TestConcurrentOperations() {
	// Create user and organization
	user := testutils.CreateTestRegularUser(suite.ctx.DB)
	org := testutils.CreateTestOrganization(suite.ctx.DB, user, "Concurrent Org")
	
	token, _ := suite.ctx.AuthService.GenerateToken(
		user.ID.String(), user.Username, user.Email, string(user.Role),
	)
	
	authHeaders := map[string]string{
		"Authorization": "Bearer " + token,
	}
	
	// Test concurrent API key creation
	numKeys := 5
	results := make(chan int, numKeys)
	
	for i := 0; i < numKeys; i++ {
		go func(index int) {
			keyData := map[string]interface{}{
				"name": "Concurrent Key " + string(rune(index+49)),
			}
			
			w := testutils.PerformRequest(suite.ctx.Router, "POST", "/api/v1/organizations/"+org.ID.String()+"/api-keys", keyData, authHeaders)
			results <- w.Code
		}(i)
	}
	
	// Collect results
	successCount := 0
	for i := 0; i < numKeys; i++ {
		statusCode := <-results
		if statusCode == http.StatusCreated {
			successCount++
		}
	}
	
	// All API key creations should succeed
	suite.Equal(numKeys, successCount)
	
	// Verify all keys were created
	w := testutils.PerformRequest(suite.ctx.Router, "GET", "/api/v1/organizations/"+org.ID.String()+"/api-keys", nil, authHeaders)
	response := testutils.AssertJSONResponse(suite.T(), w, http.StatusOK, "api_keys")
	
	apiKeys := response["api_keys"].([]interface{})
	suite.Len(apiKeys, numKeys)
}

// Test service health and status
func (suite *E2ETestSuite) TestServiceHealthAndStatus() {
	// Test health endpoint
	w := testutils.PerformRequest(suite.ctx.Router, "GET", "/health", nil, nil)
	response := testutils.AssertJSONResponse(suite.T(), w, http.StatusOK, "status", "service", "database")
	
	suite.Equal("healthy", response["status"])
	suite.Equal("ADC SSO Service", response["service"])
	suite.Equal("connected", response["database"])
	
	// Test root endpoint
	w = testutils.PerformRequest(suite.ctx.Router, "GET", "/", nil, nil)
	response = testutils.AssertJSONResponse(suite.T(), w, http.StatusOK, "service", "version", "endpoints")
	
	suite.Equal("ADC SSO Service - Enhanced", response["service"])
	suite.Equal("2.0.0", response["version"])
	suite.Contains(response, "endpoints")
}