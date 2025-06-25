package middleware

import (
	"encoding/json"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"adc-sso-service/internal/auth"
	"adc-sso-service/internal/models"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/suite"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// AuthMiddlewareTestSuite defines the test suite for authentication middleware
type AuthMiddlewareTestSuite struct {
	suite.Suite
	db             *gorm.DB
	authService    *auth.AuthService
	authMiddleware *AuthMiddleware
	router         *gin.Engine
	testUser       *models.User
	testAdmin      *models.User
	testOrg        *models.Organization
	testAPIKey     *models.APIKey
}

// setupTestDB creates a PostgreSQL database connection for testing
func (suite *AuthMiddlewareTestSuite) setupTestDB() *gorm.DB {
	// Use Supabase PostgreSQL for tests
	testDBURL := "postgresql://postgres.rifsieaejflaeaqwwjvk:KL3hWne8KKYAUzZM@aws-0-ap-southeast-1.pooler.supabase.com:6543/postgres"
	
	// Override with environment variable if provided
	if envDBURL := os.Getenv("TEST_DATABASE_URL"); envDBURL != "" {
		testDBURL = envDBURL
	}
	
	db, err := gorm.Open(postgres.Open(testDBURL), &gorm.Config{
		Logger: logger.New(
			log.New(os.Stdout, "\r\n", log.LstdFlags),
			logger.Config{
				LogLevel: logger.Silent,
			},
		),
	})
	if err != nil {
		suite.T().Fatalf("Failed to connect to test database: %v", err)
	}

	err = db.AutoMigrate(
		&models.User{},
		&models.Organization{},
		&models.UserOrganization{},
		&models.APIKey{},
		&models.SSOUserMapping{},
		&models.AuditLog{},
	)
	if err != nil {
		// Check if the error is about existing relations, which is fine for tests
		if !isTableExistsError(err) {
			suite.T().Fatalf("Failed to migrate test database: %v", err)
		}
		// Tables already exist, which is fine for shared test database
	}

	return db
}

// isTableExistsError checks if the error is related to table already existing
func isTableExistsError(err error) bool {
	return strings.Contains(err.Error(), "already exists") || 
		   strings.Contains(err.Error(), "42P07")
}

// createTestUser creates a test user
func (suite *AuthMiddlewareTestSuite) createTestUser(email string, role models.UserRole) *models.User {
	user := &models.User{
		Username:    "testuser",
		Email:       email,
		Password:    "hashed_password",
		FullName:    "Test User",
		Role:        role,
		Status:      models.UserStatusActive,
		Timezone:    "UTC",
		Locale:      "en",
	}

	err := suite.db.Create(user).Error
	if err != nil {
		suite.T().Fatalf("Failed to create test user: %v", err)
	}

	return user
}

// createTestOrganization creates a test organization
func (suite *AuthMiddlewareTestSuite) createTestOrganization(owner *models.User, name string) *models.Organization {
	org := &models.Organization{
		Name:    name,
		OwnerID: owner.ID,
		Status:  models.OrganizationStatusActive,
	}

	err := suite.db.Create(org).Error
	if err != nil {
		suite.T().Fatalf("Failed to create test organization: %v", err)
	}

	// Create user-organization relationship
	userOrg := &models.UserOrganization{
		UserID:         owner.ID,
		OrganizationID: org.ID,
		Role:           models.UserRoleOwner,
		Status:         models.UserStatusActive,
	}

	err = suite.db.Create(userOrg).Error
	if err != nil {
		suite.T().Fatalf("Failed to create user-organization relationship: %v", err)
	}

	return org
}

// createTestAPIKey creates a test API key
func (suite *AuthMiddlewareTestSuite) createTestAPIKey(user *models.User, org *models.Organization, name string) *models.APIKey {
	fullKey, keyHash, keyPrefix, err := models.GenerateAPIKey()
	if err != nil {
		suite.T().Fatalf("Failed to generate API key: %v", err)
	}

	apiKey := &models.APIKey{
		Name:           name,
		KeyHash:        keyHash,
		KeyPrefix:      keyPrefix,
		UserID:         user.ID,
		OrganizationID: org.ID,
		Permissions:    []string{"read", "write"},
		Scopes:         []string{"api"},
		IsActive:       true,
	}

	err = suite.db.Create(apiKey).Error
	if err != nil {
		suite.T().Fatalf("Failed to create test API key: %v", err)
	}

	// Store the full key for testing
	apiKey.KeyHash = fullKey
	return apiKey
}

// createExpiredAPIKey creates an expired API key for testing
func (suite *AuthMiddlewareTestSuite) createExpiredAPIKey(user *models.User, org *models.Organization) *models.APIKey {
	fullKey, keyHash, keyPrefix, err := models.GenerateAPIKey()
	if err != nil {
		suite.T().Fatalf("Failed to generate API key: %v", err)
	}

	yesterday := time.Now().Add(-24 * time.Hour)
	apiKey := &models.APIKey{
		Name:           "Expired Key",
		KeyHash:        keyHash,
		KeyPrefix:      keyPrefix,
		UserID:         user.ID,
		OrganizationID: org.ID,
		Permissions:    []string{"read"},
		Scopes:         []string{"api"},
		IsActive:       true,
		ExpiresAt:      &yesterday,
	}

	err = suite.db.Create(apiKey).Error
	if err != nil {
		suite.T().Fatalf("Failed to create expired API key: %v", err)
	}

	// Store the full key for testing
	apiKey.KeyHash = fullKey
	return apiKey
}

// loadUserWithOrganizations loads user with organization relationships
func (suite *AuthMiddlewareTestSuite) loadUserWithOrganizations(userID uuid.UUID) *models.User {
	var user models.User
	err := suite.db.Preload("UserOrganizations").First(&user, userID).Error
	if err != nil {
		suite.T().Fatalf("Failed to load user with organizations: %v", err)
	}
	return &user
}

// assertJSONResponse asserts a JSON response with expected fields
func (suite *AuthMiddlewareTestSuite) assertJSONResponse(w *httptest.ResponseRecorder, expectedStatus int, expectedFields ...string) map[string]interface{} {
	suite.Equal(expectedStatus, w.Code)
	suite.Equal("application/json; charset=utf-8", w.Header().Get("Content-Type"))

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	suite.NoError(err)

	for _, field := range expectedFields {
		suite.Contains(response, field)
	}

	return response
}

// assertErrorResponse asserts an error response
func (suite *AuthMiddlewareTestSuite) assertErrorResponse(w *httptest.ResponseRecorder, expectedStatus int, expectedMessage string) {
	response := suite.assertJSONResponse(w, expectedStatus, "success", "message")
	suite.False(response["success"].(bool))
	if expectedMessage != "" {
		suite.Contains(response["message"].(string), expectedMessage)
	}
}

// SetupTest runs before each test
func (suite *AuthMiddlewareTestSuite) SetupTest() {
	gin.SetMode(gin.TestMode)
	
	// Setup test database
	suite.db = suite.setupTestDB()
	
	// Create auth service
	suite.authService = auth.NewAuthService("test-secret")
	
	// Create auth middleware
	suite.authMiddleware = NewAuthMiddleware(suite.authService, suite.db)
	
	// Setup router
	suite.router = gin.New()
	
	// Create test users
	suite.testUser = suite.createTestUser("testuser@example.com", models.UserRoleUser)
	suite.testAdmin = suite.createTestUser("admin@example.com", models.UserRoleAdmin)
	
	// Create test organization
	suite.testOrg = suite.createTestOrganization(suite.testUser, "Test Org")
	
	// Create test API key
	suite.testAPIKey = suite.createTestAPIKey(suite.testUser, suite.testOrg, "Test Key")
	
	// Load user with organizations
	suite.testUser = suite.loadUserWithOrganizations(suite.testUser.ID)
}

// TearDownTest runs after each test
func (suite *AuthMiddlewareTestSuite) TearDownTest() {
	if suite.db != nil {
		sqlDB, err := suite.db.DB()
		if err == nil {
			sqlDB.Close()
		}
	}
}

// TestAuthMiddlewareTestSuite runs the test suite
func TestAuthMiddlewareTestSuite(t *testing.T) {
	suite.Run(t, new(AuthMiddlewareTestSuite))
}

// Test JWT authentication middleware with valid token
func (suite *AuthMiddlewareTestSuite) TestJWTAuthMiddleware_ValidToken() {
	// Create a route that requires JWT auth
	suite.router.GET("/protected", suite.authMiddleware.JWTAuthMiddleware(), func(c *gin.Context) {
		user, exists := GetUserFromContext(c)
		suite.True(exists)
		suite.Equal(suite.testUser.ID, user.ID)
		c.JSON(http.StatusOK, gin.H{"user_id": user.ID})
	})

	// Create valid JWT token
	token, err := suite.authService.GenerateToken(
		suite.testUser.ID.String(),
		suite.testUser.Username,
		suite.testUser.Email,
		string(suite.testUser.Role),
	)
	suite.NoError(err)

	// Make request with valid token
	req := httptest.NewRequest("GET", "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()

	suite.router.ServeHTTP(w, req)

	suite.Equal(http.StatusOK, w.Code)
	
	// Verify response contains user ID
	response := suite.assertJSONResponse(w, http.StatusOK, "user_id")
	suite.Equal(suite.testUser.ID.String(), response["user_id"])
}

// Test JWT authentication middleware with missing token
func (suite *AuthMiddlewareTestSuite) TestJWTAuthMiddleware_MissingToken() {
	suite.router.GET("/protected", suite.authMiddleware.JWTAuthMiddleware(), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"success": true})
	})

	req := httptest.NewRequest("GET", "/protected", nil)
	w := httptest.NewRecorder()

	suite.router.ServeHTTP(w, req)

	suite.assertErrorResponse(w, http.StatusUnauthorized, "Authorization header required")
}

// Test JWT authentication middleware with invalid token format
func (suite *AuthMiddlewareTestSuite) TestJWTAuthMiddleware_InvalidTokenFormat() {
	suite.router.GET("/protected", suite.authMiddleware.JWTAuthMiddleware(), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"success": true})
	})

	// Test without "Bearer " prefix
	req := httptest.NewRequest("GET", "/protected", nil)
	req.Header.Set("Authorization", "invalid-token")
	w := httptest.NewRecorder()

	suite.router.ServeHTTP(w, req)

	suite.assertErrorResponse(w, http.StatusUnauthorized, "Invalid authorization header format")
}

// Test JWT authentication middleware with invalid token
func (suite *AuthMiddlewareTestSuite) TestJWTAuthMiddleware_InvalidToken() {
	suite.router.GET("/protected", suite.authMiddleware.JWTAuthMiddleware(), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"success": true})
	})

	req := httptest.NewRequest("GET", "/protected", nil)
	req.Header.Set("Authorization", "Bearer invalid.jwt.token")
	w := httptest.NewRecorder()

	suite.router.ServeHTTP(w, req)

	suite.assertErrorResponse(w, http.StatusUnauthorized, "Invalid token")
}

// Test JWT authentication middleware with inactive user
func (suite *AuthMiddlewareTestSuite) TestJWTAuthMiddleware_InactiveUser() {
	// Deactivate user
	suite.testUser.Status = models.UserStatusInactive
	suite.db.Save(suite.testUser)

	suite.router.GET("/protected", suite.authMiddleware.JWTAuthMiddleware(), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"success": true})
	})

	token, err := suite.authService.GenerateToken(
		suite.testUser.ID.String(),
		suite.testUser.Username,
		suite.testUser.Email,
		string(suite.testUser.Role),
	)
	suite.NoError(err)

	req := httptest.NewRequest("GET", "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()

	suite.router.ServeHTTP(w, req)

	suite.assertErrorResponse(w, http.StatusUnauthorized, "not active")
}

// Test API key authentication middleware with valid key
func (suite *AuthMiddlewareTestSuite) TestAPIKeyAuthMiddleware_ValidKey() {
	suite.router.GET("/api", suite.authMiddleware.APIKeyAuthMiddleware(), func(c *gin.Context) {
		user, exists := GetUserFromContext(c)
		suite.True(exists)
		suite.Equal(suite.testUser.ID, user.ID)
		
		orgID, exists := GetOrganizationIDFromContext(c)
		suite.True(exists)
		suite.Equal(suite.testOrg.ID, orgID)
		
		c.JSON(http.StatusOK, gin.H{"success": true})
	})

	req := httptest.NewRequest("GET", "/api", nil)
	req.Header.Set("X-API-Key", suite.testAPIKey.KeyHash) // Using full key stored in fixture
	w := httptest.NewRecorder()

	suite.router.ServeHTTP(w, req)

	suite.Equal(http.StatusOK, w.Code)
}

// Test API key authentication middleware with missing key
func (suite *AuthMiddlewareTestSuite) TestAPIKeyAuthMiddleware_MissingKey() {
	suite.router.GET("/api", suite.authMiddleware.APIKeyAuthMiddleware(), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"success": true})
	})

	req := httptest.NewRequest("GET", "/api", nil)
	w := httptest.NewRecorder()

	suite.router.ServeHTTP(w, req)

	suite.assertErrorResponse(w, http.StatusUnauthorized, "API key required")
}

// Test API key authentication middleware with invalid format
func (suite *AuthMiddlewareTestSuite) TestAPIKeyAuthMiddleware_InvalidFormat() {
	suite.router.GET("/api", suite.authMiddleware.APIKeyAuthMiddleware(), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"success": true})
	})

	req := httptest.NewRequest("GET", "/api", nil)
	req.Header.Set("X-API-Key", "invalid_key_format")
	w := httptest.NewRecorder()

	suite.router.ServeHTTP(w, req)

	suite.assertErrorResponse(w, http.StatusUnauthorized, "Invalid API key format")
}

// Test API key authentication middleware with expired key
func (suite *AuthMiddlewareTestSuite) TestAPIKeyAuthMiddleware_ExpiredKey() {
	// Create expired API key
	expiredKey := suite.createExpiredAPIKey(suite.testUser, suite.testOrg)

	suite.router.GET("/api", suite.authMiddleware.APIKeyAuthMiddleware(), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"success": true})
	})

	req := httptest.NewRequest("GET", "/api", nil)
	req.Header.Set("X-API-Key", expiredKey.KeyHash) // Using full key
	w := httptest.NewRecorder()

	suite.router.ServeHTTP(w, req)

	suite.assertErrorResponse(w, http.StatusUnauthorized, "not valid or has expired")
}

// Test flexible authentication middleware with JWT
func (suite *AuthMiddlewareTestSuite) TestFlexibleAuthMiddleware_JWT() {
	suite.router.GET("/flexible", suite.authMiddleware.FlexibleAuthMiddleware(), func(c *gin.Context) {
		user, exists := GetUserFromContext(c)
		suite.True(exists)
		c.JSON(http.StatusOK, gin.H{"user_id": user.ID})
	})

	token, err := suite.authService.GenerateToken(
		suite.testUser.ID.String(),
		suite.testUser.Username,
		suite.testUser.Email,
		string(suite.testUser.Role),
	)
	suite.NoError(err)

	req := httptest.NewRequest("GET", "/flexible", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()

	suite.router.ServeHTTP(w, req)

	suite.Equal(http.StatusOK, w.Code)
}

// Test flexible authentication middleware with API key
func (suite *AuthMiddlewareTestSuite) TestFlexibleAuthMiddleware_APIKey() {
	suite.router.GET("/flexible", suite.authMiddleware.FlexibleAuthMiddleware(), func(c *gin.Context) {
		user, exists := GetUserFromContext(c)
		suite.True(exists)
		c.JSON(http.StatusOK, gin.H{"user_id": user.ID})
	})

	req := httptest.NewRequest("GET", "/flexible", nil)
	req.Header.Set("X-API-Key", suite.testAPIKey.KeyHash)
	w := httptest.NewRecorder()

	suite.router.ServeHTTP(w, req)

	suite.Equal(http.StatusOK, w.Code)
}

// Test flexible authentication middleware with no auth
func (suite *AuthMiddlewareTestSuite) TestFlexibleAuthMiddleware_NoAuth() {
	suite.router.GET("/flexible", suite.authMiddleware.FlexibleAuthMiddleware(), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"success": true})
	})

	req := httptest.NewRequest("GET", "/flexible", nil)
	w := httptest.NewRecorder()

	suite.router.ServeHTTP(w, req)

	suite.assertErrorResponse(w, http.StatusUnauthorized, "Authentication required")
}

// Test role requirement middleware
func (suite *AuthMiddlewareTestSuite) TestRequireRole_ValidRole() {
	suite.router.GET("/admin", 
		suite.authMiddleware.JWTAuthMiddleware(),
		suite.authMiddleware.RequireRole(models.UserRoleAdmin),
		func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"success": true})
		})

	token, err := suite.authService.GenerateToken(
		suite.testAdmin.ID.String(),
		suite.testAdmin.Username,
		suite.testAdmin.Email,
		string(suite.testAdmin.Role),
	)
	suite.NoError(err)

	req := httptest.NewRequest("GET", "/admin", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()

	suite.router.ServeHTTP(w, req)

	suite.Equal(http.StatusOK, w.Code)
}

// Test role requirement middleware with insufficient role
func (suite *AuthMiddlewareTestSuite) TestRequireRole_InsufficientRole() {
	suite.router.GET("/admin", 
		suite.authMiddleware.JWTAuthMiddleware(),
		suite.authMiddleware.RequireRole(models.UserRoleAdmin),
		func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"success": true})
		})

	token, err := suite.authService.GenerateToken(
		suite.testUser.ID.String(),
		suite.testUser.Username,
		suite.testUser.Email,
		string(suite.testUser.Role),
	)
	suite.NoError(err)

	req := httptest.NewRequest("GET", "/admin", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()

	suite.router.ServeHTTP(w, req)

	suite.assertErrorResponse(w, http.StatusForbidden, "Insufficient permissions")
}

// Test organization access requirement
func (suite *AuthMiddlewareTestSuite) TestRequireOrganizationAccess_ValidAccess() {
	suite.router.GET("/org/:org_id", 
		suite.authMiddleware.JWTAuthMiddleware(),
		suite.authMiddleware.RequireOrganizationAccess(),
		func(c *gin.Context) {
			orgID, exists := GetOrganizationIDFromContext(c)
			suite.True(exists)
			c.JSON(http.StatusOK, gin.H{"org_id": orgID})
		})

	token, err := suite.authService.GenerateToken(
		suite.testUser.ID.String(),
		suite.testUser.Username,
		suite.testUser.Email,
		string(suite.testUser.Role),
	)
	suite.NoError(err)

	req := httptest.NewRequest("GET", "/org/"+suite.testOrg.ID.String(), nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()

	suite.router.ServeHTTP(w, req)

	suite.Equal(http.StatusOK, w.Code)
}

// Test organization access requirement with invalid org ID
func (suite *AuthMiddlewareTestSuite) TestRequireOrganizationAccess_InvalidOrgID() {
	suite.router.GET("/org/:org_id", 
		suite.authMiddleware.JWTAuthMiddleware(),
		suite.authMiddleware.RequireOrganizationAccess(),
		func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"success": true})
		})

	token, err := suite.authService.GenerateToken(
		suite.testUser.ID.String(),
		suite.testUser.Username,
		suite.testUser.Email,
		string(suite.testUser.Role),
	)
	suite.NoError(err)

	req := httptest.NewRequest("GET", "/org/invalid-uuid", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()

	suite.router.ServeHTTP(w, req)

	suite.assertErrorResponse(w, http.StatusBadRequest, "Organization ID required")
}

// Test organization access requirement with no access
func (suite *AuthMiddlewareTestSuite) TestRequireOrganizationAccess_NoAccess() {
	// Create another organization that testUser doesn't have access to
	otherUser := suite.createTestUser("other@test.com", models.UserRoleUser)
	otherOrg := suite.createTestOrganization(otherUser, "Other Org")

	suite.router.GET("/org/:org_id", 
		suite.authMiddleware.JWTAuthMiddleware(),
		suite.authMiddleware.RequireOrganizationAccess(),
		func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"success": true})
		})

	token, err := suite.authService.GenerateToken(
		suite.testUser.ID.String(),
		suite.testUser.Username,
		suite.testUser.Email,
		string(suite.testUser.Role),
	)
	suite.NoError(err)

	req := httptest.NewRequest("GET", "/org/"+otherOrg.ID.String(), nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()

	suite.router.ServeHTTP(w, req)

	suite.assertErrorResponse(w, http.StatusForbidden, "Access denied to organization")
}

// Test admin bypass for organization access
func (suite *AuthMiddlewareTestSuite) TestRequireOrganizationAccess_AdminBypass() {
	// Create organization that admin doesn't own
	otherUser := suite.createTestUser("other@test.com", models.UserRoleUser)
	otherOrg := suite.createTestOrganization(otherUser, "Other Org")

	suite.router.GET("/org/:org_id", 
		suite.authMiddleware.JWTAuthMiddleware(),
		suite.authMiddleware.RequireOrganizationAccess(),
		func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"success": true})
		})

	token, err := suite.authService.GenerateToken(
		suite.testAdmin.ID.String(),
		suite.testAdmin.Username,
		suite.testAdmin.Email,
		string(suite.testAdmin.Role),
	)
	suite.NoError(err)

	req := httptest.NewRequest("GET", "/org/"+otherOrg.ID.String(), nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()

	suite.router.ServeHTTP(w, req)

	suite.Equal(http.StatusOK, w.Code) // Admin should have access
}

// Test context helper functions
func (suite *AuthMiddlewareTestSuite) TestContextHelpers() {
	suite.router.GET("/test", suite.authMiddleware.JWTAuthMiddleware(), func(c *gin.Context) {
		// Test GetUserFromContext
		user, exists := GetUserFromContext(c)
		suite.True(exists)
		suite.Equal(suite.testUser.ID, user.ID)

		c.JSON(http.StatusOK, gin.H{"success": true})
	})

	token, err := suite.authService.GenerateToken(
		suite.testUser.ID.String(),
		suite.testUser.Username,
		suite.testUser.Email,
		string(suite.testUser.Role),
	)
	suite.NoError(err)

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()

	suite.router.ServeHTTP(w, req)

	suite.Equal(http.StatusOK, w.Code)
}

// Test API key usage tracking
func (suite *AuthMiddlewareTestSuite) TestAPIKeyUsageTracking() {
	initialUsageCount := suite.testAPIKey.UsageCount
	initialLastUsed := suite.testAPIKey.LastUsedAt

	suite.router.GET("/api", suite.authMiddleware.APIKeyAuthMiddleware(), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"success": true})
	})

	req := httptest.NewRequest("GET", "/api", nil)
	req.Header.Set("X-API-Key", suite.testAPIKey.KeyHash)
	w := httptest.NewRecorder()

	suite.router.ServeHTTP(w, req)

	suite.Equal(http.StatusOK, w.Code)

	// Check that usage was tracked
	var updatedKey models.APIKey
	suite.db.First(&updatedKey, suite.testAPIKey.ID)
	
	suite.Greater(updatedKey.UsageCount, initialUsageCount)
	if initialLastUsed != nil {
		suite.True(updatedKey.LastUsedAt.After(*initialLastUsed))
	} else {
		suite.NotNil(updatedKey.LastUsedAt)
	}
}

// Test concurrent authentication requests
func (suite *AuthMiddlewareTestSuite) TestConcurrentAuthentication() {
	suite.router.GET("/concurrent", suite.authMiddleware.JWTAuthMiddleware(), func(c *gin.Context) {
		time.Sleep(10 * time.Millisecond) // Simulate some processing
		c.JSON(http.StatusOK, gin.H{"success": true})
	})

	token, err := suite.authService.GenerateToken(
		suite.testUser.ID.String(),
		suite.testUser.Username,
		suite.testUser.Email,
		string(suite.testUser.Role),
	)
	suite.NoError(err)

	numRequests := 10
	results := make(chan int, numRequests)

	// Make concurrent requests
	for i := 0; i < numRequests; i++ {
		go func() {
			req := httptest.NewRequest("GET", "/concurrent", nil)
			req.Header.Set("Authorization", "Bearer "+token)
			w := httptest.NewRecorder()

			suite.router.ServeHTTP(w, req)
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