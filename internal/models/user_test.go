package models

import (
	"log"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// setupTestDB creates a PostgreSQL database connection for testing
func setupTestDB(t *testing.T) *gorm.DB {
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
		t.Fatalf("Failed to connect to test database: %v", err)
	}

	err = db.AutoMigrate(
		&User{},
		&Organization{},
		&UserOrganization{},
		&APIKey{},
		&SSOUserMapping{},
		&AuditLog{},
	)
	if err != nil {
		// Check if the error is about existing relations, which is fine for tests
		if !isTableExistsError(err) {
			t.Fatalf("Failed to migrate test database: %v", err)
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

// cleanupTestDB cleans up the test database
func cleanupTestDB(t *testing.T, db *gorm.DB) {
	if db != nil {
		// Clean up test data by deleting recent records in dependency order
		db.Exec("DELETE FROM audit_logs WHERE created_at > NOW() - INTERVAL '1 hour'")
		db.Exec("DELETE FROM sso_user_mappings WHERE created_at > NOW() - INTERVAL '1 hour'")
		db.Exec("DELETE FROM api_keys WHERE created_at > NOW() - INTERVAL '1 hour'")
		db.Exec("DELETE FROM user_organizations WHERE created_at > NOW() - INTERVAL '1 hour'")
		db.Exec("DELETE FROM organizations WHERE created_at > NOW() - INTERVAL '1 hour'")
		db.Exec("DELETE FROM users WHERE created_at > NOW() - INTERVAL '1 hour'")
		
		// Force close all prepared statements to avoid conflicts
		if sqlDB, err := db.DB(); err == nil {
			sqlDB.SetMaxIdleConns(0)
			sqlDB.SetMaxOpenConns(1)
		}
	}
}

// UserModelTestSuite defines the test suite for user model
type UserModelTestSuite struct {
	suite.Suite
	db *gorm.DB
}

// SetupTest runs before each test
func (suite *UserModelTestSuite) SetupTest() {
	suite.db = setupTestDB(suite.T())
}

// TearDownTest runs after each test
func (suite *UserModelTestSuite) TearDownTest() {
	cleanupTestDB(suite.T(), suite.db)
}

// TestUserModelTestSuite runs the test suite
func TestUserModelTestSuite(t *testing.T) {
	suite.Run(t, new(UserModelTestSuite))
}

// Test user creation with BeforeCreate hook
func (suite *UserModelTestSuite) TestUserBeforeCreate() {
	user := &User{
		Username:    "testuser",
		Email:       "test@example.com",
		Password:    "hashed_password",
		FullName:    "Test User",
		Role:        UserRoleUser,
		Status:      UserStatusActive,
	}

	err := suite.db.Create(user).Error
	suite.NoError(err)
	suite.NotEqual(uuid.Nil, user.ID)
	suite.NotZero(user.CreatedAt)
}

// Test user creation with existing ID
func (suite *UserModelTestSuite) TestUserBeforeCreateWithExistingID() {
	existingID := uuid.New()
	user := &User{
		ID:       existingID,
		Username: "testuser",
		Email:    "test@example.com",
		Password: "hashed_password",
	}

	err := suite.db.Create(user).Error
	suite.NoError(err)
	suite.Equal(existingID, user.ID) // Should preserve existing ID
}

// Test user helper methods
func (suite *UserModelTestSuite) TestUserHelperMethods() {
	user := &User{
		Role:   UserRoleUser,
		Status: UserStatusActive,
	}

	// Test IsActive
	suite.True(user.IsActive())

	user.Status = UserStatusInactive
	suite.False(user.IsActive())

	// Test IsAdmin
	user.Role = UserRoleUser
	suite.False(user.IsAdmin())

	user.Role = UserRoleAdmin
	suite.True(user.IsAdmin())
}

// Test user organization access methods
func (suite *UserModelTestSuite) TestUserOrganizationAccess() {
	// Create user
	user := &User{
		Username: "testuser",
		Email:    "test@example.com",
		Password: "password",
		Role:     UserRoleUser,
		Status:   UserStatusActive,
	}
	suite.db.Create(user)

	// Create organization
	org := &Organization{
		Name:    "Test Org",
		OwnerID: user.ID,
		Status:  OrganizationStatusActive,
	}
	suite.db.Create(org)

	// Create user-organization relationship
	userOrg := &UserOrganization{
		UserID:         user.ID,
		OrganizationID: org.ID,
		Role:           UserRoleOwner,
		Status:         UserStatusActive,
	}
	suite.db.Create(userOrg)

	// Load user with organizations
	suite.db.Preload("UserOrganizations").First(user, user.ID)

	// Test CanAccessOrganization
	suite.True(user.CanAccessOrganization(org.ID))

	// Test with non-accessible organization
	otherOrg := &Organization{ID: uuid.New()}
	suite.False(user.CanAccessOrganization(otherOrg.ID))

	// Test GetOrganizationRole
	role, exists := user.GetOrganizationRole(org.ID)
	suite.True(exists)
	suite.Equal(UserRoleOwner, role)

	// Test with non-accessible organization
	_, exists = user.GetOrganizationRole(otherOrg.ID)
	suite.False(exists)
}

// Test default values
func (suite *UserModelTestSuite) TestUserDefaults() {
	user := &User{
		Username: "testuser",
		Email:    "test@example.com",
		Password: "password",
	}

	err := suite.db.Create(user).Error
	suite.NoError(err)

	// Reload to get defaults
	err = suite.db.First(user, user.ID).Error
	suite.NoError(err)

	// Check defaults
	suite.Equal(UserRoleUser, user.Role)
	suite.Equal(UserStatusActive, user.Status)
	suite.Equal("UTC", user.Timezone)
	suite.Equal("en", user.Locale)
	suite.False(user.EmailVerified)
}

// Test unique constraints
func (suite *UserModelTestSuite) TestUserValidation() {
	// Test unique constraints
	user1 := &User{
		Username: "testuser",
		Email:    "test@example.com",
		Password: "password",
		Role:     UserRoleUser,
		Status:   UserStatusActive,
	}

	err := suite.db.Create(user1).Error
	suite.NoError(err)

	// Try to create another user with same email
	user2 := &User{
		Username: "testuser2",
		Email:    "test@example.com", // Same email
		Password: "password",
		Role:     UserRoleUser,
		Status:   UserStatusActive,
	}

	err = suite.db.Create(user2).Error
	suite.Error(err) // Should fail due to unique constraint
}

// OrganizationModelTestSuite for organization-specific tests
type OrganizationModelTestSuite struct {
	suite.Suite
	db *gorm.DB
}

func (suite *OrganizationModelTestSuite) SetupTest() {
	suite.db = setupTestDB(suite.T())
}

func (suite *OrganizationModelTestSuite) TearDownTest() {
	cleanupTestDB(suite.T(), suite.db)
}

func TestOrganizationModelTestSuite(t *testing.T) {
	suite.Run(t, new(OrganizationModelTestSuite))
}

// Test organization model
func (suite *OrganizationModelTestSuite) TestOrganizationBeforeCreate() {
	owner := &User{
		Username: "owner",
		Email:    "owner@test.com",
		Password: "password",
	}
	suite.db.Create(owner)
	
	org := &Organization{
		Name:    "Test Organization",
		OwnerID: owner.ID,
	}

	err := suite.db.Create(org).Error
	suite.NoError(err)
	suite.NotEqual(uuid.Nil, org.ID)
	suite.Equal("test-organization", org.Slug) // Auto-generated slug
}

// Test organization with custom slug
func (suite *OrganizationModelTestSuite) TestOrganizationCustomSlug() {
	owner := &User{
		Username: "owner",
		Email:    "owner@test.com",
		Password: "password",
	}
	suite.db.Create(owner)
	
	org := &Organization{
		Name:    "Test Organization",
		Slug:    "custom-slug",
		OwnerID: owner.ID,
	}

	err := suite.db.Create(org).Error
	suite.NoError(err)
	suite.Equal("custom-slug", org.Slug) // Should preserve custom slug
}

// Test organization helper methods
func (suite *OrganizationModelTestSuite) TestOrganizationHelperMethods() {
	org := &Organization{
		Status: OrganizationStatusActive,
	}

	// Test IsActive
	suite.True(org.IsActive())

	org.Status = OrganizationStatusInactive
	suite.False(org.IsActive())
}

// Test JSON field handling
func (suite *OrganizationModelTestSuite) TestJSONFields() {
	owner := &User{
		Username: "owner",
		Email:    "owner@test.com",
		Password: "password",
	}
	suite.db.Create(owner)
	
	settings := map[string]interface{}{
		"theme":    "dark",
		"timezone": "UTC",
		"features": []string{"feature1", "feature2"},
	}
	
	metadata := map[string]interface{}{
		"source":     "api",
		"created_by": "admin",
		"version":    1.0,
	}

	org := &Organization{
		Name:     "JSON Test Org",
		OwnerID:  owner.ID,
		Settings: settings,
		Metadata: metadata,
	}

	err := suite.db.Create(org).Error
	suite.NoError(err)

	// Reload and verify JSON fields
	var loadedOrg Organization
	err = suite.db.First(&loadedOrg, org.ID).Error
	suite.NoError(err)

	suite.Equal("dark", loadedOrg.Settings["theme"])
	suite.Equal("api", loadedOrg.Metadata["source"])
	suite.Equal(1.0, loadedOrg.Metadata["version"])
}

// APIKeyModelTestSuite for API key-specific tests
type APIKeyModelTestSuite struct {
	suite.Suite
	db *gorm.DB
}

func (suite *APIKeyModelTestSuite) SetupTest() {
	suite.db = setupTestDB(suite.T())
}

func (suite *APIKeyModelTestSuite) TearDownTest() {
	cleanupTestDB(suite.T(), suite.db)
}

func TestAPIKeyModelTestSuite(t *testing.T) {
	suite.Run(t, new(APIKeyModelTestSuite))
}

// Test API key generation
func (suite *APIKeyModelTestSuite) TestGenerateAPIKey() {
	fullKey, keyHash, keyPrefix, err := GenerateAPIKey()

	suite.NoError(err)
	suite.NotEmpty(fullKey)
	suite.NotEmpty(keyHash)
	suite.NotEmpty(keyPrefix)

	// Verify key format
	suite.True(assert.Greater(suite.T(), len(fullKey), 40), "API key should be reasonably long")
	suite.True(assert.Contains(suite.T(), fullKey, "adc_"), "API key should have adc_ prefix")
	suite.True(assert.Contains(suite.T(), keyPrefix, "..."), "Key prefix should end with ...")

	// Verify hash is different from key
	suite.NotEqual(fullKey, keyHash)

	// Verify key uniqueness
	fullKey2, keyHash2, keyPrefix2, err2 := GenerateAPIKey()
	suite.NoError(err2)
	suite.NotEqual(fullKey, fullKey2)
	suite.NotEqual(keyHash, keyHash2)
	suite.NotEqual(keyPrefix, keyPrefix2)
}

// Test API key hashing
func (suite *APIKeyModelTestSuite) TestHashAPIKey() {
	testKey := "adc_test_key_12345"
	hash1 := HashAPIKey(testKey)
	hash2 := HashAPIKey(testKey)

	// Hash should be consistent
	suite.Equal(hash1, hash2)

	// Hash should be different from original key
	suite.NotEqual(testKey, hash1)

	// Different keys should produce different hashes
	differentKey := "adc_different_key_67890"
	differentHash := HashAPIKey(differentKey)
	suite.NotEqual(hash1, differentHash)
}

// Test API key helper methods
func (suite *APIKeyModelTestSuite) TestAPIKeyHelperMethods() {
	// Create user and organization
	user := &User{
		Username: "testuser",
		Email:    "test@example.com",
		Password: "password",
	}
	suite.db.Create(user)

	org := &Organization{
		Name:    "Test Org",
		OwnerID: user.ID,
	}
	suite.db.Create(org)

	// Create API key
	_, keyHash, keyPrefix, _ := GenerateAPIKey()
	apiKey := &APIKey{
		Name:           "Test Key",
		KeyHash:        keyHash,
		KeyPrefix:      keyPrefix,
		UserID:         user.ID,
		OrganizationID: org.ID,
		Permissions:    []string{"read", "write"},
		Scopes:         []string{"api"},
		IsActive:       true,
	}
	suite.db.Create(apiKey)

	// Test IsValid
	suite.True(apiKey.IsValid())

	// Test with inactive key
	apiKey.IsActive = false
	suite.False(apiKey.IsValid())

	// Test with expired key
	apiKey.IsActive = true
	yesterday := time.Now().Add(-24 * time.Hour)
	apiKey.ExpiresAt = &yesterday
	suite.False(apiKey.IsValid())

	// Test HasPermission
	apiKey.ExpiresAt = nil // Remove expiration
	suite.True(apiKey.HasPermission("read"))
	suite.True(apiKey.HasPermission("write"))
	suite.False(apiKey.HasPermission("admin"))

	// Test wildcard permission
	apiKey.Permissions = []string{"*"}
	suite.True(apiKey.HasPermission("anything"))

	// Test HasScope
	apiKey.Scopes = []string{"api", "webhooks"}
	suite.True(apiKey.HasScope("api"))
	suite.True(apiKey.HasScope("webhooks"))
	suite.False(apiKey.HasScope("admin"))

	// Test wildcard scope
	apiKey.Scopes = []string{"*"}
	suite.True(apiKey.HasScope("anything"))
}

// Test API key usage tracking
func (suite *APIKeyModelTestSuite) TestAPIKeyUsageTracking() {
	// Create user and organization
	user := &User{
		Username: "testuser",
		Email:    "test@example.com",
		Password: "password",
	}
	suite.db.Create(user)

	org := &Organization{
		Name:    "Test Org",
		OwnerID: user.ID,
	}
	suite.db.Create(org)

	// Create API key
	_, keyHash, keyPrefix, _ := GenerateAPIKey()
	apiKey := &APIKey{
		Name:           "Test Key",
		KeyHash:        keyHash,
		KeyPrefix:      keyPrefix,
		UserID:         user.ID,
		OrganizationID: org.ID,
		IsActive:       true,
		UsageCount:     0,
	}
	suite.db.Create(apiKey)

	initialCount := apiKey.UsageCount
	initialLastUsed := apiKey.LastUsedAt

	// Update usage
	apiKey.UpdateUsage()

	suite.Equal(initialCount+1, apiKey.UsageCount)
	suite.NotNil(apiKey.LastUsedAt)
	
	if initialLastUsed != nil {
		suite.True(apiKey.LastUsedAt.After(*initialLastUsed))
	}
}