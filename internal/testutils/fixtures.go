package testutils

import (
	"time"

	"adc-sso-service/internal/models"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// TestUser creates a test user
func CreateTestUser(db *gorm.DB, email string, role models.UserRole) *models.User {
	user := &models.User{
		ID:            uuid.New(),
		Username:      "testuser_" + uuid.New().String()[:8],
		Email:         email,
		Password:      "hashed_password",
		FullName:      "Test User",
		Role:          role,
		Status:        models.UserStatusActive,
		EmailVerified: true,
		Timezone:      "UTC",
		Locale:        "en",
	}
	
	db.Create(user)
	return user
}

// CreateTestAdmin creates a test admin user
func CreateTestAdmin(db *gorm.DB) *models.User {
	return CreateTestUser(db, "admin@test.com", models.UserRoleAdmin)
}

// CreateTestRegularUser creates a test regular user
func CreateTestRegularUser(db *gorm.DB) *models.User {
	return CreateTestUser(db, "user@test.com", models.UserRoleUser)
}

// CreateTestOrganization creates a test organization
func CreateTestOrganization(db *gorm.DB, owner *models.User, name string) *models.Organization {
	org := &models.Organization{
		ID:          uuid.New(),
		Name:        name,
		Slug:        name + "-" + uuid.New().String()[:8],
		Description: "Test organization",
		OwnerID:     owner.ID,
		Status:      models.OrganizationStatusActive,
		Settings:    make(map[string]interface{}),
		Metadata:    make(map[string]interface{}),
	}
	
	db.Create(org)
	
	// Create user-organization relationship
	userOrg := &models.UserOrganization{
		ID:             uuid.New(),
		UserID:         owner.ID,
		OrganizationID: org.ID,
		Role:           models.UserRoleOwner,
		Status:         models.UserStatusActive,
		JoinedAt:       time.Now(),
	}
	
	db.Create(userOrg)
	return org
}

// AddUserToOrganization adds a user to an organization with specified role
func AddUserToOrganization(db *gorm.DB, user *models.User, org *models.Organization, role models.UserRole) {
	userOrg := &models.UserOrganization{
		ID:             uuid.New(),
		UserID:         user.ID,
		OrganizationID: org.ID,
		Role:           role,
		Status:         models.UserStatusActive,
		JoinedAt:       time.Now(),
	}
	
	db.Create(userOrg)
}

// CreateTestAPIKey creates a test API key
func CreateTestAPIKey(db *gorm.DB, user *models.User, org *models.Organization, name string) *models.APIKey {
	fullKey, keyHash, keyPrefix, _ := models.GenerateAPIKey()
	
	apiKey := &models.APIKey{
		ID:             uuid.New(),
		Name:           name,
		KeyHash:        keyHash,
		KeyPrefix:      keyPrefix,
		UserID:         user.ID,
		OrganizationID: org.ID,
		Permissions:    []string{"read", "write"},
		Scopes:         []string{"api"},
		IsActive:       true,
		UsageCount:     0,
	}
	
	db.Create(apiKey)
	
	// Return the key with the full key for testing
	apiKey.KeyHash = fullKey // Store full key for test validation
	return apiKey
}

// CreateExpiredAPIKey creates an expired API key for testing
func CreateExpiredAPIKey(db *gorm.DB, user *models.User, org *models.Organization) *models.APIKey {
	fullKey, keyHash, keyPrefix, _ := models.GenerateAPIKey()
	yesterday := time.Now().Add(-24 * time.Hour)
	
	apiKey := &models.APIKey{
		ID:             uuid.New(),
		Name:           "Expired Key",
		KeyHash:        keyHash,
		KeyPrefix:      keyPrefix,
		UserID:         user.ID,
		OrganizationID: org.ID,
		Permissions:    []string{"read"},
		Scopes:         []string{"api"},
		IsActive:       true,
		ExpiresAt:      &yesterday,
		UsageCount:     0,
	}
	
	db.Create(apiKey)
	apiKey.KeyHash = fullKey // Store full key for test validation
	return apiKey
}

// CreateSSOUserMapping creates a test SSO user mapping
func CreateSSOUserMapping(db *gorm.DB, user *models.User, provider string, providerID string) *models.SSOUserMapping {
	mapping := &models.SSOUserMapping{
		ID:         uuid.New(),
		UserID:     user.ID,
		Provider:   provider,
		ProviderID: providerID,
		Email:      user.Email,
		ProviderData: map[string]interface{}{
			"name":           user.FullName,
			"email_verified": true,
		},
	}
	
	db.Create(mapping)
	return mapping
}

// CreateAuditLog creates a test audit log entry
func CreateAuditLog(db *gorm.DB, user *models.User, org *models.Organization, eventType string) *models.AuditLog {
	auditLog := &models.AuditLog{
		ID:             uuid.New(),
		UserID:         &user.ID,
		OrganizationID: &org.ID,
		EventType:      eventType,
		EventCategory:  "test",
		IPAddress:      "127.0.0.1",
		UserAgent:      "test-agent",
		Success:        true,
		Details:        map[string]interface{}{"test": true},
	}
	
	db.Create(auditLog)
	return auditLog
}

// LoadUserWithOrganizations loads a user with their organization relationships
func LoadUserWithOrganizations(db *gorm.DB, userID uuid.UUID) *models.User {
	var user models.User
	db.Preload("UserOrganizations.Organization").First(&user, userID)
	return &user
}