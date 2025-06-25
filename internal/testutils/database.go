package testutils

import (
	"log"
	"os"
	"strings"
	"testing"

	"adc-sso-service/internal/models"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// SetupTestDB creates a PostgreSQL database connection for testing
func SetupTestDB(t *testing.T) *gorm.DB {
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
				LogLevel: logger.Silent, // Reduce noise in tests
			},
		),
	})
	if err != nil {
		t.Fatalf("Failed to connect to test database: %v", err)
	}

	// Auto-migrate all models
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

// CleanupTestDB cleans up the test database
func CleanupTestDB(t *testing.T, db *gorm.DB) {
	if db != nil {
		// Clean up test data by deleting records created during test
		TruncateAllTables(db)
		
		// Note: Don't close the connection as it may be reused
		// The connection pool will handle cleanup
	}
}

// TruncateAllTables removes all test data from database tables
func TruncateAllTables(db *gorm.DB) {
	// Delete in order to respect foreign key constraints
	db.Exec("DELETE FROM audit_logs WHERE created_at > NOW() - INTERVAL '1 hour'")
	db.Exec("DELETE FROM sso_user_mappings WHERE created_at > NOW() - INTERVAL '1 hour'")
	db.Exec("DELETE FROM api_keys WHERE created_at > NOW() - INTERVAL '1 hour'")
	db.Exec("DELETE FROM user_organizations WHERE created_at > NOW() - INTERVAL '1 hour'")
	db.Exec("DELETE FROM organizations WHERE created_at > NOW() - INTERVAL '1 hour'")
	db.Exec("DELETE FROM users WHERE created_at > NOW() - INTERVAL '1 hour'")
}