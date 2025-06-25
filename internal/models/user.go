package models

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type UserRole string
type UserStatus string
type OrganizationStatus string

const (
	UserRoleUser    UserRole = "user"
	UserRoleAdmin   UserRole = "admin"
	UserRoleOwner   UserRole = "owner"
	UserRoleMember  UserRole = "member"

	UserStatusActive    UserStatus = "active"
	UserStatusInactive  UserStatus = "inactive"
	UserStatusSuspended UserStatus = "suspended"
	UserStatusPending   UserStatus = "pending"

	OrganizationStatusActive    OrganizationStatus = "active"
	OrganizationStatusInactive  OrganizationStatus = "inactive"
	OrganizationStatusSuspended OrganizationStatus = "suspended"
)

// User represents a user in the system
type User struct {
	ID              uuid.UUID              `json:"id" gorm:"type:uuid;primary_key;default:gen_random_uuid()"`
	Username        string                 `json:"username" gorm:"uniqueIndex;not null"`
	Email           string                 `json:"email" gorm:"uniqueIndex;not null"`
	Password        string                 `json:"-" gorm:"not null"`
	FullName        string                 `json:"full_name"`
	Role            UserRole               `json:"role" gorm:"default:'user'"`
	Status          UserStatus             `json:"status" gorm:"default:'active'"`
	EmailVerified   bool                   `json:"email_verified" gorm:"default:false"`
	LastLogin       *time.Time             `json:"last_login"`
	ProfileImageURL string                 `json:"profile_image_url"`
	Timezone        string                 `json:"timezone" gorm:"default:'UTC'"`
	Locale          string                 `json:"locale" gorm:"default:'en'"`
	
	// SSO Integration
	SSOProviders    []SSOUserMapping       `json:"sso_providers,omitempty" gorm:"foreignKey:UserID"`
	
	// Organization relationships
	UserOrganizations []UserOrganization   `json:"user_organizations,omitempty" gorm:"foreignKey:UserID"`
	OwnedOrganizations []Organization      `json:"owned_organizations,omitempty" gorm:"foreignKey:OwnerID"`
	
	// API Keys
	APIKeys         []APIKey               `json:"api_keys,omitempty" gorm:"foreignKey:UserID"`
	
	// Audit fields
	CreatedAt       time.Time              `json:"created_at"`
	UpdatedAt       time.Time              `json:"updated_at"`
	DeletedAt       gorm.DeletedAt         `json:"-" gorm:"index"`
}

// Organization represents a tenant/organization in the system
type Organization struct {
	ID          uuid.UUID           `json:"id" gorm:"type:uuid;primary_key;default:gen_random_uuid()"`
	Name        string              `json:"name" gorm:"not null"`
	Slug        string              `json:"slug" gorm:"uniqueIndex;not null"`
	Description string              `json:"description"`
	Website     string              `json:"website"`
	OwnerID     uuid.UUID           `json:"owner_id" gorm:"type:uuid;not null"`
	Owner       User                `json:"owner,omitempty" gorm:"foreignKey:OwnerID"`
	Status      OrganizationStatus  `json:"status" gorm:"default:'active'"`
	
	// Settings
	Settings    map[string]interface{} `json:"settings" gorm:"type:jsonb;default:'{}'"`
	Metadata    map[string]interface{} `json:"metadata" gorm:"type:jsonb;default:'{}'"`
	
	// Relationships
	Members     []UserOrganization     `json:"members,omitempty" gorm:"foreignKey:OrganizationID"`
	APIKeys     []APIKey               `json:"api_keys,omitempty" gorm:"foreignKey:OrganizationID"`
	
	// Audit fields
	CreatedAt   time.Time              `json:"created_at"`
	UpdatedAt   time.Time              `json:"updated_at"`
	DeletedAt   gorm.DeletedAt         `json:"-" gorm:"index"`
}

// UserOrganization represents the many-to-many relationship between users and organizations
type UserOrganization struct {
	ID             uuid.UUID    `json:"id" gorm:"type:uuid;primary_key;default:gen_random_uuid()"`
	UserID         uuid.UUID    `json:"user_id" gorm:"type:uuid;not null;index"`
	OrganizationID uuid.UUID    `json:"organization_id" gorm:"type:uuid;not null;index"`
	Role           UserRole     `json:"role" gorm:"default:'member'"`
	Status         UserStatus   `json:"status" gorm:"default:'active'"`
	JoinedAt       time.Time    `json:"joined_at" gorm:"default:CURRENT_TIMESTAMP"`
	
	// Relationships
	User           User         `json:"user,omitempty" gorm:"foreignKey:UserID"`
	Organization   Organization `json:"organization,omitempty" gorm:"foreignKey:OrganizationID"`
	
	// Audit fields
	CreatedAt      time.Time    `json:"created_at"`
	UpdatedAt      time.Time    `json:"updated_at"`
}

// APIKey represents API keys for programmatic access
type APIKey struct {
	ID             uuid.UUID    `json:"id" gorm:"type:uuid;primary_key;default:gen_random_uuid()"`
	Name           string       `json:"name" gorm:"not null"`
	KeyHash        string       `json:"-" gorm:"not null;index"` // SHA256 hash of the key
	KeyPrefix      string       `json:"key_prefix" gorm:"not null;index"` // First 8 characters for identification
	UserID         uuid.UUID    `json:"user_id" gorm:"type:uuid;not null;index"`
	OrganizationID uuid.UUID    `json:"organization_id" gorm:"type:uuid;not null;index"`
	
	// Permissions and access control
	Permissions    []string     `json:"permissions" gorm:"type:jsonb;default:'[]'"`
	Scopes         []string     `json:"scopes" gorm:"type:jsonb;default:'[]'"`
	IsActive       bool         `json:"is_active" gorm:"default:true"`
	
	// Usage tracking
	LastUsedAt     *time.Time   `json:"last_used_at"`
	UsageCount     int64        `json:"usage_count" gorm:"default:0"`
	
	// Expiration
	ExpiresAt      *time.Time   `json:"expires_at"`
	
	// Relationships
	User           User         `json:"user,omitempty" gorm:"foreignKey:UserID"`
	Organization   Organization `json:"organization,omitempty" gorm:"foreignKey:OrganizationID"`
	
	// Audit fields
	CreatedAt      time.Time    `json:"created_at"`
	UpdatedAt      time.Time    `json:"updated_at"`
	DeletedAt      gorm.DeletedAt `json:"-" gorm:"index"`
}

// SSOUserMapping represents the mapping between SSO providers and local users
type SSOUserMapping struct {
	ID           uuid.UUID `json:"id" gorm:"type:uuid;primary_key;default:gen_random_uuid()"`
	UserID       uuid.UUID `json:"user_id" gorm:"type:uuid;not null;index"`
	Provider     string    `json:"provider" gorm:"not null;index"` // keycloak, google, github, etc.
	ProviderID   string    `json:"provider_id" gorm:"not null;index"` // User ID from the provider
	Email        string    `json:"email" gorm:"not null"`
	ProviderData map[string]interface{} `json:"provider_data" gorm:"type:jsonb;default:'{}'"`
	
	// Relationships
	User         User      `json:"user,omitempty" gorm:"foreignKey:UserID"`
	
	// Audit fields
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

// AuditLog represents authentication and authorization audit events
type AuditLog struct {
	ID             uuid.UUID              `json:"id" gorm:"type:uuid;primary_key;default:gen_random_uuid()"`
	UserID         *uuid.UUID             `json:"user_id" gorm:"type:uuid;index"`
	OrganizationID *uuid.UUID             `json:"organization_id" gorm:"type:uuid;index"`
	EventType      string                 `json:"event_type" gorm:"not null;index"` // login, logout, api_key_used, etc.
	EventCategory  string                 `json:"event_category" gorm:"not null;index"` // auth, api, security
	Resource       string                 `json:"resource" gorm:"index"`
	Action         string                 `json:"action" gorm:"index"`
	
	// Context information
	IPAddress      string                 `json:"ip_address"`
	UserAgent      string                 `json:"user_agent"`
	RequestID      string                 `json:"request_id" gorm:"index"`
	
	// Event details
	Success        bool                   `json:"success"`
	ErrorMessage   string                 `json:"error_message"`
	Details        map[string]interface{} `json:"details" gorm:"type:jsonb;default:'{}'"`
	
	// Audit fields
	CreatedAt      time.Time              `json:"created_at"`
}

// Security methods

func (u *User) BeforeCreate(tx *gorm.DB) error {
	if u.ID == uuid.Nil {
		u.ID = uuid.New()
	}
	return nil
}

func (o *Organization) BeforeCreate(tx *gorm.DB) error {
	if o.ID == uuid.Nil {
		o.ID = uuid.New()
	}
	if o.Slug == "" {
		o.Slug = strings.ToLower(strings.ReplaceAll(o.Name, " ", "-"))
	}
	return nil
}

func (uo *UserOrganization) BeforeCreate(tx *gorm.DB) error {
	if uo.ID == uuid.Nil {
		uo.ID = uuid.New()
	}
	return nil
}

func (ak *APIKey) BeforeCreate(tx *gorm.DB) error {
	if ak.ID == uuid.Nil {
		ak.ID = uuid.New()
	}
	return nil
}

// GenerateAPIKey creates a new API key with secure random generation
func GenerateAPIKey() (string, string, string, error) {
	// Generate 32 random bytes (256 bits)
	keyBytes := make([]byte, 32)
	if _, err := rand.Read(keyBytes); err != nil {
		return "", "", "", fmt.Errorf("failed to generate random key: %w", err)
	}
	
	// Encode as base64
	key := base64.RawURLEncoding.EncodeToString(keyBytes)
	
	// Add prefix for identification
	fullKey := fmt.Sprintf("adc_%s", key)
	
	// Generate hash for storage
	hash := sha256.Sum256([]byte(fullKey))
	keyHash := base64.StdEncoding.EncodeToString(hash[:])
	
	// Generate prefix for display (first 8 characters)
	keyPrefix := fullKey[:12] + "..."
	
	return fullKey, keyHash, keyPrefix, nil
}

// HashAPIKey creates a SHA256 hash of an API key for storage
func HashAPIKey(key string) string {
	hash := sha256.Sum256([]byte(key))
	return base64.StdEncoding.EncodeToString(hash[:])
}

// User helper methods

func (u *User) IsActive() bool {
	return u.Status == UserStatusActive
}

func (u *User) IsAdmin() bool {
	return u.Role == UserRoleAdmin
}

func (u *User) CanAccessOrganization(orgID uuid.UUID) bool {
	for _, userOrg := range u.UserOrganizations {
		if userOrg.OrganizationID == orgID && userOrg.Status == UserStatusActive {
			return true
		}
	}
	return false
}

func (u *User) GetOrganizationRole(orgID uuid.UUID) (UserRole, bool) {
	for _, userOrg := range u.UserOrganizations {
		if userOrg.OrganizationID == orgID && userOrg.Status == UserStatusActive {
			return userOrg.Role, true
		}
	}
	return "", false
}

// Organization helper methods

func (o *Organization) IsActive() bool {
	return o.Status == OrganizationStatusActive
}

func (o *Organization) HasMember(userID uuid.UUID) bool {
	for _, member := range o.Members {
		if member.UserID == userID && member.Status == UserStatusActive {
			return true
		}
	}
	return false
}

// APIKey helper methods

func (ak *APIKey) IsValid() bool {
	if !ak.IsActive {
		return false
	}
	if ak.ExpiresAt != nil && ak.ExpiresAt.Before(time.Now()) {
		return false
	}
	return true
}

func (ak *APIKey) HasPermission(permission string) bool {
	for _, p := range ak.Permissions {
		if p == permission || p == "*" {
			return true
		}
	}
	return false
}

func (ak *APIKey) HasScope(scope string) bool {
	for _, s := range ak.Scopes {
		if s == scope || s == "*" {
			return true
		}
	}
	return false
}

func (ak *APIKey) UpdateUsage() {
	now := time.Now()
	ak.LastUsedAt = &now
	ak.UsageCount++
}