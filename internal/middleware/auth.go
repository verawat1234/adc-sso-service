package middleware

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"adc-sso-service/internal/auth"
	"adc-sso-service/internal/models"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// AuthContext keys for storing authentication information
type AuthContextKey string

const (
	UserContextKey         AuthContextKey = "user"
	OrganizationContextKey AuthContextKey = "organization"
	APIKeyContextKey       AuthContextKey = "api_key"
	RoleContextKey         AuthContextKey = "role"
	PermissionsContextKey  AuthContextKey = "permissions"
)

// AuthMiddleware provides authentication and authorization middleware
type AuthMiddleware struct {
	authService *auth.AuthService
	db          *gorm.DB
}

// NewAuthMiddleware creates a new authentication middleware instance
func NewAuthMiddleware(authService *auth.AuthService, db *gorm.DB) *AuthMiddleware {
	return &AuthMiddleware{
		authService: authService,
		db:          db,
	}
}

// JWTAuthMiddleware validates JWT tokens and sets user context
func (m *AuthMiddleware) JWTAuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Extract token from Authorization header
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization header required"})
			c.Abort()
			return
		}

		// Check for Bearer token format
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || parts[0] != "Bearer" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid authorization header format"})
			c.Abort()
			return
		}

		tokenString := parts[1]

		// Validate token
		claims, err := m.authService.ValidateToken(tokenString)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
			c.Abort()
			return
		}

		// Get user from database with organizations
		var user models.User
		userID, err := uuid.Parse(claims.UserID)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid user ID in token"})
			c.Abort()
			return
		}

		if err := m.db.Preload("UserOrganizations.Organization").First(&user, userID).Error; err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "User not found"})
			c.Abort()
			return
		}

		// Check if user is active
		if !user.IsActive() {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "User account is not active"})
			c.Abort()
			return
		}

		// Update last login
		now := time.Now()
		user.LastLogin = &now
		m.db.Model(&user).Update("last_login", now)

		// Set user context
		c.Set(string(UserContextKey), user)
		c.Set(string(RoleContextKey), user.Role)

		// Log authentication event
		m.logAuthEvent(c, user.ID, nil, "jwt_auth", "auth", true, "")

		c.Next()
	}
}

// APIKeyAuthMiddleware validates API keys and sets organization context
func (m *AuthMiddleware) APIKeyAuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Extract API key from header or query parameter
		apiKey := c.GetHeader("X-API-Key")
		if apiKey == "" {
			apiKey = c.Query("api_key")
		}

		if apiKey == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "API key required"})
			c.Abort()
			return
		}

		// Validate API key format
		if !strings.HasPrefix(apiKey, "adc_") {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid API key format"})
			c.Abort()
			return
		}

		// Hash the API key for lookup
		keyHash := models.HashAPIKey(apiKey)

		// Find API key in database with relationships
		var apiKeyModel models.APIKey
		if err := m.db.Preload("User").Preload("Organization").Where("key_hash = ?", keyHash).First(&apiKeyModel).Error; err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid API key"})
			c.Abort()
			return
		}

		// Check if API key is valid
		if !apiKeyModel.IsValid() {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "API key is not valid or has expired"})
			c.Abort()
			return
		}

		// Check if user is active
		if !apiKeyModel.User.IsActive() {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "User account is not active"})
			c.Abort()
			return
		}

		// Check if organization is active
		if !apiKeyModel.Organization.IsActive() {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Organization is not active"})
			c.Abort()
			return
		}

		// Update API key usage
		apiKeyModel.UpdateUsage()
		m.db.Save(&apiKeyModel)

		// Set context
		c.Set(string(UserContextKey), apiKeyModel.User)
		c.Set(string(OrganizationContextKey), apiKeyModel.Organization)
		c.Set(string(APIKeyContextKey), apiKeyModel)
		c.Set(string(PermissionsContextKey), apiKeyModel.Permissions)

		// Log authentication event
		m.logAuthEvent(c, apiKeyModel.UserID, &apiKeyModel.OrganizationID, "api_key_auth", "api", true, "")

		c.Next()
	}
}

// FlexibleAuthMiddleware accepts either JWT or API key authentication
func (m *AuthMiddleware) FlexibleAuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Check for JWT token first
		authHeader := c.GetHeader("Authorization")
		if authHeader != "" && strings.HasPrefix(authHeader, "Bearer ") {
			m.JWTAuthMiddleware()(c)
			return
		}

		// Check for API key
		apiKey := c.GetHeader("X-API-Key")
		if apiKey == "" {
			apiKey = c.Query("api_key")
		}

		if apiKey != "" {
			m.APIKeyAuthMiddleware()(c)
			return
		}

		// No valid authentication found
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Authentication required (JWT token or API key)"})
		c.Abort()
	}
}

// RequireRole ensures the authenticated user has the specified role
func (m *AuthMiddleware) RequireRole(roles ...models.UserRole) gin.HandlerFunc {
	return func(c *gin.Context) {
		userInterface, exists := c.Get(string(UserContextKey))
		if !exists {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "User context not found"})
			c.Abort()
			return
		}

		user, ok := userInterface.(models.User)
		if !ok {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Invalid user context"})
			c.Abort()
			return
		}

		// Check if user has any of the required roles
		for _, role := range roles {
			if user.Role == role {
				c.Next()
				return
			}
		}

		// Log authorization failure
		m.logAuthEvent(c, user.ID, nil, "authorization_failed", "auth", false, fmt.Sprintf("Required roles: %v, User role: %s", roles, user.Role))

		c.JSON(http.StatusForbidden, gin.H{"error": "Insufficient permissions"})
		c.Abort()
	}
}

// RequireOrganizationAccess ensures the user has access to the specified organization
func (m *AuthMiddleware) RequireOrganizationAccess() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Extract organization ID from various sources
		orgID := m.extractOrganizationID(c)
		if orgID == uuid.Nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Organization ID required"})
			c.Abort()
			return
		}

		userInterface, exists := c.Get(string(UserContextKey))
		if !exists {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "User context not found"})
			c.Abort()
			return
		}

		user, ok := userInterface.(models.User)
		if !ok {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Invalid user context"})
			c.Abort()
			return
		}

		// Check if user is admin (can access any organization)
		if user.IsAdmin() {
			c.Set(string(OrganizationContextKey), orgID)
			c.Next()
			return
		}

		// Check if user has access to the organization
		if !user.CanAccessOrganization(orgID) {
			m.logAuthEvent(c, user.ID, &orgID, "organization_access_denied", "auth", false, "User does not have access to organization")
			c.JSON(http.StatusForbidden, gin.H{"error": "Access denied to organization"})
			c.Abort()
			return
		}

		// Set organization context
		c.Set(string(OrganizationContextKey), orgID)

		// Get user's role in the organization
		if role, exists := user.GetOrganizationRole(orgID); exists {
			c.Set(string(RoleContextKey), role)
		}

		c.Next()
	}
}

// RequirePermission checks if the user has the specified permission
func (m *AuthMiddleware) RequirePermission(permission string) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Check if authenticated via API key with specific permissions
		if apiKeyInterface, exists := c.Get(string(APIKeyContextKey)); exists {
			if apiKey, ok := apiKeyInterface.(models.APIKey); ok {
				if apiKey.HasPermission(permission) {
					c.Next()
					return
				}
			}
		}

		// For JWT auth, check user role-based permissions
		userInterface, exists := c.Get(string(UserContextKey))
		if !exists {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "User context not found"})
			c.Abort()
			return
		}

		user, ok := userInterface.(models.User)
		if !ok {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Invalid user context"})
			c.Abort()
			return
		}

		// Admin users have all permissions
		if user.IsAdmin() {
			c.Next()
			return
		}

		// Check permission based on role or specific grants
		// This would be expanded with a proper permission system
		if m.hasPermission(user, permission) {
			c.Next()
			return
		}

		m.logAuthEvent(c, user.ID, nil, "permission_denied", "auth", false, fmt.Sprintf("Required permission: %s", permission))
		c.JSON(http.StatusForbidden, gin.H{"error": "Permission denied"})
		c.Abort()
	}
}

// OrganizationContextMiddleware extracts organization context from request
func (m *AuthMiddleware) OrganizationContextMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		orgID := m.extractOrganizationID(c)
		if orgID != uuid.Nil {
			c.Set(string(OrganizationContextKey), orgID)
		}
		c.Next()
	}
}

// Helper methods

func (m *AuthMiddleware) extractOrganizationID(c *gin.Context) uuid.UUID {
	// Try multiple sources for organization ID
	sources := []string{
		c.GetHeader("X-Organization-ID"),
		c.Param("organization_id"),
		c.Param("org_id"),
		c.Query("organization_id"),
		c.Query("org_id"),
	}

	for _, source := range sources {
		if source != "" {
			if orgID, err := uuid.Parse(source); err == nil {
				return orgID
			}
		}
	}

	return uuid.Nil
}

func (m *AuthMiddleware) hasPermission(user models.User, permission string) bool {
	// Basic permission checking - would be expanded with proper RBAC
	switch permission {
	case "read":
		return user.Status == models.UserStatusActive
	case "write":
		return user.Role == models.UserRoleAdmin || user.Role == models.UserRoleOwner
	case "admin":
		return user.Role == models.UserRoleAdmin
	default:
		return false
	}
}

func (m *AuthMiddleware) logAuthEvent(c *gin.Context, userID uuid.UUID, orgID *uuid.UUID, eventType, category string, success bool, errorMessage string) {
	auditLog := models.AuditLog{
		UserID:         &userID,
		OrganizationID: orgID,
		EventType:      eventType,
		EventCategory:  category,
		IPAddress:      c.ClientIP(),
		UserAgent:      c.GetHeader("User-Agent"),
		RequestID:      c.GetHeader("X-Request-ID"),
		Success:        success,
		ErrorMessage:   errorMessage,
		Details: map[string]interface{}{
			"method": c.Request.Method,
			"path":   c.Request.URL.Path,
			"query":  c.Request.URL.RawQuery,
		},
	}

	// Log asynchronously to avoid blocking the request
	go func() {
		m.db.Create(&auditLog)
	}()
}

// Context helper functions

// GetUserFromContext retrieves the authenticated user from the Gin context
func GetUserFromContext(c *gin.Context) (*models.User, bool) {
	userInterface, exists := c.Get(string(UserContextKey))
	if !exists {
		return nil, false
	}

	user, ok := userInterface.(models.User)
	if !ok {
		return nil, false
	}

	return &user, true
}

// GetOrganizationIDFromContext retrieves the organization ID from the Gin context
func GetOrganizationIDFromContext(c *gin.Context) (uuid.UUID, bool) {
	orgInterface, exists := c.Get(string(OrganizationContextKey))
	if !exists {
		return uuid.Nil, false
	}

	switch org := orgInterface.(type) {
	case uuid.UUID:
		return org, true
	case string:
		if orgID, err := uuid.Parse(org); err == nil {
			return orgID, true
		}
	}

	return uuid.Nil, false
}

// GetAPIKeyFromContext retrieves the API key from the Gin context
func GetAPIKeyFromContext(c *gin.Context) (*models.APIKey, bool) {
	apiKeyInterface, exists := c.Get(string(APIKeyContextKey))
	if !exists {
		return nil, false
	}

	apiKey, ok := apiKeyInterface.(models.APIKey)
	if !ok {
		return nil, false
	}

	return &apiKey, true
}
