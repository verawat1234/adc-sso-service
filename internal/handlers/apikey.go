package handlers

import (
	"net/http"
	"strconv"
	"time"

	"adc-sso-service/internal/middleware"
	"adc-sso-service/internal/models"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

type APIKeyHandler struct {
	db *gorm.DB
}

func NewAPIKeyHandler(db *gorm.DB) *APIKeyHandler {
	return &APIKeyHandler{db: db}
}

// CreateAPIKey creates a new API key for the authenticated user
// POST /api/v1/organizations/{org_id}/api-keys
func (h *APIKeyHandler) CreateAPIKey(c *gin.Context) {
	user, exists := middleware.GetUserFromContext(c)
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User context not found"})
		return
	}

	orgID, exists := middleware.GetOrganizationIDFromContext(c)
	if !exists {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Organization context not found"})
		return
	}

	var req struct {
		Name        string    `json:"name" binding:"required"`
		Permissions []string  `json:"permissions"`
		Scopes      []string  `json:"scopes"`
		ExpiresAt   *time.Time `json:"expires_at,omitempty"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Verify user has access to the organization
	if !user.IsAdmin() && !user.CanAccessOrganization(orgID) {
		c.JSON(http.StatusForbidden, gin.H{"error": "Access denied to organization"})
		return
	}

	// Check if user has permission to create API keys
	orgRole, hasRole := user.GetOrganizationRole(orgID)
	if !hasRole || (orgRole != models.UserRoleOwner && orgRole != models.UserRoleAdmin && !user.IsAdmin()) {
		c.JSON(http.StatusForbidden, gin.H{"error": "Insufficient permissions to create API keys"})
		return
	}

	// Generate API key
	fullKey, keyHash, keyPrefix, err := models.GenerateAPIKey()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate API key"})
		return
	}

	// Create API key record
	apiKey := models.APIKey{
		Name:           req.Name,
		KeyHash:        keyHash,
		KeyPrefix:      keyPrefix,
		UserID:         user.ID,
		OrganizationID: orgID,
		Permissions:    req.Permissions,
		Scopes:         req.Scopes,
		IsActive:       true,
		ExpiresAt:      req.ExpiresAt,
	}

	if err := h.db.Create(&apiKey).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create API key"})
		return
	}

	// Return API key (only time the full key is shown)
	c.JSON(http.StatusCreated, gin.H{
		"api_key": map[string]interface{}{
			"id":          apiKey.ID,
			"name":        apiKey.Name,
			"key":         fullKey, // Only shown once
			"key_prefix":  apiKey.KeyPrefix,
			"permissions": apiKey.Permissions,
			"scopes":      apiKey.Scopes,
			"expires_at":  apiKey.ExpiresAt,
			"created_at":  apiKey.CreatedAt,
		},
		"warning": "This is the only time the full API key will be shown. Please store it securely.",
	})
}

// ListAPIKeys lists API keys for an organization
// GET /api/v1/organizations/{org_id}/api-keys
func (h *APIKeyHandler) ListAPIKeys(c *gin.Context) {
	user, exists := middleware.GetUserFromContext(c)
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User context not found"})
		return
	}

	orgID, exists := middleware.GetOrganizationIDFromContext(c)
	if !exists {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Organization context not found"})
		return
	}

	// Verify user has access to the organization
	if !user.IsAdmin() && !user.CanAccessOrganization(orgID) {
		c.JSON(http.StatusForbidden, gin.H{"error": "Access denied to organization"})
		return
	}

	// Parse query parameters
	limit := 50
	if limitStr := c.Query("limit"); limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 && l <= 100 {
			limit = l
		}
	}

	offset := 0
	if offsetStr := c.Query("offset"); offsetStr != "" {
		if o, err := strconv.Atoi(offsetStr); err == nil && o >= 0 {
			offset = o
		}
	}

	showInactive := c.Query("include_inactive") == "true"

	// Build query
	query := h.db.Where("organization_id = ?", orgID)
	if !showInactive {
		query = query.Where("is_active = ?", true)
	}

	// Get total count
	var total int64
	query.Model(&models.APIKey{}).Count(&total)

	// Get API keys with user information
	var apiKeys []models.APIKey
	if err := query.Preload("User").Limit(limit).Offset(offset).Order("created_at DESC").Find(&apiKeys).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch API keys"})
		return
	}

	// Format response (exclude sensitive data)
	response := make([]map[string]interface{}, len(apiKeys))
	for i, key := range apiKeys {
		response[i] = map[string]interface{}{
			"id":           key.ID,
			"name":         key.Name,
			"key_prefix":   key.KeyPrefix,
			"permissions":  key.Permissions,
			"scopes":       key.Scopes,
			"is_active":    key.IsActive,
			"last_used_at": key.LastUsedAt,
			"usage_count":  key.UsageCount,
			"expires_at":   key.ExpiresAt,
			"created_at":   key.CreatedAt,
			"created_by": map[string]interface{}{
				"id":       key.User.ID,
				"username": key.User.Username,
				"email":    key.User.Email,
			},
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"api_keys": response,
		"pagination": map[string]interface{}{
			"total":  total,
			"limit":  limit,
			"offset": offset,
			"has_more": int64(offset+limit) < total,
		},
	})
}

// GetAPIKey retrieves a specific API key
// GET /api/v1/organizations/{org_id}/api-keys/{key_id}
func (h *APIKeyHandler) GetAPIKey(c *gin.Context) {
	user, exists := middleware.GetUserFromContext(c)
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User context not found"})
		return
	}

	orgID, exists := middleware.GetOrganizationIDFromContext(c)
	if !exists {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Organization context not found"})
		return
	}

	keyIDStr := c.Param("key_id")
	keyID, err := uuid.Parse(keyIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid API key ID"})
		return
	}

	// Verify user has access to the organization
	if !user.IsAdmin() && !user.CanAccessOrganization(orgID) {
		c.JSON(http.StatusForbidden, gin.H{"error": "Access denied to organization"})
		return
	}

	// Find API key
	var apiKey models.APIKey
	if err := h.db.Preload("User").Where("id = ? AND organization_id = ?", keyID, orgID).First(&apiKey).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "API key not found"})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch API key"})
		}
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"api_key": map[string]interface{}{
			"id":           apiKey.ID,
			"name":         apiKey.Name,
			"key_prefix":   apiKey.KeyPrefix,
			"permissions":  apiKey.Permissions,
			"scopes":       apiKey.Scopes,
			"is_active":    apiKey.IsActive,
			"last_used_at": apiKey.LastUsedAt,
			"usage_count":  apiKey.UsageCount,
			"expires_at":   apiKey.ExpiresAt,
			"created_at":   apiKey.CreatedAt,
			"created_by": map[string]interface{}{
				"id":       apiKey.User.ID,
				"username": apiKey.User.Username,
				"email":    apiKey.User.Email,
			},
		},
	})
}

// UpdateAPIKey updates an API key
// PUT /api/v1/organizations/{org_id}/api-keys/{key_id}
func (h *APIKeyHandler) UpdateAPIKey(c *gin.Context) {
	user, exists := middleware.GetUserFromContext(c)
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User context not found"})
		return
	}

	orgID, exists := middleware.GetOrganizationIDFromContext(c)
	if !exists {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Organization context not found"})
		return
	}

	keyIDStr := c.Param("key_id")
	keyID, err := uuid.Parse(keyIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid API key ID"})
		return
	}

	var req struct {
		Name        *string    `json:"name,omitempty"`
		Permissions []string   `json:"permissions,omitempty"`
		Scopes      []string   `json:"scopes,omitempty"`
		IsActive    *bool      `json:"is_active,omitempty"`
		ExpiresAt   *time.Time `json:"expires_at,omitempty"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Verify user has access to the organization
	if !user.IsAdmin() && !user.CanAccessOrganization(orgID) {
		c.JSON(http.StatusForbidden, gin.H{"error": "Access denied to organization"})
		return
	}

	// Check permissions
	orgRole, hasRole := user.GetOrganizationRole(orgID)
	if !hasRole || (orgRole != models.UserRoleOwner && orgRole != models.UserRoleAdmin && !user.IsAdmin()) {
		c.JSON(http.StatusForbidden, gin.H{"error": "Insufficient permissions to update API keys"})
		return
	}

	// Find and update API key
	var apiKey models.APIKey
	if err := h.db.Where("id = ? AND organization_id = ?", keyID, orgID).First(&apiKey).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "API key not found"})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch API key"})
		}
		return
	}

	// Update fields
	if req.Name != nil {
		apiKey.Name = *req.Name
	}
	if req.Permissions != nil {
		apiKey.Permissions = req.Permissions
	}
	if req.Scopes != nil {
		apiKey.Scopes = req.Scopes
	}
	if req.IsActive != nil {
		apiKey.IsActive = *req.IsActive
	}
	if req.ExpiresAt != nil {
		apiKey.ExpiresAt = req.ExpiresAt
	}

	if err := h.db.Save(&apiKey).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update API key"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"api_key": map[string]interface{}{
			"id":           apiKey.ID,
			"name":         apiKey.Name,
			"key_prefix":   apiKey.KeyPrefix,
			"permissions":  apiKey.Permissions,
			"scopes":       apiKey.Scopes,
			"is_active":    apiKey.IsActive,
			"last_used_at": apiKey.LastUsedAt,
			"usage_count":  apiKey.UsageCount,
			"expires_at":   apiKey.ExpiresAt,
			"updated_at":   apiKey.UpdatedAt,
		},
	})
}

// DeleteAPIKey deletes an API key
// DELETE /api/v1/organizations/{org_id}/api-keys/{key_id}
func (h *APIKeyHandler) DeleteAPIKey(c *gin.Context) {
	user, exists := middleware.GetUserFromContext(c)
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User context not found"})
		return
	}

	orgID, exists := middleware.GetOrganizationIDFromContext(c)
	if !exists {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Organization context not found"})
		return
	}

	keyIDStr := c.Param("key_id")
	keyID, err := uuid.Parse(keyIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid API key ID"})
		return
	}

	// Verify user has access to the organization
	if !user.IsAdmin() && !user.CanAccessOrganization(orgID) {
		c.JSON(http.StatusForbidden, gin.H{"error": "Access denied to organization"})
		return
	}

	// Check permissions
	orgRole, hasRole := user.GetOrganizationRole(orgID)
	if !hasRole || (orgRole != models.UserRoleOwner && orgRole != models.UserRoleAdmin && !user.IsAdmin()) {
		c.JSON(http.StatusForbidden, gin.H{"error": "Insufficient permissions to delete API keys"})
		return
	}

	// Find and delete API key
	result := h.db.Where("id = ? AND organization_id = ?", keyID, orgID).Delete(&models.APIKey{})
	if result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete API key"})
		return
	}

	if result.RowsAffected == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "API key not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "API key deleted successfully"})
}

// RegenerateAPIKey regenerates an API key (creates new key, invalidates old one)
// POST /api/v1/organizations/{org_id}/api-keys/{key_id}/regenerate
func (h *APIKeyHandler) RegenerateAPIKey(c *gin.Context) {
	user, exists := middleware.GetUserFromContext(c)
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User context not found"})
		return
	}

	orgID, exists := middleware.GetOrganizationIDFromContext(c)
	if !exists {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Organization context not found"})
		return
	}

	keyIDStr := c.Param("key_id")
	keyID, err := uuid.Parse(keyIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid API key ID"})
		return
	}

	// Verify user has access to the organization
	if !user.IsAdmin() && !user.CanAccessOrganization(orgID) {
		c.JSON(http.StatusForbidden, gin.H{"error": "Access denied to organization"})
		return
	}

	// Check permissions
	orgRole, hasRole := user.GetOrganizationRole(orgID)
	if !hasRole || (orgRole != models.UserRoleOwner && orgRole != models.UserRoleAdmin && !user.IsAdmin()) {
		c.JSON(http.StatusForbidden, gin.H{"error": "Insufficient permissions to regenerate API keys"})
		return
	}

	// Find existing API key
	var apiKey models.APIKey
	if err := h.db.Where("id = ? AND organization_id = ?", keyID, orgID).First(&apiKey).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "API key not found"})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch API key"})
		}
		return
	}

	// Generate new API key
	fullKey, keyHash, keyPrefix, err := models.GenerateAPIKey()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate new API key"})
		return
	}

	// Update the API key with new values
	apiKey.KeyHash = keyHash
	apiKey.KeyPrefix = keyPrefix
	apiKey.LastUsedAt = nil
	apiKey.UsageCount = 0

	if err := h.db.Save(&apiKey).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update API key"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"api_key": map[string]interface{}{
			"id":          apiKey.ID,
			"name":        apiKey.Name,
			"key":         fullKey, // Only shown once
			"key_prefix":  apiKey.KeyPrefix,
			"permissions": apiKey.Permissions,
			"scopes":      apiKey.Scopes,
			"updated_at":  apiKey.UpdatedAt,
		},
		"warning": "This is the only time the new API key will be shown. Please store it securely.",
	})
}
