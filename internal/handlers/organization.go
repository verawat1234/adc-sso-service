package handlers

import (
	"net/http"
	"strconv"
	"strings"

	"adc-sso-service/internal/middleware"
	"adc-sso-service/internal/models"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

type OrganizationHandler struct {
	db *gorm.DB
}

func NewOrganizationHandler(db *gorm.DB) *OrganizationHandler {
	return &OrganizationHandler{db: db}
}

// CreateOrganization creates a new organization
// POST /api/v1/organizations
func (h *OrganizationHandler) CreateOrganization(c *gin.Context) {
	user, exists := middleware.GetUserFromContext(c)
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User context not found"})
		return
	}

	var req struct {
		Name        string                 `json:"name" binding:"required"`
		Slug        string                 `json:"slug,omitempty"`
		Description string                 `json:"description,omitempty"`
		Website     string                 `json:"website,omitempty"`
		Settings    map[string]interface{} `json:"settings,omitempty"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Generate slug if not provided
	if req.Slug == "" {
		req.Slug = strings.ToLower(strings.ReplaceAll(req.Name, " ", "-"))
	}

	// Check if slug is already taken
	var existingOrg models.Organization
	if err := h.db.Where("slug = ?", req.Slug).First(&existingOrg).Error; err == nil {
		c.JSON(http.StatusConflict, gin.H{"error": "Organization slug already exists"})
		return
	}

	// Create organization
	org := models.Organization{
		Name:        req.Name,
		Slug:        req.Slug,
		Description: req.Description,
		Website:     req.Website,
		OwnerID:     user.ID,
		Status:      models.OrganizationStatusActive,
		Settings:    req.Settings,
		Metadata:    make(map[string]interface{}),
	}

	// Start transaction
	tx := h.db.Begin()
	defer func() {
		if r := recover(); r != nil {
			tx.Rollback()
		}
	}()

	// Create organization
	if err := tx.Create(&org).Error; err != nil {
		tx.Rollback()
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create organization"})
		return
	}

	// Add owner as member
	userOrg := models.UserOrganization{
		UserID:         user.ID,
		OrganizationID: org.ID,
		Role:           models.UserRoleOwner,
		Status:         models.UserStatusActive,
	}

	if err := tx.Create(&userOrg).Error; err != nil {
		tx.Rollback()
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to add user to organization"})
		return
	}

	tx.Commit()

	c.JSON(http.StatusCreated, gin.H{
		"organization": map[string]interface{}{
			"id":          org.ID,
			"name":        org.Name,
			"slug":        org.Slug,
			"description": org.Description,
			"website":     org.Website,
			"status":      org.Status,
			"settings":    org.Settings,
			"created_at":  org.CreatedAt,
			"user_role":   models.UserRoleOwner,
		},
	})
}

// ListOrganizations lists organizations for the authenticated user
// GET /api/v1/organizations
func (h *OrganizationHandler) ListOrganizations(c *gin.Context) {
	user, exists := middleware.GetUserFromContext(c)
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User context not found"})
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

	// Admin users can see all organizations
	if user.IsAdmin() {
		var orgs []models.Organization
		var total int64

		h.db.Model(&models.Organization{}).Count(&total)
		if err := h.db.Limit(limit).Offset(offset).Order("created_at DESC").Find(&orgs).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch organizations"})
			return
		}

		response := make([]map[string]interface{}, len(orgs))
		for i, org := range orgs {
			response[i] = map[string]interface{}{
				"id":          org.ID,
				"name":        org.Name,
				"slug":        org.Slug,
				"description": org.Description,
				"website":     org.Website,
				"status":      org.Status,
				"created_at":  org.CreatedAt,
				"user_role":   models.UserRoleAdmin,
			}
		}

		c.JSON(http.StatusOK, gin.H{
			"organizations": response,
			"pagination": map[string]interface{}{
				"total":   total,
				"limit":   limit,
				"offset":  offset,
				"has_more": int64(offset+limit) < total,
			},
		})
		return
	}

	// Regular users see only their organizations
	var userOrgs []models.UserOrganization
	var total int64

	h.db.Model(&models.UserOrganization{}).Where("user_id = ? AND status = ?", user.ID, models.UserStatusActive).Count(&total)
	if err := h.db.Preload("Organization").Where("user_id = ? AND status = ?", user.ID, models.UserStatusActive).Limit(limit).Offset(offset).Order("joined_at DESC").Find(&userOrgs).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch organizations"})
		return
	}

	response := make([]map[string]interface{}, len(userOrgs))
	for i, userOrg := range userOrgs {
		response[i] = map[string]interface{}{
			"id":          userOrg.Organization.ID,
			"name":        userOrg.Organization.Name,
			"slug":        userOrg.Organization.Slug,
			"description": userOrg.Organization.Description,
			"website":     userOrg.Organization.Website,
			"status":      userOrg.Organization.Status,
			"created_at":  userOrg.Organization.CreatedAt,
			"user_role":   userOrg.Role,
			"joined_at":   userOrg.JoinedAt,
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"organizations": response,
		"pagination": map[string]interface{}{
			"total":   total,
			"limit":   limit,
			"offset":  offset,
			"has_more": int64(offset+limit) < total,
		},
	})
}

// GetOrganization retrieves a specific organization
// GET /api/v1/organizations/{org_id}
func (h *OrganizationHandler) GetOrganization(c *gin.Context) {
	user, exists := middleware.GetUserFromContext(c)
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User context not found"})
		return
	}

	orgIDStr := c.Param("org_id")
	orgID, err := uuid.Parse(orgIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid organization ID"})
		return
	}

	// Check access
	if !user.IsAdmin() && !user.CanAccessOrganization(orgID) {
		c.JSON(http.StatusForbidden, gin.H{"error": "Access denied to organization"})
		return
	}

	// Find organization with owner info
	var org models.Organization
	if err := h.db.Preload("Owner").First(&org, orgID).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "Organization not found"})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch organization"})
		}
		return
	}

	// Get user's role in the organization
	userRole := models.UserRoleAdmin // Default for admin users
	if !user.IsAdmin() {
		if role, exists := user.GetOrganizationRole(orgID); exists {
			userRole = role
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"organization": map[string]interface{}{
			"id":          org.ID,
			"name":        org.Name,
			"slug":        org.Slug,
			"description": org.Description,
			"website":     org.Website,
			"status":      org.Status,
			"settings":    org.Settings,
			"metadata":    org.Metadata,
			"created_at":  org.CreatedAt,
			"updated_at":  org.UpdatedAt,
			"owner": map[string]interface{}{
				"id":       org.Owner.ID,
				"username": org.Owner.Username,
				"email":    org.Owner.Email,
				"full_name": org.Owner.FullName,
			},
			"user_role": userRole,
		},
	})
}

// UpdateOrganization updates an organization
// PUT /api/v1/organizations/{org_id}
func (h *OrganizationHandler) UpdateOrganization(c *gin.Context) {
	user, exists := middleware.GetUserFromContext(c)
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User context not found"})
		return
	}

	orgIDStr := c.Param("org_id")
	orgID, err := uuid.Parse(orgIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid organization ID"})
		return
	}

	var req struct {
		Name        *string                `json:"name,omitempty"`
		Description *string                `json:"description,omitempty"`
		Website     *string                `json:"website,omitempty"`
		Settings    map[string]interface{} `json:"settings,omitempty"`
		Status      *models.OrganizationStatus `json:"status,omitempty"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Check access and permissions
	if !user.IsAdmin() {
		if !user.CanAccessOrganization(orgID) {
			c.JSON(http.StatusForbidden, gin.H{"error": "Access denied to organization"})
			return
		}

		// Check if user has owner/admin role
		orgRole, hasRole := user.GetOrganizationRole(orgID)
		if !hasRole || (orgRole != models.UserRoleOwner && orgRole != models.UserRoleAdmin) {
			c.JSON(http.StatusForbidden, gin.H{"error": "Insufficient permissions to update organization"})
			return
		}

		// Non-admin users cannot change organization status
		if req.Status != nil {
			c.JSON(http.StatusForbidden, gin.H{"error": "Only system administrators can change organization status"})
			return
		}
	}

	// Find and update organization
	var org models.Organization
	if err := h.db.First(&org, orgID).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "Organization not found"})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch organization"})
		}
		return
	}

	// Update fields
	if req.Name != nil {
		org.Name = *req.Name
	}
	if req.Description != nil {
		org.Description = *req.Description
	}
	if req.Website != nil {
		org.Website = *req.Website
	}
	if req.Settings != nil {
		org.Settings = req.Settings
	}
	if req.Status != nil && user.IsAdmin() {
		org.Status = *req.Status
	}

	if err := h.db.Save(&org).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update organization"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"organization": map[string]interface{}{
			"id":          org.ID,
			"name":        org.Name,
			"slug":        org.Slug,
			"description": org.Description,
			"website":     org.Website,
			"status":      org.Status,
			"settings":    org.Settings,
			"updated_at":  org.UpdatedAt,
		},
	})
}

// DeleteOrganization deletes an organization
// DELETE /api/v1/organizations/{org_id}
func (h *OrganizationHandler) DeleteOrganization(c *gin.Context) {
	user, exists := middleware.GetUserFromContext(c)
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User context not found"})
		return
	}

	orgIDStr := c.Param("org_id")
	orgID, err := uuid.Parse(orgIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid organization ID"})
		return
	}

	// Find organization
	var org models.Organization
	if err := h.db.First(&org, orgID).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "Organization not found"})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch organization"})
		}
		return
	}

	// Check permissions - only owner or admin can delete
	if !user.IsAdmin() && org.OwnerID != user.ID {
		c.JSON(http.StatusForbidden, gin.H{"error": "Only organization owner or system administrator can delete organization"})
		return
	}

	// Start transaction for cleanup
	tx := h.db.Begin()
	defer func() {
		if r := recover(); r != nil {
			tx.Rollback()
		}
	}()

	// Delete related records
	if err := tx.Where("organization_id = ?", orgID).Delete(&models.UserOrganization{}).Error; err != nil {
		tx.Rollback()
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete organization members"})
		return
	}

	if err := tx.Where("organization_id = ?", orgID).Delete(&models.APIKey{}).Error; err != nil {
		tx.Rollback()
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete organization API keys"})
		return
	}

	// Delete organization
	if err := tx.Delete(&org).Error; err != nil {
		tx.Rollback()
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete organization"})
		return
	}

	tx.Commit()

	c.JSON(http.StatusOK, gin.H{"message": "Organization deleted successfully"})
}

// ListOrganizationMembers lists members of an organization
// GET /api/v1/organizations/{org_id}/members
func (h *OrganizationHandler) ListOrganizationMembers(c *gin.Context) {
	user, exists := middleware.GetUserFromContext(c)
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User context not found"})
		return
	}

	orgIDStr := c.Param("org_id")
	orgID, err := uuid.Parse(orgIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid organization ID"})
		return
	}

	// Check access
	if !user.IsAdmin() && !user.CanAccessOrganization(orgID) {
		c.JSON(http.StatusForbidden, gin.H{"error": "Access denied to organization"})
		return
	}

	// Get organization members
	var members []models.UserOrganization
	if err := h.db.Preload("User").Where("organization_id = ?", orgID).Find(&members).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch organization members"})
		return
	}

	response := make([]map[string]interface{}, len(members))
	for i, member := range members {
		response[i] = map[string]interface{}{
			"user": map[string]interface{}{
				"id":              member.User.ID,
				"username":        member.User.Username,
				"email":           member.User.Email,
				"full_name":       member.User.FullName,
				"profile_image_url": member.User.ProfileImageURL,
				"status":          member.User.Status,
				"last_login":      member.User.LastLogin,
			},
			"role":      member.Role,
			"status":    member.Status,
			"joined_at": member.JoinedAt,
		}
	}

	c.JSON(http.StatusOK, gin.H{"members": response})
}
