package handlers

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"adc-sso-service/internal/auth"
	"adc-sso-service/internal/cache"
	"adc-sso-service/internal/config"
	"adc-sso-service/internal/models"
	"adc-sso-service/internal/types"
	"adc-sso-service/internal/utils"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"gorm.io/gorm"
)

type AuthHandler struct {
	db             *gorm.DB
	authService    *auth.AuthService
	config         *config.Config
	sessionManager *cache.SessionManager
}

func NewAuthHandler(db *gorm.DB, authService *auth.AuthService, cfg *config.Config, sessionManager *cache.SessionManager) *AuthHandler {
	return &AuthHandler{
		db:             db,
		authService:    authService,
		config:         cfg,
		sessionManager: sessionManager,
	}
}

// RedirectToSSO redirects user to Keycloak for SSO authentication
func (h *AuthHandler) RedirectToSSO(c *gin.Context) {
	resp := utils.NewResponseHelper(c)

	// Generate state parameter for CSRF protection
	state, err := generateSecureState()
	if err != nil {
		logrus.WithError(err).Error("Failed to generate SSO state")
		resp.InternalError("Failed to generate authentication state")
		return
	}

	// Store state in session/cache for validation
	h.storeStateInSession(c, state)

	// Build Keycloak authorization URL
	authURL := fmt.Sprintf("%s/realms/%s/protocol/openid-connect/auth", 
		h.config.KeycloakURL, h.config.KeycloakRealm)
	
	params := url.Values{}
	params.Add("client_id", h.config.KeycloakClientID)
	params.Add("redirect_uri", h.config.KeycloakRedirectURI)
	params.Add("response_type", "code")
	params.Add("scope", "openid email profile")
	params.Add("state", state)

	fullAuthURL := authURL + "?" + params.Encode()

	// Return redirect URL
	response := map[string]string{
		"redirect_url": fullAuthURL,
		"state":        state,
	}

	resp.Success(response, "SSO redirect URL generated")
}

// HandleSSOCallback handles the callback from Keycloak
func (h *AuthHandler) HandleSSOCallback(c *gin.Context) {
	resp := utils.NewResponseHelper(c)

	// Get parameters from callback
	code := c.Query("code")
	state := c.Query("state")
	errorParam := c.Query("error")

	if errorParam != "" {
		logrus.WithField("error", errorParam).Warn("SSO callback returned error")
		resp.BadRequest("SSO authentication failed: " + errorParam)
		return
	}

	if code == "" || state == "" {
		resp.BadRequest("Missing required callback parameters")
		return
	}

	// Validate state parameter
	if !h.validateStateFromSession(c, state) {
		resp.BadRequest("Invalid or expired authentication state")
		return
	}

	// Exchange code for tokens
	tokenResponse, err := h.exchangeCodeForTokens(code)
	if err != nil {
		logrus.WithError(err).Error("Failed to exchange code for tokens")
		resp.InternalError("Failed to complete SSO authentication")
		return
	}

	// Get user info from Keycloak
	userInfo, err := h.getUserInfoFromKeycloak(tokenResponse.AccessToken)
	if err != nil {
		logrus.WithError(err).Error("Failed to get user info from Keycloak")
		resp.InternalError("Failed to get user information")
		return
	}

	// Find or create user in local database
	user, isNewUser, err := h.findOrCreateUserFromSSO(userInfo)
	if err != nil {
		logrus.WithError(err).Error("Failed to find or create user from SSO")
		resp.InternalError("Failed to process user information")
		return
	}

	// Generate local JWT tokens
	accessToken, err := h.authService.GenerateToken(
		user.ID.String(),
		user.Username,
		user.Email,
		string(user.Role),
	)
	if err != nil {
		logrus.WithError(err).Error("Failed to generate access token")
		resp.InternalError("Failed to generate access token")
		return
	}

	refreshToken, err := h.authService.GenerateRefreshToken(user.ID.String())
	if err != nil {
		logrus.WithError(err).Error("Failed to generate refresh token")
		resp.InternalError("Failed to generate refresh token")
		return
	}

	// Update user's last login
	now := time.Now()
	user.LastLogin = &now
	h.db.Save(user)

	// Create response
	response := map[string]interface{}{
		"user_id":       user.ID.String(),
		"username":      user.Username,
		"email":         user.Email,
		"full_name":     user.FullName,
		"role":          string(user.Role),
		"access_token":  accessToken,
		"refresh_token": refreshToken,
		"expires_in":    24 * 60 * 60, // 24 hours in seconds
		"token_type":    "Bearer",
		"is_new_user":   isNewUser,
		"sso_source":    "keycloak",
	}

	resp.Success(response, "SSO authentication successful")
}

// ValidateToken validates JWT tokens for other services
func (h *AuthHandler) ValidateToken(c *gin.Context) {
	resp := utils.NewResponseHelper(c)

	var req types.TokenValidationRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		resp.BadRequest("Invalid request data", err.Error())
		return
	}

	// Validate the token
	claims, err := h.authService.ValidateToken(req.AccessToken)
	if err != nil {
		resp.Unauthorized("Invalid or expired token")
		return
	}

	// Get user from database
	var user models.User
	if err := h.db.Where("id = ? AND status = ?", claims.UserID, models.UserStatusActive).First(&user).Error; err != nil {
		resp.Unauthorized("User not found or inactive")
		return
	}

	// Return user information
	response := map[string]interface{}{
		"valid":     true,
		"user_id":   user.ID.String(),
		"username":  user.Username,
		"email":     user.Email,
		"full_name": user.FullName,
		"role":      string(user.Role),
		"expires_at": claims.ExpiresAt.Time,
	}

	resp.Success(response, "Token is valid")
}

// RefreshToken generates new access token using refresh token
func (h *AuthHandler) RefreshToken(c *gin.Context) {
	resp := utils.NewResponseHelper(c)

	var req types.TokenRefreshRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		resp.BadRequest("Invalid request data", err.Error())
		return
	}

	// Validate refresh token
	userID, err := h.authService.ValidateRefreshToken(req.RefreshToken)
	if err != nil {
		resp.Unauthorized("Invalid or expired refresh token")
		return
	}

	// Get user from database
	var user models.User
	if err := h.db.Where("id = ? AND status = ?", userID, models.UserStatusActive).First(&user).Error; err != nil {
		resp.Unauthorized("User not found or inactive")
		return
	}

	// Generate new access token
	accessToken, err := h.authService.GenerateToken(
		user.ID.String(),
		user.Username,
		user.Email,
		string(user.Role),
	)
	if err != nil {
		resp.InternalError("Failed to generate access token")
		return
	}

	response := map[string]interface{}{
		"access_token": accessToken,
		"expires_in":   24 * 60 * 60, // 24 hours in seconds
		"token_type":   "Bearer",
	}

	resp.Success(response, "Token refreshed successfully")
}

// Helper functions for SSO integration

func generateSecureState() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

func (h *AuthHandler) storeStateInSession(c *gin.Context, state string) {
	ctx := context.Background()
	ssoState := &cache.SSOState{
		State:       state,
		RedirectURL: c.Query("redirect_url"),
		Metadata: map[string]string{
			"ip":         c.ClientIP(),
			"user_agent": c.GetHeader("User-Agent"),
		},
	}
	
	// Store in Redis with 10 minutes expiration
	if err := h.sessionManager.StoreOAuthState(ctx, ssoState, 10*time.Minute); err != nil {
		logrus.WithError(err).Error("Failed to store OAuth state in Redis")
		// Fallback to cookie for backward compatibility
		c.SetCookie("sso_state", state, 600, "/", "", false, true)
	}
}

func (h *AuthHandler) validateStateFromSession(c *gin.Context, state string) bool {
	ctx := context.Background()
	
	// Try to validate from Redis first
	ssoState, err := h.sessionManager.ValidateAndConsumeOAuthState(ctx, state)
	if err == nil && ssoState != nil {
		// Log successful validation with metadata
		logrus.WithFields(logrus.Fields{
			"state":      state,
			"ip":         ssoState.Metadata["ip"],
			"user_agent": ssoState.Metadata["user_agent"],
		}).Info("OAuth state validated from Redis")
		return true
	}
	
	// Fallback to cookie validation
	storedState, err := c.Cookie("sso_state")
	if err != nil {
		logrus.WithError(err).Warn("Failed to validate OAuth state from both Redis and cookie")
		return false
	}
	
	// Clear the state cookie
	c.SetCookie("sso_state", "", -1, "/", "", false, true)
	
	if storedState == state {
		logrus.WithField("state", state).Info("OAuth state validated from cookie fallback")
		return true
	}
	
	return false
}

func (h *AuthHandler) exchangeCodeForTokens(code string) (*KeycloakTokenResponse, error) {
	tokenURL := fmt.Sprintf("%s/realms/%s/protocol/openid-connect/token", 
		h.config.KeycloakURL, h.config.KeycloakRealm)

	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("client_id", h.config.KeycloakClientID)
	data.Set("client_secret", h.config.KeycloakClientSecret)
	data.Set("code", code)
	data.Set("redirect_uri", h.config.KeycloakRedirectURI)

	req, err := http.NewRequest("POST", tokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("token exchange failed with status %d: %s", resp.StatusCode, string(body))
	}

	var tokenResp KeycloakTokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return nil, err
	}

	return &tokenResp, nil
}

func (h *AuthHandler) getUserInfoFromKeycloak(accessToken string) (*KeycloakUserInfo, error) {
	userInfoURL := fmt.Sprintf("%s/realms/%s/protocol/openid-connect/userinfo", 
		h.config.KeycloakURL, h.config.KeycloakRealm)

	req, err := http.NewRequest("GET", userInfoURL, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("userinfo request failed with status %d: %s", resp.StatusCode, string(body))
	}

	var userInfo KeycloakUserInfo
	if err := json.NewDecoder(resp.Body).Decode(&userInfo); err != nil {
		return nil, err
	}

	return &userInfo, nil
}

func (h *AuthHandler) findOrCreateUserFromSSO(userInfo *KeycloakUserInfo) (*models.User, bool, error) {
	// Try to find existing user by email
	var existingUser models.User
	err := h.db.Where("email = ?", userInfo.Email).First(&existingUser).Error

	if err == nil {
		// User exists, update SSO fields if needed
		if existingUser.FullName != userInfo.Name {
			existingUser.FullName = userInfo.Name
		}
		existingUser.EmailVerified = userInfo.EmailVerified
		h.db.Save(&existingUser)
		return &existingUser, false, nil
	}

	if err != gorm.ErrRecordNotFound {
		return nil, false, err
	}

	// Create new user from SSO
	username := h.generateUsernameFromEmail(userInfo.Email)

	newUser := &models.User{
		Username:      username,
		Email:         userInfo.Email,
		FullName:      userInfo.Name,
		Role:          models.UserRoleUser,
		Status:        models.UserStatusActive,
		EmailVerified: userInfo.EmailVerified,
		Password:      "", // No password for SSO users
	}

	if err := h.db.Create(newUser).Error; err != nil {
		return nil, false, err
	}

	return newUser, true, nil
}

func (h *AuthHandler) generateUsernameFromEmail(email string) string {
	username := strings.Split(email, "@")[0]
	username = strings.ReplaceAll(username, ".", "_")
	username = strings.ReplaceAll(username, "+", "_")

	// Check if username is available
	var count int64
	h.db.Model(&models.User{}).Where("username = ?", username).Count(&count)
	if count == 0 {
		return username
	}

	// Add suffix until unique
	for i := 1; i <= 100; i++ {
		candidate := fmt.Sprintf("%s_%d", username, i)
		h.db.Model(&models.User{}).Where("username = ?", candidate).Count(&count)
		if count == 0 {
			return candidate
		}
	}

	// Fallback to UUID suffix
	return username + "_" + uuid.New().String()[:8]
}

// Keycloak response types
type KeycloakTokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	Scope        string `json:"scope"`
}

type KeycloakUserInfo struct {
	Sub           string `json:"sub"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	Name          string `json:"name"`
	GivenName     string `json:"given_name"`
	FamilyName    string `json:"family_name"`
	Username      string `json:"preferred_username"`
	Plan          string `json:"plan,omitempty"`
	Role          string `json:"role,omitempty"`
}