package handlers

import (
	"encoding/json"
	"net/http"
	"net/url"
	"testing"

	"adc-sso-service/internal/auth"
	"adc-sso-service/internal/config"
	"adc-sso-service/internal/models"
	"adc-sso-service/internal/testutils"
	"adc-sso-service/internal/types"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/suite"
	"gorm.io/gorm"
)

// AuthHandlerTestSuite defines the test suite for auth handler
type AuthHandlerTestSuite struct {
	suite.Suite
	db           *gorm.DB
	authService  *auth.AuthService
	config       *config.Config
	handler      *AuthHandler
	router       *gin.Engine
	mockKeycloak *testutils.MockKeycloakServer
	testUser     *models.User
}

// SetupTest runs before each test
func (suite *AuthHandlerTestSuite) SetupTest() {
	gin.SetMode(gin.TestMode)
	
	// Setup test database
	suite.db = testutils.SetupTestDB(suite.T())
	
	// Setup mock Keycloak server
	suite.mockKeycloak = testutils.NewMockKeycloakServer()
	
	// Create test config with mock Keycloak URL
	suite.config = &config.Config{
		JWTSecret:            "test-jwt-secret",
		KeycloakURL:          suite.mockKeycloak.GetURL(),
		KeycloakRealm:        "adc-brandkit",
		KeycloakClientID:     "adc-brandkit-app",
		KeycloakClientSecret: "test-client-secret",
		KeycloakRedirectURI:  "http://localhost:3000/auth/sso/callback",
		FrontendURL:          "http://localhost:3000",
	}
	
	// Create auth service
	suite.authService = auth.NewAuthService(suite.config.JWTSecret)
	
	// Create auth handler
	suite.handler = NewAuthHandler(suite.db, suite.authService, suite.config)
	
	// Setup router
	suite.router = gin.New()
	suite.router.GET("/sso/login", suite.handler.RedirectToSSO)
	suite.router.GET("/sso/callback", suite.handler.HandleSSOCallback)
	suite.router.POST("/sso/validate", suite.handler.ValidateToken)
	suite.router.POST("/sso/refresh", suite.handler.RefreshToken)
	
	// Create test user
	suite.testUser = testutils.CreateTestRegularUser(suite.db)
}

// TearDownTest runs after each test
func (suite *AuthHandlerTestSuite) TearDownTest() {
	suite.mockKeycloak.Close()
	testutils.CleanupTestDB(suite.T(), suite.db)
}

// TestAuthHandlerTestSuite runs the test suite
func TestAuthHandlerTestSuite(t *testing.T) {
	suite.Run(t, new(AuthHandlerTestSuite))
}

// Test SSO redirect URL generation
func (suite *AuthHandlerTestSuite) TestRedirectToSSO_Success() {
	w := testutils.PerformRequest(suite.router, "GET", "/sso/login", nil, nil)

	response := testutils.AssertSuccessResponse(suite.T(), w, "data")
	
	data, ok := response["data"].(map[string]interface{})
	suite.True(ok, "Data should be a map")
	suite.Contains(data, "redirect_url")
	suite.Contains(data, "state")

	// Verify redirect URL format
	redirectURL, ok := data["redirect_url"].(string)
	suite.True(ok, "redirect_url should be a string")
	
	parsedURL, err := url.Parse(redirectURL)
	suite.NoError(err)
	
	suite.Equal(suite.mockKeycloak.GetURL(), parsedURL.Scheme+"://"+parsedURL.Host)
	suite.Contains(parsedURL.Path, "/realms/adc-brandkit/protocol/openid-connect/auth")
	
	// Verify query parameters
	query := parsedURL.Query()
	suite.Equal("adc-brandkit-app", query.Get("client_id"))
	suite.Equal("code", query.Get("response_type"))
	suite.Equal("openid email profile", query.Get("scope"))
	suite.NotEmpty(query.Get("state"))
}

// Test SSO callback with valid code
func (suite *AuthHandlerTestSuite) TestHandleSSOCallback_Success() {
	// First, generate a state by calling login endpoint
	loginW := testutils.PerformRequest(suite.router, "GET", "/sso/login", nil, nil)
	loginResponse := testutils.AssertSuccessResponse(suite.T(), loginW, "data")
	
	data := loginResponse["data"].(map[string]interface{})
	state := data["state"].(string)

	// Mock successful Keycloak responses
	suite.mockKeycloak.Reset()
	suite.mockKeycloak.SetUserInfo(map[string]interface{}{
		"sub":             "keycloak-user-123",
		"email":           "newuser@example.com",
		"email_verified":  true,
		"name":            "New User",
		"given_name":      "New",
		"family_name":     "User",
		"preferred_username": "newuser",
	})

	// Prepare callback request
	callbackURL := "/sso/callback?code=test_code&state=" + state
	
	// Set the state cookie (simulating browser behavior)
	headers := map[string]string{
		"Cookie": "sso_state=" + state,
	}
	
	w := testutils.PerformRequest(suite.router, "GET", callbackURL, nil, headers)

	response := testutils.AssertSuccessResponse(suite.T(), w, "data")
	
	data = response["data"].(map[string]interface{})
	suite.Contains(data, "user_id")
	suite.Contains(data, "username")
	suite.Contains(data, "email")
	suite.Contains(data, "access_token")
	suite.Contains(data, "refresh_token")
	suite.Contains(data, "is_new_user")
	suite.Contains(data, "sso_source")

	suite.Equal("newuser@example.com", data["email"])
	suite.Equal("keycloak", data["sso_source"])
	suite.Equal(true, data["is_new_user"])

	// Verify user was created in database
	var user models.User
	err := suite.db.Where("email = ?", "newuser@example.com").First(&user).Error
	suite.NoError(err)
	suite.Equal("New User", user.FullName)
	suite.True(user.EmailVerified)

	// Verify Keycloak endpoints were called
	suite.True(suite.mockKeycloak.TokenEndpointCalled)
	suite.True(suite.mockKeycloak.UserInfoEndpointCalled)
}

// Test SSO callback with existing user
func (suite *AuthHandlerTestSuite) TestHandleSSOCallback_ExistingUser() {
	// First, generate a state by calling login endpoint
	loginW := testutils.PerformRequest(suite.router, "GET", "/sso/login", nil, nil)
	loginResponse := testutils.AssertSuccessResponse(suite.T(), loginW, "data")
	
	data := loginResponse["data"].(map[string]interface{})
	state := data["state"].(string)

	// Mock Keycloak response with existing user's email
	suite.mockKeycloak.Reset()
	suite.mockKeycloak.SetUserInfo(map[string]interface{}{
		"sub":             "keycloak-user-123",
		"email":           suite.testUser.Email,
		"email_verified":  true,
		"name":            "Updated Name",
		"given_name":      "Updated",
		"family_name":     "Name",
		"preferred_username": suite.testUser.Username,
	})

	callbackURL := "/sso/callback?code=test_code&state=" + state
	headers := map[string]string{
		"Cookie": "sso_state=" + state,
	}
	
	w := testutils.PerformRequest(suite.router, "GET", callbackURL, nil, headers)

	response := testutils.AssertSuccessResponse(suite.T(), w, "data")
	
	data = response["data"].(map[string]interface{})
	suite.Equal(suite.testUser.Email, data["email"])
	suite.Equal(false, data["is_new_user"])

	// Verify user was updated in database
	var user models.User
	err := suite.db.First(&user, suite.testUser.ID).Error
	suite.NoError(err)
	suite.Equal("Updated Name", user.FullName)
}

// Test SSO callback with missing code
func (suite *AuthHandlerTestSuite) TestHandleSSOCallback_MissingCode() {
	w := testutils.PerformRequest(suite.router, "GET", "/sso/callback?state=test", nil, nil)

	testutils.AssertErrorResponse(suite.T(), w, http.StatusBadRequest, "Missing required callback parameters")
}

// Test SSO callback with invalid state
func (suite *AuthHandlerTestSuite) TestHandleSSOCallback_InvalidState() {
	callbackURL := "/sso/callback?code=test_code&state=invalid_state"
	
	w := testutils.PerformRequest(suite.router, "GET", callbackURL, nil, nil)

	testutils.AssertErrorResponse(suite.T(), w, http.StatusBadRequest, "Invalid or expired authentication state")
}

// Test SSO callback with Keycloak error
func (suite *AuthHandlerTestSuite) TestHandleSSOCallback_KeycloakError() {
	w := testutils.PerformRequest(suite.router, "GET", "/sso/callback?error=access_denied", nil, nil)

	testutils.AssertErrorResponse(suite.T(), w, http.StatusBadRequest, "SSO authentication failed")
}

// Test SSO callback with Keycloak token exchange failure
func (suite *AuthHandlerTestSuite) TestHandleSSOCallback_TokenExchangeFailure() {
	// Generate state
	loginW := testutils.PerformRequest(suite.router, "GET", "/sso/login", nil, nil)
	loginResponse := testutils.AssertSuccessResponse(suite.T(), loginW, "data")
	
	data := loginResponse["data"].(map[string]interface{})
	state := data["state"].(string)

	// Configure mock to return error
	suite.mockKeycloak.SetError(http.StatusBadRequest, "Invalid authorization code")

	callbackURL := "/sso/callback?code=invalid_code&state=" + state
	headers := map[string]string{
		"Cookie": "sso_state=" + state,
	}
	
	w := testutils.PerformRequest(suite.router, "GET", callbackURL, nil, headers)

	testutils.AssertErrorResponse(suite.T(), w, http.StatusInternalServerError, "Failed to complete SSO authentication")
}

// Test token validation with valid token
func (suite *AuthHandlerTestSuite) TestValidateToken_Success() {
	// Generate a valid token
	token, err := suite.authService.GenerateToken(
		suite.testUser.ID.String(),
		suite.testUser.Username,
		suite.testUser.Email,
		string(suite.testUser.Role),
	)
	suite.NoError(err)

	reqBody := types.TokenValidationRequest{
		AccessToken: token,
	}

	w := testutils.PerformRequest(suite.router, "POST", "/sso/validate", reqBody, nil)

	response := testutils.AssertSuccessResponse(suite.T(), w, "data")
	
	data := response["data"].(map[string]interface{})
	suite.Contains(data, "valid")
	suite.Contains(data, "user_id")
	suite.Contains(data, "username")
	suite.Contains(data, "email")
	suite.Contains(data, "role")

	suite.Equal(true, data["valid"])
	suite.Equal(suite.testUser.ID.String(), data["user_id"])
	suite.Equal(suite.testUser.Email, data["email"])
}

// Test token validation with invalid token
func (suite *AuthHandlerTestSuite) TestValidateToken_InvalidToken() {
	reqBody := types.TokenValidationRequest{
		AccessToken: "invalid.jwt.token",
	}

	w := testutils.PerformRequest(suite.router, "POST", "/sso/validate", reqBody, nil)

	testutils.AssertErrorResponse(suite.T(), w, http.StatusUnauthorized, "Invalid or expired token")
}

// Test token validation with missing token
func (suite *AuthHandlerTestSuite) TestValidateToken_MissingToken() {
	reqBody := types.TokenValidationRequest{
		AccessToken: "",
	}

	w := testutils.PerformRequest(suite.router, "POST", "/sso/validate", reqBody, nil)

	testutils.AssertErrorResponse(suite.T(), w, http.StatusBadRequest, "")
}

// Test token validation with inactive user
func (suite *AuthHandlerTestSuite) TestValidateToken_InactiveUser() {
	// Deactivate user
	suite.testUser.Status = models.UserStatusInactive
	suite.db.Save(suite.testUser)

	token, err := suite.authService.GenerateToken(
		suite.testUser.ID.String(),
		suite.testUser.Username,
		suite.testUser.Email,
		string(suite.testUser.Role),
	)
	suite.NoError(err)

	reqBody := types.TokenValidationRequest{
		AccessToken: token,
	}

	w := testutils.PerformRequest(suite.router, "POST", "/sso/validate", reqBody, nil)

	testutils.AssertErrorResponse(suite.T(), w, http.StatusUnauthorized, "User not found or inactive")
}

// Test refresh token functionality
func (suite *AuthHandlerTestSuite) TestRefreshToken_Success() {
	// Generate refresh token
	refreshToken, err := suite.authService.GenerateRefreshToken(suite.testUser.ID.String())
	suite.NoError(err)

	reqBody := types.TokenRefreshRequest{
		RefreshToken: refreshToken,
	}

	w := testutils.PerformRequest(suite.router, "POST", "/sso/refresh", reqBody, nil)

	response := testutils.AssertSuccessResponse(suite.T(), w, "data")
	
	data := response["data"].(map[string]interface{})
	suite.Contains(data, "access_token")
	suite.Contains(data, "expires_in")
	suite.Contains(data, "token_type")

	suite.Equal("Bearer", data["token_type"])
	suite.Equal(float64(24*60*60), data["expires_in"]) // JSON numbers are float64

	// Verify new access token is valid
	newToken := data["access_token"].(string)
	claims, err := suite.authService.ValidateToken(newToken)
	suite.NoError(err)
	suite.Equal(suite.testUser.ID.String(), claims.UserID)
}

// Test refresh token with invalid token
func (suite *AuthHandlerTestSuite) TestRefreshToken_InvalidToken() {
	reqBody := types.TokenRefreshRequest{
		RefreshToken: "invalid.refresh.token",
	}

	w := testutils.PerformRequest(suite.router, "POST", "/sso/refresh", reqBody, nil)

	testutils.AssertErrorResponse(suite.T(), w, http.StatusUnauthorized, "Invalid or expired refresh token")
}

// Test refresh token with inactive user
func (suite *AuthHandlerTestSuite) TestRefreshToken_InactiveUser() {
	// Generate refresh token before deactivating user
	refreshToken, err := suite.authService.GenerateRefreshToken(suite.testUser.ID.String())
	suite.NoError(err)

	// Deactivate user
	suite.testUser.Status = models.UserStatusInactive
	suite.db.Save(suite.testUser)

	reqBody := types.TokenRefreshRequest{
		RefreshToken: refreshToken,
	}

	w := testutils.PerformRequest(suite.router, "POST", "/sso/refresh", reqBody, nil)

	testutils.AssertErrorResponse(suite.T(), w, http.StatusUnauthorized, "User not found or inactive")
}

// Test concurrent SSO login requests
func (suite *AuthHandlerTestSuite) TestConcurrentSSOLogin() {
	numRequests := 10
	results := make(chan int, numRequests)

	// Make concurrent requests
	for i := 0; i < numRequests; i++ {
		go func() {
			w := testutils.PerformRequest(suite.router, "GET", "/sso/login", nil, nil)
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

// Test malformed JSON in validation request
func (suite *AuthHandlerTestSuite) TestValidateToken_MalformedJSON() {
	w := testutils.PerformRequest(suite.router, "POST", "/sso/validate", "invalid json", nil)

	testutils.AssertErrorResponse(suite.T(), w, http.StatusBadRequest, "")
}

// Test state parameter generation uniqueness
func (suite *AuthHandlerTestSuite) TestSSOStateUniqueness() {
	states := make(map[string]bool)
	numRequests := 100

	for i := 0; i < numRequests; i++ {
		w := testutils.PerformRequest(suite.router, "GET", "/sso/login", nil, nil)
		response := testutils.AssertSuccessResponse(suite.T(), w, "data")
		
		data := response["data"].(map[string]interface{})
		state := data["state"].(string)
		
		suite.False(states[state], "State parameter should be unique")
		states[state] = true
		suite.NotEmpty(state, "State parameter should not be empty")
	}
}