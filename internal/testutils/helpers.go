package testutils

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"adc-sso-service/internal/auth"
	"adc-sso-service/internal/config"
	"adc-sso-service/internal/models"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"gorm.io/gorm"
)

// TestContext holds common test dependencies
type TestContext struct {
	DB            *gorm.DB
	AuthService   *auth.AuthService
	Config        *config.Config
	MockKeycloak  *MockKeycloakServer
	Router        *gin.Engine
	Cleanup       func()
}

// SetupTestContext creates a basic test context with database and auth
func SetupTestContext(t *testing.T) *TestContext {
	// Set Gin to test mode
	gin.SetMode(gin.TestMode)
	
	// Setup test database
	db := SetupTestDB(t)
	
	// Setup mock Keycloak server
	mockKeycloak := NewMockKeycloakServer()
	
	// Create test config with mock Keycloak URL
	cfg := &config.Config{
		Port:                 "9000",
		DatabaseURL:          "sqlite://memory",
		JWTSecret:            "test-jwt-secret-key",
		KeycloakURL:          mockKeycloak.GetURL(),
		KeycloakRealm:        "adc-brandkit",
		KeycloakClientID:     "adc-brandkit-app",
		KeycloakClientSecret: "test-client-secret",
		KeycloakRedirectURI:  "http://localhost:3000/auth/sso/callback",
		FrontendURL:          "http://localhost:3000",
		AllowedOrigins:       []string{"http://localhost:3000"},
	}
	
	// Create auth service
	authService := auth.NewAuthService(cfg.JWTSecret)
	
	ctx := &TestContext{
		DB:           db,
		AuthService:  authService,
		Config:       cfg,
		MockKeycloak: mockKeycloak,
		Router:       nil, // Router will be set up in individual tests
		Cleanup: func() {
			mockKeycloak.Close()
			CleanupTestDB(t, db)
		},
	}
	
	return ctx
}

// PerformRequest executes an HTTP request against the test router
func PerformRequest(router *gin.Engine, method, path string, body interface{}, headers map[string]string) *httptest.ResponseRecorder {
	var req *http.Request
	
	if body != nil {
		jsonBody, _ := json.Marshal(body)
		req = httptest.NewRequest(method, path, bytes.NewBuffer(jsonBody))
		req.Header.Set("Content-Type", "application/json")
	} else {
		req = httptest.NewRequest(method, path, nil)
	}
	
	// Add custom headers
	for key, value := range headers {
		req.Header.Set(key, value)
	}
	
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	
	return w
}

// AuthenticatedRequest creates a request with a valid JWT token
func AuthenticatedRequest(ctx *TestContext, user *models.User, method, path string, body interface{}) *httptest.ResponseRecorder {
	token, _ := ctx.AuthService.GenerateToken(
		user.ID.String(),
		user.Username,
		user.Email,
		string(user.Role),
	)
	
	headers := map[string]string{
		"Authorization": "Bearer " + token,
	}
	
	return PerformRequest(ctx.Router, method, path, body, headers)
}

// APIKeyRequest creates a request with a valid API key
func APIKeyRequest(ctx *TestContext, apiKey *models.APIKey, method, path string, body interface{}) *httptest.ResponseRecorder {
	headers := map[string]string{
		"X-API-Key": apiKey.KeyHash, // Use stored full key from fixture
	}
	
	return PerformRequest(ctx.Router, method, path, body, headers)
}

// AssertJSONResponse asserts response status and JSON structure
func AssertJSONResponse(t *testing.T, w *httptest.ResponseRecorder, expectedStatus int, expectedKeys ...string) map[string]interface{} {
	assert.Equal(t, expectedStatus, w.Code)
	assert.Equal(t, "application/json; charset=utf-8", w.Header().Get("Content-Type"))
	
	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	
	for _, key := range expectedKeys {
		assert.Contains(t, response, key, fmt.Sprintf("Response should contain key: %s", key))
	}
	
	return response
}

// AssertErrorResponse asserts an error response with expected message
func AssertErrorResponse(t *testing.T, w *httptest.ResponseRecorder, expectedStatus int, expectedMessage string) {
	response := AssertJSONResponse(t, w, expectedStatus, "error")
	
	if expectedMessage != "" {
		assert.Contains(t, response["error"], expectedMessage)
	}
}

// AssertSuccessResponse asserts a successful response
func AssertSuccessResponse(t *testing.T, w *httptest.ResponseRecorder, dataKeys ...string) map[string]interface{} {
	response := AssertJSONResponse(t, w, http.StatusOK)
	
	for _, key := range dataKeys {
		assert.Contains(t, response, key)
	}
	
	return response
}

// CreateTestJWT creates a test JWT token for a user
func CreateTestJWT(authService *auth.AuthService, userID, username, email, role string) string {
	token, _ := authService.GenerateToken(userID, username, email, role)
	return token
}

// CreateExpiredJWT creates an expired JWT token for testing
func CreateExpiredJWT(authService *auth.AuthService, userID string) string {
	// Create a token with past expiration
	userCtx := &auth.UserContext{
		UserID:   userID,
		Username: "test",
		Email:    "test@example.com",
		Role:     "user",
	}
	
	// This would need modification to auth service to support custom expiration
	token, _ := authService.GenerateTokenWithContext(userCtx)
	return token
}

// GenerateTestState generates a test state parameter for SSO
func GenerateTestState() string {
	return uuid.New().String()
}

// MockJSONRequest creates a mock JSON request body
func MockJSONRequest(data interface{}) *bytes.Buffer {
	jsonData, _ := json.Marshal(data)
	return bytes.NewBuffer(jsonData)
}

// ParseJSONResponse parses a JSON response into a map
func ParseJSONResponse(w *httptest.ResponseRecorder) (map[string]interface{}, error) {
	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	return response, err
}

// AssertDatabaseState asserts that database records exist
func AssertDatabaseState(t *testing.T, db *gorm.DB, model interface{}, conditions map[string]interface{}, shouldExist bool) {
	query := db.Model(model)
	for field, value := range conditions {
		query = query.Where(fmt.Sprintf("%s = ?", field), value)
	}
	
	var count int64
	query.Count(&count)
	
	if shouldExist {
		assert.Greater(t, count, int64(0), "Expected record to exist in database")
	} else {
		assert.Equal(t, int64(0), count, "Expected record to not exist in database")
	}
}