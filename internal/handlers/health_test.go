package handlers

import (
	"net/http"
	"testing"

	"adc-sso-service/internal/testutils"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/suite"
	"gorm.io/gorm"
)

// HealthHandlerTestSuite defines the test suite for health handler
type HealthHandlerTestSuite struct {
	suite.Suite
	db      *gorm.DB
	handler *HealthHandler
	router  *gin.Engine
}

// SetupTest runs before each test
func (suite *HealthHandlerTestSuite) SetupTest() {
	gin.SetMode(gin.TestMode)
	
	// Setup test database
	suite.db = testutils.SetupTestDB(suite.T())
	
	// Create health handler
	suite.handler = NewHealthHandler(suite.db)
	
	// Setup router
	suite.router = gin.New()
	suite.router.GET("/health", suite.handler.Health)
}

// TearDownTest runs after each test
func (suite *HealthHandlerTestSuite) TearDownTest() {
	testutils.CleanupTestDB(suite.T(), suite.db)
}

// TestHealthHandlerTestSuite runs the test suite
func TestHealthHandlerTestSuite(t *testing.T) {
	suite.Run(t, new(HealthHandlerTestSuite))
}

// Test health endpoint with healthy database
func (suite *HealthHandlerTestSuite) TestHealth_Healthy() {
	w := testutils.PerformRequest(suite.router, "GET", "/health", nil, nil)

	response := testutils.AssertJSONResponse(suite.T(), w, http.StatusOK, 
		"status", "service", "version", "database", "timestamp")

	suite.Equal("healthy", response["status"])
	suite.Equal("ADC SSO Service", response["service"])
	suite.Equal("1.0.0", response["version"])
	suite.Equal("connected", response["database"])
	suite.NotNil(response["timestamp"])
}

// Test health endpoint response format
func (suite *HealthHandlerTestSuite) TestHealth_ResponseFormat() {
	w := testutils.PerformRequest(suite.router, "GET", "/health", nil, nil)

	suite.Equal(http.StatusOK, w.Code)
	suite.Equal("application/json; charset=utf-8", w.Header().Get("Content-Type"))

	response, err := testutils.ParseJSONResponse(w)
	suite.NoError(err)

	// Verify all required fields are present
	requiredFields := []string{"status", "service", "version", "database", "timestamp"}
	for _, field := range requiredFields {
		suite.Contains(response, field, "Response should contain field: %s", field)
	}

	// Verify field types and values
	suite.IsType("", response["status"])
	suite.IsType("", response["service"])
	suite.IsType("", response["version"])
	suite.IsType("", response["database"])
	suite.NotNil(response["timestamp"])
}

// Test health endpoint with multiple concurrent requests
func (suite *HealthHandlerTestSuite) TestHealth_ConcurrentRequests() {
	numRequests := 10
	results := make(chan int, numRequests)

	// Make concurrent requests
	for i := 0; i < numRequests; i++ {
		go func() {
			w := testutils.PerformRequest(suite.router, "GET", "/health", nil, nil)
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
	suite.Equal(numRequests, successCount, "All concurrent health checks should succeed")
}

// Test health endpoint performance
func (suite *HealthHandlerTestSuite) TestHealth_Performance() {
	// Make multiple requests to check performance consistency
	iterations := 50
	for i := 0; i < iterations; i++ {
		w := testutils.PerformRequest(suite.router, "GET", "/health", nil, nil)
		suite.Equal(http.StatusOK, w.Code, "Health check %d should succeed", i+1)
	}
}

// Note: Testing database connection failure would require more complex setup
// to simulate database disconnection, which is difficult with in-memory SQLite.
// In a real environment, you might use test containers or mock the database connection.