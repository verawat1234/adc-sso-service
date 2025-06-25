package utils

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

// ResponseHelperTestSuite defines the test suite for response helper
type ResponseHelperTestSuite struct {
	suite.Suite
	router *gin.Engine
}

// SetupTest runs before each test
func (suite *ResponseHelperTestSuite) SetupTest() {
	gin.SetMode(gin.TestMode)
	suite.router = gin.New()
}

// TestResponseHelperTestSuite runs the test suite
func TestResponseHelperTestSuite(t *testing.T) {
	suite.Run(t, new(ResponseHelperTestSuite))
}

// Test Success response
func (suite *ResponseHelperTestSuite) TestSuccess() {
	suite.router.GET("/success", func(c *gin.Context) {
		resp := NewResponseHelper(c)
		resp.Success(map[string]string{"test": "data"}, "Operation successful")
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/success", nil)
	suite.router.ServeHTTP(w, req)

	assert.Equal(suite.T(), http.StatusOK, w.Code)
	assert.Equal(suite.T(), "application/json; charset=utf-8", w.Header().Get("Content-Type"))
	assert.Contains(suite.T(), w.Body.String(), `"success":true`)
	assert.Contains(suite.T(), w.Body.String(), `"message":"Operation successful"`)
	assert.Contains(suite.T(), w.Body.String(), `"test":"data"`)
}

// Test Success response with default message
func (suite *ResponseHelperTestSuite) TestSuccessDefaultMessage() {
	suite.router.GET("/success-default", func(c *gin.Context) {
		resp := NewResponseHelper(c)
		resp.Success(map[string]string{"test": "data"})
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/success-default", nil)
	suite.router.ServeHTTP(w, req)

	assert.Equal(suite.T(), http.StatusOK, w.Code)
	assert.Contains(suite.T(), w.Body.String(), `"message":"Success"`)
}

// Test BadRequest response
func (suite *ResponseHelperTestSuite) TestBadRequest() {
	suite.router.GET("/bad-request", func(c *gin.Context) {
		resp := NewResponseHelper(c)
		resp.BadRequest("Invalid input", "Email is required")
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/bad-request", nil)
	suite.router.ServeHTTP(w, req)

	assert.Equal(suite.T(), http.StatusBadRequest, w.Code)
	assert.Equal(suite.T(), "application/json; charset=utf-8", w.Header().Get("Content-Type"))
	assert.Contains(suite.T(), w.Body.String(), `"success":false`)
	assert.Contains(suite.T(), w.Body.String(), `"message":"Invalid input"`)
	assert.Contains(suite.T(), w.Body.String(), `"details":"Email is required"`)
}

// Test BadRequest response without details
func (suite *ResponseHelperTestSuite) TestBadRequestNoDetails() {
	suite.router.GET("/bad-request-no-details", func(c *gin.Context) {
		resp := NewResponseHelper(c)
		resp.BadRequest("Invalid input")
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/bad-request-no-details", nil)
	suite.router.ServeHTTP(w, req)

	assert.Equal(suite.T(), http.StatusBadRequest, w.Code)
	assert.Contains(suite.T(), w.Body.String(), `"message":"Invalid input"`)
	assert.NotContains(suite.T(), w.Body.String(), `"details"`)
}

// Test Unauthorized response
func (suite *ResponseHelperTestSuite) TestUnauthorized() {
	suite.router.GET("/unauthorized", func(c *gin.Context) {
		resp := NewResponseHelper(c)
		resp.Unauthorized("Authentication required")
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/unauthorized", nil)
	suite.router.ServeHTTP(w, req)

	assert.Equal(suite.T(), http.StatusUnauthorized, w.Code)
	assert.Equal(suite.T(), "application/json; charset=utf-8", w.Header().Get("Content-Type"))
	assert.Contains(suite.T(), w.Body.String(), `"success":false`)
	assert.Contains(suite.T(), w.Body.String(), `"message":"Authentication required"`)
}

// Test Forbidden response
func (suite *ResponseHelperTestSuite) TestForbidden() {
	suite.router.GET("/forbidden", func(c *gin.Context) {
		resp := NewResponseHelper(c)
		resp.Forbidden("Access denied")
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/forbidden", nil)
	suite.router.ServeHTTP(w, req)

	assert.Equal(suite.T(), http.StatusForbidden, w.Code)
	assert.Equal(suite.T(), "application/json; charset=utf-8", w.Header().Get("Content-Type"))
	assert.Contains(suite.T(), w.Body.String(), `"success":false`)
	assert.Contains(suite.T(), w.Body.String(), `"message":"Access denied"`)
}

// Test NotFound response
func (suite *ResponseHelperTestSuite) TestNotFound() {
	suite.router.GET("/not-found", func(c *gin.Context) {
		resp := NewResponseHelper(c)
		resp.NotFound("Resource not found")
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/not-found", nil)
	suite.router.ServeHTTP(w, req)

	assert.Equal(suite.T(), http.StatusNotFound, w.Code)
	assert.Equal(suite.T(), "application/json; charset=utf-8", w.Header().Get("Content-Type"))
	assert.Contains(suite.T(), w.Body.String(), `"success":false`)
	assert.Contains(suite.T(), w.Body.String(), `"message":"Resource not found"`)
}

// Test Conflict response
func (suite *ResponseHelperTestSuite) TestConflict() {
	suite.router.GET("/conflict", func(c *gin.Context) {
		resp := NewResponseHelper(c)
		resp.Conflict("Resource already exists")
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/conflict", nil)
	suite.router.ServeHTTP(w, req)

	assert.Equal(suite.T(), http.StatusConflict, w.Code)
	assert.Equal(suite.T(), "application/json; charset=utf-8", w.Header().Get("Content-Type"))
	assert.Contains(suite.T(), w.Body.String(), `"success":false`)
	assert.Contains(suite.T(), w.Body.String(), `"message":"Resource already exists"`)
}

// Test InternalError response
func (suite *ResponseHelperTestSuite) TestInternalError() {
	suite.router.GET("/internal-error", func(c *gin.Context) {
		resp := NewResponseHelper(c)
		resp.InternalError("Internal server error")
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/internal-error", nil)
	suite.router.ServeHTTP(w, req)

	assert.Equal(suite.T(), http.StatusInternalServerError, w.Code)
	assert.Equal(suite.T(), "application/json; charset=utf-8", w.Header().Get("Content-Type"))
	assert.Contains(suite.T(), w.Body.String(), `"success":false`)
	assert.Contains(suite.T(), w.Body.String(), `"message":"Internal server error"`)
}

// Test response helper with various data types
func (suite *ResponseHelperTestSuite) TestSuccessWithVariousDataTypes() {
	// Test with string data
	suite.router.GET("/string-data", func(c *gin.Context) {
		resp := NewResponseHelper(c)
		resp.Success("simple string")
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/string-data", nil)
	suite.router.ServeHTTP(w, req)

	assert.Equal(suite.T(), http.StatusOK, w.Code)
	assert.Contains(suite.T(), w.Body.String(), `"data":"simple string"`)

	// Test with array data
	suite.router.GET("/array-data", func(c *gin.Context) {
		resp := NewResponseHelper(c)
		resp.Success([]string{"item1", "item2", "item3"})
	})

	w = httptest.NewRecorder()
	req = httptest.NewRequest("GET", "/array-data", nil)
	suite.router.ServeHTTP(w, req)

	assert.Equal(suite.T(), http.StatusOK, w.Code)
	assert.Contains(suite.T(), w.Body.String(), `"data":["item1","item2","item3"]`)

	// Test with nil data
	suite.router.GET("/nil-data", func(c *gin.Context) {
		resp := NewResponseHelper(c)
		resp.Success(nil)
	})

	w = httptest.NewRecorder()
	req = httptest.NewRequest("GET", "/nil-data", nil)
	suite.router.ServeHTTP(w, req)

	assert.Equal(suite.T(), http.StatusOK, w.Code)
	assert.Contains(suite.T(), w.Body.String(), `"data":null`)
}

// Test response consistency
func (suite *ResponseHelperTestSuite) TestResponseConsistency() {
	// All error responses should have consistent structure
	errorRoutes := []struct {
		path   string
		status int
		method func(*ResponseHelper)
	}{
		{"/bad-request", http.StatusBadRequest, func(r *ResponseHelper) { r.BadRequest("test") }},
		{"/unauthorized", http.StatusUnauthorized, func(r *ResponseHelper) { r.Unauthorized("test") }},
		{"/forbidden", http.StatusForbidden, func(r *ResponseHelper) { r.Forbidden("test") }},
		{"/not-found", http.StatusNotFound, func(r *ResponseHelper) { r.NotFound("test") }},
		{"/conflict", http.StatusConflict, func(r *ResponseHelper) { r.Conflict("test") }},
		{"/internal-error", http.StatusInternalServerError, func(r *ResponseHelper) { r.InternalError("test") }},
	}

	for _, route := range errorRoutes {
		suite.router.GET(route.path, func(c *gin.Context) {
			resp := NewResponseHelper(c)
			route.method(resp)
		})

		w := httptest.NewRecorder()
		req := httptest.NewRequest("GET", route.path, nil)
		suite.router.ServeHTTP(w, req)

		assert.Equal(suite.T(), route.status, w.Code, "Status code mismatch for %s", route.path)
		assert.Equal(suite.T(), "application/json; charset=utf-8", w.Header().Get("Content-Type"))
		assert.Contains(suite.T(), w.Body.String(), `"success":false`, "Error response should have success:false for %s", route.path)
		assert.Contains(suite.T(), w.Body.String(), `"message":"test"`, "Error response should have message for %s", route.path)
	}
}

// Test response helper creation
func (suite *ResponseHelperTestSuite) TestNewResponseHelper() {
	suite.router.GET("/test-creation", func(c *gin.Context) {
		resp := NewResponseHelper(c)
		assert.NotNil(suite.T(), resp)
		assert.Equal(suite.T(), c, resp.c)
		resp.Success("test")
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/test-creation", nil)
	suite.router.ServeHTTP(w, req)

	assert.Equal(suite.T(), http.StatusOK, w.Code)
}

// Test multiple response calls (first status code is preserved in Gin)
func (suite *ResponseHelperTestSuite) TestMultipleResponseCalls() {
	suite.router.GET("/multiple-calls", func(c *gin.Context) {
		resp := NewResponseHelper(c)
		resp.Success("first call")
		// Note: In practice, you shouldn't call multiple response methods
		// This test just verifies the behavior when it happens
		resp.InternalError("second call")
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/multiple-calls", nil)
	suite.router.ServeHTTP(w, req)

	// First status code is preserved in Gin
	assert.Equal(suite.T(), http.StatusOK, w.Code)
	// Both responses will be in the body
	assert.Contains(suite.T(), w.Body.String(), "first call")
	assert.Contains(suite.T(), w.Body.String(), "second call")
}

// Test edge cases with empty messages
func (suite *ResponseHelperTestSuite) TestEmptyMessages() {
	suite.router.GET("/empty-message", func(c *gin.Context) {
		resp := NewResponseHelper(c)
		resp.BadRequest("") // Empty message
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/empty-message", nil)
	suite.router.ServeHTTP(w, req)

	assert.Equal(suite.T(), http.StatusBadRequest, w.Code)
	assert.Contains(suite.T(), w.Body.String(), `"message":""`)
}

// Test concurrent response helper usage
func (suite *ResponseHelperTestSuite) TestConcurrentUsage() {
	suite.router.GET("/concurrent", func(c *gin.Context) {
		resp := NewResponseHelper(c)
		resp.Success("concurrent test")
	})

	numRequests := 10
	results := make(chan int, numRequests)

	// Make concurrent requests
	for i := 0; i < numRequests; i++ {
		go func() {
			w := httptest.NewRecorder()
			req := httptest.NewRequest("GET", "/concurrent", nil)
			suite.router.ServeHTTP(w, req)
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
	assert.Equal(suite.T(), numRequests, successCount)
}