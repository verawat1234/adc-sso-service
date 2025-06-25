package testutils

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
)

// MockKeycloakServer creates a mock Keycloak server for testing SSO flows
type MockKeycloakServer struct {
	*httptest.Server
	TokenEndpointCalled    bool
	UserInfoEndpointCalled bool
	LastTokenRequest       map[string]string
	MockUserInfo           map[string]interface{}
	MockTokenResponse      map[string]interface{}
	ShouldReturnError      bool
	ErrorCode              int
	ErrorMessage           string
}

// NewMockKeycloakServer creates a new mock Keycloak server
func NewMockKeycloakServer() *MockKeycloakServer {
	mock := &MockKeycloakServer{
		MockUserInfo: map[string]interface{}{
			"sub":             "keycloak-user-123",
			"email":           "test@example.com",
			"email_verified":  true,
			"name":            "Test User",
			"given_name":      "Test",
			"family_name":     "User",
			"preferred_username": "testuser",
		},
		MockTokenResponse: map[string]interface{}{
			"access_token":  "mock_access_token_12345",
			"token_type":    "Bearer",
			"expires_in":    3600,
			"refresh_token": "mock_refresh_token_12345",
			"scope":         "openid email profile",
		},
	}

	mux := http.NewServeMux()
	
	// Token endpoint - handles authorization code exchange
	mux.HandleFunc("/realms/adc-brandkit/protocol/openid-connect/token", func(w http.ResponseWriter, r *http.Request) {
		mock.TokenEndpointCalled = true
		
		if mock.ShouldReturnError {
			w.WriteHeader(mock.ErrorCode)
			json.NewEncoder(w).Encode(map[string]string{
				"error":             "invalid_grant",
				"error_description": mock.ErrorMessage,
			})
			return
		}
		
		// Parse form data
		r.ParseForm()
		mock.LastTokenRequest = map[string]string{
			"grant_type":    r.FormValue("grant_type"),
			"client_id":     r.FormValue("client_id"),
			"client_secret": r.FormValue("client_secret"),
			"code":          r.FormValue("code"),
			"redirect_uri":  r.FormValue("redirect_uri"),
		}
		
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(mock.MockTokenResponse)
	})
	
	// UserInfo endpoint - returns user information
	mux.HandleFunc("/realms/adc-brandkit/protocol/openid-connect/userinfo", func(w http.ResponseWriter, r *http.Request) {
		mock.UserInfoEndpointCalled = true
		
		if mock.ShouldReturnError {
			w.WriteHeader(mock.ErrorCode)
			json.NewEncoder(w).Encode(map[string]string{
				"error":             "invalid_token",
				"error_description": mock.ErrorMessage,
			})
			return
		}
		
		// Check Authorization header
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "unauthorized",
			})
			return
		}
		
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(mock.MockUserInfo)
	})
	
	// Health endpoint
	mux.HandleFunc("/health/ready", func(w http.ResponseWriter, r *http.Request) {
		if mock.ShouldReturnError {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})
	
	// Authorization endpoint (for generating redirect URLs)
	mux.HandleFunc("/realms/adc-brandkit/protocol/openid-connect/auth", func(w http.ResponseWriter, r *http.Request) {
		// This would normally show login form, but for testing we'll just return success
		query := r.URL.Query()
		redirectURI := query.Get("redirect_uri")
		state := query.Get("state")
		
		if redirectURI != "" {
			// Simulate successful login by redirecting back with a code
			callbackURL, _ := url.Parse(redirectURI)
			callbackQuery := callbackURL.Query()
			callbackQuery.Set("code", "mock_authorization_code_12345")
			callbackQuery.Set("state", state)
			callbackURL.RawQuery = callbackQuery.Encode()
			
			http.Redirect(w, r, callbackURL.String(), http.StatusFound)
			return
		}
		
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Mock Keycloak Auth Page"))
	})

	mock.Server = httptest.NewServer(mux)
	return mock
}

// SetUserInfo updates the mock user info response
func (m *MockKeycloakServer) SetUserInfo(userInfo map[string]interface{}) {
	m.MockUserInfo = userInfo
}

// SetTokenResponse updates the mock token response
func (m *MockKeycloakServer) SetTokenResponse(tokenResp map[string]interface{}) {
	m.MockTokenResponse = tokenResp
}

// SetError configures the mock to return an error
func (m *MockKeycloakServer) SetError(code int, message string) {
	m.ShouldReturnError = true
	m.ErrorCode = code
	m.ErrorMessage = message
}

// ClearError resets error state
func (m *MockKeycloakServer) ClearError() {
	m.ShouldReturnError = false
	m.ErrorCode = 0
	m.ErrorMessage = ""
}

// Reset clears all call tracking
func (m *MockKeycloakServer) Reset() {
	m.TokenEndpointCalled = false
	m.UserInfoEndpointCalled = false
	m.LastTokenRequest = nil
	m.ClearError()
}

// GetURL returns the base URL of the mock server
func (m *MockKeycloakServer) GetURL() string {
	return m.Server.URL
}

// GenerateMockAuthURL generates a mock authorization URL for testing
func GenerateMockAuthURL(keycloakURL, clientID, redirectURI, state string) string {
	params := url.Values{}
	params.Add("client_id", clientID)
	params.Add("redirect_uri", redirectURI)
	params.Add("response_type", "code")
	params.Add("scope", "openid email profile")
	params.Add("state", state)
	
	return fmt.Sprintf("%s/realms/adc-brandkit/protocol/openid-connect/auth?%s", 
		keycloakURL, params.Encode())
}

// MockHTTPClient provides a mock HTTP client for testing external requests
type MockHTTPClient struct {
	Responses map[string]*http.Response
	Requests  []*http.Request
}

// NewMockHTTPClient creates a new mock HTTP client
func NewMockHTTPClient() *MockHTTPClient {
	return &MockHTTPClient{
		Responses: make(map[string]*http.Response),
		Requests:  make([]*http.Request, 0),
	}
}

// AddResponse adds a mock response for a specific URL
func (m *MockHTTPClient) AddResponse(url string, response *http.Response) {
	m.Responses[url] = response
}

// Do executes the mock HTTP request
func (m *MockHTTPClient) Do(req *http.Request) (*http.Response, error) {
	m.Requests = append(m.Requests, req)
	
	if response, exists := m.Responses[req.URL.String()]; exists {
		return response, nil
	}
	
	// Default response if no specific mock found
	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       http.NoBody,
	}, nil
}

// GetRequestCount returns the number of requests made
func (m *MockHTTPClient) GetRequestCount() int {
	return len(m.Requests)
}

// GetLastRequest returns the last request made
func (m *MockHTTPClient) GetLastRequest() *http.Request {
	if len(m.Requests) > 0 {
		return m.Requests[len(m.Requests)-1]
	}
	return nil
}