package sdk

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/google/uuid"
)

type SSOClient struct {
	baseURL    string
	httpClient *http.Client
	apiKey     string // For service-to-service authentication
}

type SSOLoginResponse struct {
	RedirectURL string `json:"redirect_url"`
	State       string `json:"state"`
}

type SSOCallbackResponse struct {
	UserID       string `json:"user_id"`
	Username     string `json:"username"`
	Email        string `json:"email"`
	FullName     string `json:"full_name"`
	Role         string `json:"role"`
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"`
	TokenType    string `json:"token_type"`
	IsNewUser    bool   `json:"is_new_user"`
	SSOSource    string `json:"sso_source"`
}

type TokenValidationResponse struct {
	Valid         bool     `json:"valid"`
	UserID        string   `json:"user_id"`
	Username      string   `json:"username"`
	Email         string   `json:"email"`
	FullName      string   `json:"full_name"`
	Role          string   `json:"role"`
	Organizations []string `json:"organizations"`
	Permissions   []string `json:"permissions"`
	SessionID     string   `json:"session_id"`
	SSOProvider   string   `json:"sso_provider"`
	ExpiresAt     time.Time `json:"expires_at"`
}

type UserContext struct {
	UserID        string   `json:"user_id"`
	Username      string   `json:"username"`
	Email         string   `json:"email"`
	FullName      string   `json:"full_name"`
	Role          string   `json:"role"`
	Organizations []string `json:"organizations"`
	Permissions   []string `json:"permissions"`
	SessionID     string   `json:"session_id"`
	SSOProvider   string   `json:"sso_provider"`
}

type Organization struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Slug        string                 `json:"slug"`
	Description string                 `json:"description"`
	Website     string                 `json:"website"`
	Status      string                 `json:"status"`
	Settings    map[string]interface{} `json:"settings"`
	UserRole    string                 `json:"user_role"`
	CreatedAt   time.Time              `json:"created_at"`
	UpdatedAt   time.Time              `json:"updated_at"`
}

type APIKeyInfo struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	KeyPrefix   string    `json:"key_prefix"`
	Permissions []string  `json:"permissions"`
	Scopes      []string  `json:"scopes"`
	IsActive    bool      `json:"is_active"`
	LastUsedAt  *time.Time `json:"last_used_at"`
	UsageCount  int64     `json:"usage_count"`
	ExpiresAt   *time.Time `json:"expires_at"`
	CreatedAt   time.Time `json:"created_at"`
}

type TokenRefreshResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
	TokenType   string `json:"token_type"`
}

type APIResponse struct {
	Success bool        `json:"success"`
	Message string      `json:"message"`
	Data    interface{} `json:"data"`
}

func NewSSOClient(baseURL string) *SSOClient {
	return &SSOClient{
		baseURL: baseURL,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

func NewSSOClientWithAPIKey(baseURL, apiKey string) *SSOClient {
	return &SSOClient{
		baseURL: baseURL,
		apiKey:  apiKey,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// addAuthHeaders adds authentication headers to the request
func (c *SSOClient) addAuthHeaders(req *http.Request, accessToken string) {
	if accessToken != "" {
		req.Header.Set("Authorization", "Bearer "+accessToken)
	} else if c.apiKey != "" {
		req.Header.Set("X-API-Key", c.apiKey)
	}
}

// makeRequest is a helper method for making HTTP requests
func (c *SSOClient) makeRequest(ctx context.Context, method, endpoint string, body interface{}, accessToken string) (*http.Response, error) {
	var reqBody io.Reader
	if body != nil {
		jsonData, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal request body: %w", err)
		}
		reqBody = bytes.NewBuffer(jsonData)
	}

	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+endpoint, reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	c.addAuthHeaders(req, accessToken)

	return c.httpClient.Do(req)
}

// GetSSOLoginURL gets the SSO login redirect URL
func (c *SSOClient) GetSSOLoginURL() (*SSOLoginResponse, error) {
	resp, err := c.httpClient.Get(c.baseURL + "/sso/login")
	if err != nil {
		return nil, fmt.Errorf("failed to get SSO login URL: %w", err)
	}
	defer resp.Body.Close()

	var apiResp APIResponse
	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	if !apiResp.Success {
		return nil, fmt.Errorf("SSO service error: %s", apiResp.Message)
	}

	data, err := json.Marshal(apiResp.Data)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response data: %w", err)
	}

	var loginResp SSOLoginResponse
	if err := json.Unmarshal(data, &loginResp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal login response: %w", err)
	}

	return &loginResp, nil
}

// HandleSSOCallback makes a request to the SSO callback endpoint
func (c *SSOClient) HandleSSOCallback(code, state string) (*SSOCallbackResponse, error) {
	url := fmt.Sprintf("%s/sso/callback?code=%s&state=%s", c.baseURL, code, state)
	
	resp, err := c.httpClient.Get(url)
	if err != nil {
		return nil, fmt.Errorf("failed to handle SSO callback: %w", err)
	}
	defer resp.Body.Close()

	var apiResp APIResponse
	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	if !apiResp.Success {
		return nil, fmt.Errorf("SSO service error: %s", apiResp.Message)
	}

	data, err := json.Marshal(apiResp.Data)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response data: %w", err)
	}

	var callbackResp SSOCallbackResponse
	if err := json.Unmarshal(data, &callbackResp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal callback response: %w", err)
	}

	return &callbackResp, nil
}

// ValidateToken validates an access token
func (c *SSOClient) ValidateToken(accessToken string) (*TokenValidationResponse, error) {
	payload := map[string]string{
		"access_token": accessToken,
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	resp, err := c.httpClient.Post(
		c.baseURL+"/sso/validate",
		"application/json",
		bytes.NewBuffer(jsonData),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to validate token: %w", err)
	}
	defer resp.Body.Close()

	var apiResp APIResponse
	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	if !apiResp.Success {
		return nil, fmt.Errorf("token validation failed: %s", apiResp.Message)
	}

	data, err := json.Marshal(apiResp.Data)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response data: %w", err)
	}

	var validationResp TokenValidationResponse
	if err := json.Unmarshal(data, &validationResp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal validation response: %w", err)
	}

	return &validationResp, nil
}

// RefreshToken refreshes an access token using refresh token
func (c *SSOClient) RefreshToken(refreshToken string) (*TokenRefreshResponse, error) {
	payload := map[string]string{
		"refresh_token": refreshToken,
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	resp, err := c.httpClient.Post(
		c.baseURL+"/sso/refresh",
		"application/json",
		bytes.NewBuffer(jsonData),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to refresh token: %w", err)
	}
	defer resp.Body.Close()

	var apiResp APIResponse
	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	if !apiResp.Success {
		return nil, fmt.Errorf("token refresh failed: %s", apiResp.Message)
	}

	data, err := json.Marshal(apiResp.Data)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response data: %w", err)
	}

	var refreshResp TokenRefreshResponse
	if err := json.Unmarshal(data, &refreshResp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal refresh response: %w", err)
	}

	return &refreshResp, nil
}

// CheckHealth checks if the SSO service is healthy
func (c *SSOClient) CheckHealth() error {
	resp, err := c.httpClient.Get(c.baseURL + "/health")
	if err != nil {
		return fmt.Errorf("failed to check health: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("SSO service unhealthy: %s", string(body))
	}

	return nil
}

// Enhanced authentication methods

// ValidateTokenWithContext validates a token and returns full user context
func (c *SSOClient) ValidateTokenWithContext(ctx context.Context, accessToken string) (*UserContext, error) {
	payload := map[string]string{
		"access_token": accessToken,
	}

	resp, err := c.makeRequest(ctx, "POST", "/api/v1/auth/validate", payload, "")
	if err != nil {
		return nil, fmt.Errorf("failed to validate token: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("token validation failed: %s", string(body))
	}

	var apiResp APIResponse
	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	data, err := json.Marshal(apiResp.Data)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response data: %w", err)
	}

	var userContext UserContext
	if err := json.Unmarshal(data, &userContext); err != nil {
		return nil, fmt.Errorf("failed to unmarshal user context: %w", err)
	}

	return &userContext, nil
}

// GetCurrentUser gets the current user information using an access token
func (c *SSOClient) GetCurrentUser(ctx context.Context, accessToken string) (*UserContext, error) {
	resp, err := c.makeRequest(ctx, "GET", "/api/v1/auth/me", nil, accessToken)
	if err != nil {
		return nil, fmt.Errorf("failed to get current user: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to get current user: %s", string(body))
	}

	var apiResp APIResponse
	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	data, err := json.Marshal(apiResp.Data)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response data: %w", err)
	}

	var userContext UserContext
	if err := json.Unmarshal(data, &userContext); err != nil {
		return nil, fmt.Errorf("failed to unmarshal user context: %w", err)
	}

	return &userContext, nil
}

// Organization management methods

// ListOrganizations lists organizations for the authenticated user
func (c *SSOClient) ListOrganizations(ctx context.Context, accessToken string, limit, offset int) ([]Organization, error) {
	endpoint := "/api/v1/organizations"
	if limit > 0 || offset > 0 {
		params := url.Values{}
		if limit > 0 {
			params.Set("limit", fmt.Sprintf("%d", limit))
		}
		if offset > 0 {
			params.Set("offset", fmt.Sprintf("%d", offset))
		}
		endpoint += "?" + params.Encode()
	}

	resp, err := c.makeRequest(ctx, "GET", endpoint, nil, accessToken)
	if err != nil {
		return nil, fmt.Errorf("failed to list organizations: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to list organizations: %s", string(body))
	}

	var apiResp APIResponse
	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	data, err := json.Marshal(apiResp.Data)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response data: %w", err)
	}

	var result struct {
		Organizations []Organization `json:"organizations"`
	}
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, fmt.Errorf("failed to unmarshal organizations: %w", err)
	}

	return result.Organizations, nil
}

// GetOrganization gets a specific organization
func (c *SSOClient) GetOrganization(ctx context.Context, accessToken, orgID string) (*Organization, error) {
	endpoint := fmt.Sprintf("/api/v1/organizations/%s", orgID)

	resp, err := c.makeRequest(ctx, "GET", endpoint, nil, accessToken)
	if err != nil {
		return nil, fmt.Errorf("failed to get organization: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to get organization: %s", string(body))
	}

	var apiResp APIResponse
	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	data, err := json.Marshal(apiResp.Data)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response data: %w", err)
	}

	var result struct {
		Organization Organization `json:"organization"`
	}
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, fmt.Errorf("failed to unmarshal organization: %w", err)
	}

	return &result.Organization, nil
}

// CreateOrganization creates a new organization
func (c *SSOClient) CreateOrganization(ctx context.Context, accessToken string, req CreateOrganizationRequest) (*Organization, error) {
	resp, err := c.makeRequest(ctx, "POST", "/api/v1/organizations", req, accessToken)
	if err != nil {
		return nil, fmt.Errorf("failed to create organization: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to create organization: %s", string(body))
	}

	var apiResp APIResponse
	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	data, err := json.Marshal(apiResp.Data)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response data: %w", err)
	}

	var result struct {
		Organization Organization `json:"organization"`
	}
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, fmt.Errorf("failed to unmarshal organization: %w", err)
	}

	return &result.Organization, nil
}

// API Key management methods

// ListAPIKeys lists API keys for an organization
func (c *SSOClient) ListAPIKeys(ctx context.Context, accessToken, orgID string, includeInactive bool) ([]APIKeyInfo, error) {
	endpoint := fmt.Sprintf("/api/v1/organizations/%s/api-keys", orgID)
	if includeInactive {
		endpoint += "?include_inactive=true"
	}

	resp, err := c.makeRequest(ctx, "GET", endpoint, nil, accessToken)
	if err != nil {
		return nil, fmt.Errorf("failed to list API keys: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to list API keys: %s", string(body))
	}

	var apiResp APIResponse
	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	data, err := json.Marshal(apiResp.Data)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response data: %w", err)
	}

	var result struct {
		APIKeys []APIKeyInfo `json:"api_keys"`
	}
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, fmt.Errorf("failed to unmarshal API keys: %w", err)
	}

	return result.APIKeys, nil
}

// CreateAPIKey creates a new API key
func (c *SSOClient) CreateAPIKey(ctx context.Context, accessToken, orgID string, req CreateAPIKeyRequest) (*CreateAPIKeyResponse, error) {
	endpoint := fmt.Sprintf("/api/v1/organizations/%s/api-keys", orgID)

	resp, err := c.makeRequest(ctx, "POST", endpoint, req, accessToken)
	if err != nil {
		return nil, fmt.Errorf("failed to create API key: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to create API key: %s", string(body))
	}

	var apiResp APIResponse
	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	data, err := json.Marshal(apiResp.Data)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response data: %w", err)
	}

	var result CreateAPIKeyResponse
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, fmt.Errorf("failed to unmarshal API key response: %w", err)
	}

	return &result, nil
}

// Request/Response types
type CreateOrganizationRequest struct {
	Name        string                 `json:"name"`
	Slug        string                 `json:"slug,omitempty"`
	Description string                 `json:"description,omitempty"`
	Website     string                 `json:"website,omitempty"`
	Settings    map[string]interface{} `json:"settings,omitempty"`
}

type CreateAPIKeyRequest struct {
	Name        string     `json:"name"`
	Permissions []string   `json:"permissions,omitempty"`
	Scopes      []string   `json:"scopes,omitempty"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
}

type CreateAPIKeyResponse struct {
	APIKey  APIKeyInfo `json:"api_key"`
	Key     string     `json:"key"`     // Only returned once
	Warning string     `json:"warning"` // Security warning
}