package auth

import (
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/stretchr/testify/suite"
)

// AuthServiceTestSuite defines the test suite for AuthService
type AuthServiceTestSuite struct {
	suite.Suite
	authService *AuthService
	testSecret  string
}

// SetupTest runs before each test
func (suite *AuthServiceTestSuite) SetupTest() {
	suite.testSecret = "test-jwt-secret-key-for-testing"
	suite.authService = NewAuthService(suite.testSecret)
}

// TestAuthServiceTestSuite runs the test suite
func TestAuthServiceTestSuite(t *testing.T) {
	suite.Run(t, new(AuthServiceTestSuite))
}

// Test JWT token generation
func (suite *AuthServiceTestSuite) TestGenerateToken() {
	userID := uuid.New().String()
	username := "testuser"
	email := "test@example.com"
	role := "user"

	token, err := suite.authService.GenerateToken(userID, username, email, role)

	suite.NoError(err)
	suite.NotEmpty(token)

	// Validate the token structure
	parsedToken, err := jwt.ParseWithClaims(token, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(suite.testSecret), nil
	})

	suite.NoError(err)
	suite.True(parsedToken.Valid)

	claims, ok := parsedToken.Claims.(*Claims)
	suite.True(ok)
	suite.Equal(userID, claims.UserID)
	suite.Equal(username, claims.Username)
	suite.Equal(email, claims.Email)
	suite.Equal(role, claims.Role)
	suite.Equal("adc-sso-service", claims.Issuer)
	suite.Equal(userID, claims.Subject)
	suite.NotEmpty(claims.SessionID)
}

// Test JWT token generation with context
func (suite *AuthServiceTestSuite) TestGenerateTokenWithContext() {
	ctx := &UserContext{
		UserID:        uuid.New().String(),
		Username:      "testuser",
		Email:         "test@example.com",
		Role:          "admin",
		Organizations: []string{"org1", "org2"},
		Permissions:   []string{"read", "write"},
		SSOProvider:   "keycloak",
	}

	token, err := suite.authService.GenerateTokenWithContext(ctx)

	suite.NoError(err)
	suite.NotEmpty(token)

	// Validate the token
	claims, err := suite.authService.ValidateToken(token)
	suite.NoError(err)

	suite.Equal(ctx.UserID, claims.UserID)
	suite.Equal(ctx.Username, claims.Username)
	suite.Equal(ctx.Email, claims.Email)
	suite.Equal(ctx.Role, claims.Role)
	suite.Equal(ctx.Organizations, claims.Organizations)
	suite.Equal(ctx.Permissions, claims.Permissions)
	suite.Equal(ctx.SSOProvider, claims.SSOProvider)
}

// Test JWT token validation
func (suite *AuthServiceTestSuite) TestValidateToken() {
	userID := uuid.New().String()
	username := "testuser"
	email := "test@example.com"
	role := "user"

	// Generate a valid token
	token, err := suite.authService.GenerateToken(userID, username, email, role)
	suite.NoError(err)

	// Validate the token
	claims, err := suite.authService.ValidateToken(token)
	suite.NoError(err)
	suite.NotNil(claims)

	suite.Equal(userID, claims.UserID)
	suite.Equal(username, claims.Username)
	suite.Equal(email, claims.Email)
	suite.Equal(role, claims.Role)
}

// Test token validation with invalid token
func (suite *AuthServiceTestSuite) TestValidateInvalidToken() {
	invalidToken := "invalid.jwt.token"

	claims, err := suite.authService.ValidateToken(invalidToken)
	suite.Error(err)
	suite.Nil(claims)
}

// Test token validation with wrong secret
func (suite *AuthServiceTestSuite) TestValidateTokenWrongSecret() {
	// Create token with different service
	wrongService := NewAuthService("wrong-secret")
	token, err := wrongService.GenerateToken("user123", "test", "test@example.com", "user")
	suite.NoError(err)

	// Try to validate with correct service
	claims, err := suite.authService.ValidateToken(token)
	suite.Error(err)
	suite.Nil(claims)
}

// Test refresh token generation
func (suite *AuthServiceTestSuite) TestGenerateRefreshToken() {
	userID := uuid.New().String()

	refreshToken, err := suite.authService.GenerateRefreshToken(userID)

	suite.NoError(err)
	suite.NotEmpty(refreshToken)

	// Validate refresh token structure
	parsedToken, err := jwt.ParseWithClaims(refreshToken, &RefreshClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(suite.testSecret), nil
	})

	suite.NoError(err)
	suite.True(parsedToken.Valid)

	claims, ok := parsedToken.Claims.(*RefreshClaims)
	suite.True(ok)
	suite.Equal(userID, claims.UserID)

	// Check expiration (should be 7 days)
	expectedExpiry := time.Now().Add(7 * 24 * time.Hour)
	actualExpiry := claims.ExpiresAt.Time
	suite.WithinDuration(expectedExpiry, actualExpiry, time.Minute)
}

// Test refresh token validation
func (suite *AuthServiceTestSuite) TestValidateRefreshToken() {
	userID := uuid.New().String()

	// Generate refresh token
	refreshToken, err := suite.authService.GenerateRefreshToken(userID)
	suite.NoError(err)

	// Validate refresh token
	validatedUserID, err := suite.authService.ValidateRefreshToken(refreshToken)
	suite.NoError(err)
	suite.Equal(userID, validatedUserID)
}

// Test invalid refresh token validation
func (suite *AuthServiceTestSuite) TestValidateInvalidRefreshToken() {
	invalidToken := "invalid.refresh.token"

	userID, err := suite.authService.ValidateRefreshToken(invalidToken)
	suite.Error(err)
	suite.Empty(userID)
}

// Test token pair generation
func (suite *AuthServiceTestSuite) TestGenerateTokenPair() {
	ctx := &UserContext{
		UserID:   uuid.New().String(),
		Username: "testuser",
		Email:    "test@example.com",
		Role:     "user",
	}

	tokenPair, err := suite.authService.GenerateTokenPair(ctx)

	suite.NoError(err)
	suite.NotNil(tokenPair)
	suite.NotEmpty(tokenPair.AccessToken)
	suite.NotEmpty(tokenPair.RefreshToken)
	suite.Equal("Bearer", tokenPair.TokenType)
	suite.Equal(int64(24*60*60), tokenPair.ExpiresIn) // 24 hours

	// Validate both tokens
	accessClaims, err := suite.authService.ValidateToken(tokenPair.AccessToken)
	suite.NoError(err)
	suite.Equal(ctx.UserID, accessClaims.UserID)

	refreshUserID, err := suite.authService.ValidateRefreshToken(tokenPair.RefreshToken)
	suite.NoError(err)
	suite.Equal(ctx.UserID, refreshUserID)
}

// Test token expiration
func (suite *AuthServiceTestSuite) TestTokenExpiration() {
	// This test would require modifying the auth service to accept custom expiration
	// For now, we'll test that the expiration is set correctly
	userID := uuid.New().String()
	token, err := suite.authService.GenerateToken(userID, "test", "test@example.com", "user")
	suite.NoError(err)

	claims, err := suite.authService.ValidateToken(token)
	suite.NoError(err)

	// Check that expiration is approximately 24 hours from now
	expectedExpiry := time.Now().Add(24 * time.Hour)
	actualExpiry := claims.ExpiresAt.Time
	suite.WithinDuration(expectedExpiry, actualExpiry, time.Minute)
}

// Test claims structure completeness
func (suite *AuthServiceTestSuite) TestClaimsStructure() {
	ctx := &UserContext{
		UserID:        uuid.New().String(),
		Username:      "testuser",
		Email:         "test@example.com",
		Role:          "admin",
		Organizations: []string{"org1", "org2"},
		Permissions:   []string{"read", "write", "admin"},
		SSOProvider:   "keycloak",
	}

	token, err := suite.authService.GenerateTokenWithContext(ctx)
	suite.NoError(err)

	claims, err := suite.authService.ValidateToken(token)
	suite.NoError(err)

	// Verify all fields are preserved
	suite.Equal(ctx.UserID, claims.UserID)
	suite.Equal(ctx.Username, claims.Username)
	suite.Equal(ctx.Email, claims.Email)
	suite.Equal(ctx.Role, claims.Role)
	suite.Equal(ctx.Organizations, claims.Organizations)
	suite.Equal(ctx.Permissions, claims.Permissions)
	suite.Equal(ctx.SSOProvider, claims.SSOProvider)

	// Verify registered claims
	suite.Equal("adc-sso-service", claims.Issuer)
	suite.Equal(ctx.UserID, claims.Subject)
	suite.NotEmpty(claims.SessionID)
	suite.NotEmpty(claims.ID)
	suite.True(claims.IssuedAt.Time.Before(time.Now().Add(time.Minute)))
	suite.True(claims.NotBefore.Time.Before(time.Now().Add(time.Minute)))
	suite.True(claims.ExpiresAt.Time.After(time.Now()))
}

// Test concurrent token generation
func (suite *AuthServiceTestSuite) TestConcurrentTokenGeneration() {
	userID := uuid.New().String()
	numGoroutines := 10
	tokens := make(chan string, numGoroutines)
	errors := make(chan error, numGoroutines)

	// Generate tokens concurrently
	for i := 0; i < numGoroutines; i++ {
		go func(i int) {
			token, err := suite.authService.GenerateToken(userID, "test", "test@example.com", "user")
			if err != nil {
				errors <- err
				return
			}
			tokens <- token
		}(i)
	}

	// Collect results
	var generatedTokens []string
	for i := 0; i < numGoroutines; i++ {
		select {
		case token := <-tokens:
			generatedTokens = append(generatedTokens, token)
		case err := <-errors:
			suite.Fail("Token generation failed", err.Error())
		}
	}

	// Verify all tokens were generated
	suite.Len(generatedTokens, numGoroutines)

	// Verify all tokens are valid and unique
	uniqueTokens := make(map[string]bool)
	for _, token := range generatedTokens {
		suite.False(uniqueTokens[token], "Token should be unique")
		uniqueTokens[token] = true

		// Validate token
		claims, err := suite.authService.ValidateToken(token)
		suite.NoError(err)
		suite.Equal(userID, claims.UserID)
	}
}

// Test empty values handling
func (suite *AuthServiceTestSuite) TestGenerateTokenWithEmptyValues() {
	// Test with empty userID
	token, err := suite.authService.GenerateToken("", "username", "email", "role")
	suite.NoError(err) // Service should handle empty values gracefully
	suite.NotEmpty(token)

	claims, err := suite.authService.ValidateToken(token)
	suite.NoError(err)
	suite.Empty(claims.UserID)
	suite.Equal("username", claims.Username)
}

// Benchmark token generation
func (suite *AuthServiceTestSuite) TestTokenGenerationPerformance() {
	userID := uuid.New().String()
	iterations := 1000

	start := time.Now()
	for i := 0; i < iterations; i++ {
		_, err := suite.authService.GenerateToken(userID, "test", "test@example.com", "user")
		suite.NoError(err)
	}
	duration := time.Since(start)

	// Should be able to generate at least 100 tokens per second
	expectedDuration := time.Duration(iterations) * 10 * time.Millisecond
	suite.Less(duration, expectedDuration, "Token generation is too slow")
}

// Test different signing methods (negative test)
func (suite *AuthServiceTestSuite) TestInvalidSigningMethod() {
	// Create a token with RS256 (should fail with HMAC validator)
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, &Claims{
		UserID: "test",
	})

	// This should fail because we're using HMAC secret but RS256 signing
	tokenString, _ := token.SignedString([]byte(suite.testSecret))

	claims, err := suite.authService.ValidateToken(tokenString)
	suite.Error(err)
	suite.Nil(claims)
}