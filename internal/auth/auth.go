package auth

import (
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

type AuthService struct {
	jwtSecret []byte
}

type Claims struct {
	UserID          string   `json:"user_id"`
	Username        string   `json:"username"`
	Email           string   `json:"email"`
	Role            string   `json:"role"`
	Organizations   []string `json:"organizations,omitempty"`   // Organization IDs user has access to
	Permissions     []string `json:"permissions,omitempty"`     // Global permissions
	Scopes          []string `json:"scopes,omitempty"`          // OAuth scopes
	SessionID       string   `json:"session_id,omitempty"`      // Session identifier
	SSOProvider     string   `json:"sso_provider,omitempty"`    // SSO provider used
	jwt.RegisteredClaims
}

type RefreshClaims struct {
	UserID    string `json:"user_id"`
	SessionID string `json:"session_id,omitempty"`
	jwt.RegisteredClaims
}

type TokenPair struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
}

type UserContext struct {
	UserID        string   `json:"user_id"`
	Username      string   `json:"username"`
	Email         string   `json:"email"`
	Role          string   `json:"role"`
	Organizations []string `json:"organizations"`
	Permissions   []string `json:"permissions"`
	SSOProvider   string   `json:"sso_provider,omitempty"`
}

func NewAuthService(jwtSecret string) *AuthService {
	return &AuthService{
		jwtSecret: []byte(jwtSecret),
	}
}

func (s *AuthService) GenerateToken(userID, username, email, role string) (string, error) {
	return s.GenerateTokenWithContext(&UserContext{
		UserID:   userID,
		Username: username,
		Email:    email,
		Role:     role,
	})
}

func (s *AuthService) GenerateTokenWithContext(ctx *UserContext) (string, error) {
	sessionID := uuid.New().String()
	
	claims := Claims{
		UserID:        ctx.UserID,
		Username:      ctx.Username,
		Email:         ctx.Email,
		Role:          ctx.Role,
		Organizations: ctx.Organizations,
		Permissions:   ctx.Permissions,
		SessionID:     sessionID,
		SSOProvider:   ctx.SSOProvider,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
			ID:        uuid.New().String(),
			Issuer:    "adc-sso-service",
			Subject:   ctx.UserID,
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(s.jwtSecret)
}

func (s *AuthService) GenerateTokenPair(ctx *UserContext) (*TokenPair, error) {
	accessToken, err := s.GenerateTokenWithContext(ctx)
	if err != nil {
		return nil, err
	}

	refreshToken, err := s.GenerateRefreshToken(ctx.UserID)
	if err != nil {
		return nil, err
	}

	return &TokenPair{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		TokenType:    "Bearer",
		ExpiresIn:    24 * 60 * 60, // 24 hours in seconds
	}, nil
}

func (s *AuthService) GenerateRefreshToken(userID string) (string, error) {
	claims := RefreshClaims{
		UserID: userID,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(7 * 24 * time.Hour)), // 7 days
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
			ID:        uuid.New().String(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(s.jwtSecret)
}

func (s *AuthService) ValidateToken(tokenString string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return s.jwtSecret, nil
	})

	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(*Claims); ok && token.Valid {
		return claims, nil
	}

	return nil, errors.New("invalid token")
}

func (s *AuthService) ValidateRefreshToken(tokenString string) (string, error) {
	token, err := jwt.ParseWithClaims(tokenString, &RefreshClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return s.jwtSecret, nil
	})

	if err != nil {
		return "", err
	}

	if claims, ok := token.Claims.(*RefreshClaims); ok && token.Valid {
		return claims.UserID, nil
	}

	return "", errors.New("invalid refresh token")
}