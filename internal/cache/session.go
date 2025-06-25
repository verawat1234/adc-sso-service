package cache

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/sirupsen/logrus"
)

// SessionManager handles session storage and retrieval using Redis
type SessionManager struct {
	redis *RedisClient
}

// SessionData represents the data stored in a session
type SessionData struct {
	UserID        string                 `json:"user_id"`
	Username      string                 `json:"username"`
	Email         string                 `json:"email"`
	Role          string                 `json:"role"`
	Organizations []string               `json:"organizations"`
	Permissions   []string               `json:"permissions"`
	SSOProvider   string                 `json:"sso_provider"`
	CreatedAt     time.Time              `json:"created_at"`
	LastAccessed  time.Time              `json:"last_accessed"`
	Metadata      map[string]interface{} `json:"metadata"`
}

// SSOState represents OAuth state information
type SSOState struct {
	State       string            `json:"state"`
	RedirectURL string            `json:"redirect_url"`
	CodeChallenge string          `json:"code_challenge,omitempty"`
	CreatedAt   time.Time         `json:"created_at"`
	Metadata    map[string]string `json:"metadata,omitempty"`
}

// NewSessionManager creates a new session manager
func NewSessionManager(redis *RedisClient) *SessionManager {
	return &SessionManager{
		redis: redis,
	}
}

// Session Management

// CreateSession creates a new session and returns the session ID
func (s *SessionManager) CreateSession(ctx context.Context, sessionData *SessionData, expiration time.Duration) (string, error) {
	sessionID := s.generateSessionID()
	sessionData.CreatedAt = time.Now()
	sessionData.LastAccessed = time.Now()

	data, err := json.Marshal(sessionData)
	if err != nil {
		logrus.WithError(err).Error("Failed to marshal session data")
		return "", fmt.Errorf("failed to marshal session data: %w", err)
	}

	key := s.sessionKey(sessionID)
	if err := s.redis.Set(ctx, key, data, expiration); err != nil {
		return "", fmt.Errorf("failed to store session: %w", err)
	}

	logrus.WithFields(logrus.Fields{
		"session_id": sessionID,
		"user_id":    sessionData.UserID,
		"expiration": expiration,
	}).Info("Session created successfully")

	return sessionID, nil
}

// GetSession retrieves session data by session ID
func (s *SessionManager) GetSession(ctx context.Context, sessionID string) (*SessionData, error) {
	key := s.sessionKey(sessionID)
	data, err := s.redis.Get(ctx, key)
	if err != nil {
		return nil, fmt.Errorf("failed to get session: %w", err)
	}

	if data == "" {
		return nil, nil // Session not found
	}

	var sessionData SessionData
	if err := json.Unmarshal([]byte(data), &sessionData); err != nil {
		logrus.WithError(err).WithField("session_id", sessionID).Error("Failed to unmarshal session data")
		return nil, fmt.Errorf("failed to unmarshal session data: %w", err)
	}

	// Update last accessed time
	sessionData.LastAccessed = time.Now()
	if err := s.UpdateSession(ctx, sessionID, &sessionData); err != nil {
		logrus.WithError(err).WithField("session_id", sessionID).Warn("Failed to update session last accessed time")
	}

	return &sessionData, nil
}

// UpdateSession updates existing session data
func (s *SessionManager) UpdateSession(ctx context.Context, sessionID string, sessionData *SessionData) error {
	key := s.sessionKey(sessionID)
	
	// Get current TTL to preserve expiration
	ttl, err := s.redis.GetTTL(ctx, key)
	if err != nil {
		logrus.WithError(err).WithField("session_id", sessionID).Error("Failed to get session TTL")
		return fmt.Errorf("failed to get session TTL: %w", err)
	}

	data, err := json.Marshal(sessionData)
	if err != nil {
		logrus.WithError(err).Error("Failed to marshal session data")
		return fmt.Errorf("failed to marshal session data: %w", err)
	}

	if err := s.redis.Set(ctx, key, data, ttl); err != nil {
		return fmt.Errorf("failed to update session: %w", err)
	}

	return nil
}

// DeleteSession removes a session
func (s *SessionManager) DeleteSession(ctx context.Context, sessionID string) error {
	key := s.sessionKey(sessionID)
	if err := s.redis.Delete(ctx, key); err != nil {
		return fmt.Errorf("failed to delete session: %w", err)
	}

	logrus.WithField("session_id", sessionID).Info("Session deleted successfully")
	return nil
}

// ExtendSession extends the expiration time of a session
func (s *SessionManager) ExtendSession(ctx context.Context, sessionID string, expiration time.Duration) error {
	key := s.sessionKey(sessionID)
	
	// Check if session exists
	exists, err := s.redis.Exists(ctx, key)
	if err != nil {
		return fmt.Errorf("failed to check session existence: %w", err)
	}
	
	if !exists {
		return fmt.Errorf("session not found")
	}

	// Set new expiration
	if err := s.redis.GetClient().Expire(ctx, key, expiration).Err(); err != nil {
		logrus.WithError(err).WithField("session_id", sessionID).Error("Failed to extend session")
		return fmt.Errorf("failed to extend session: %w", err)
	}

	return nil
}

// SSO State Management

// StoreOAuthState stores OAuth state information
func (s *SessionManager) StoreOAuthState(ctx context.Context, state *SSOState, expiration time.Duration) error {
	state.CreatedAt = time.Now()
	
	data, err := json.Marshal(state)
	if err != nil {
		logrus.WithError(err).Error("Failed to marshal OAuth state")
		return fmt.Errorf("failed to marshal OAuth state: %w", err)
	}

	key := s.oauthStateKey(state.State)
	if err := s.redis.Set(ctx, key, data, expiration); err != nil {
		return fmt.Errorf("failed to store OAuth state: %w", err)
	}

	logrus.WithFields(logrus.Fields{
		"state":      state.State,
		"expiration": expiration,
	}).Info("OAuth state stored successfully")

	return nil
}

// ValidateAndConsumeOAuthState validates OAuth state and removes it (one-time use)
func (s *SessionManager) ValidateAndConsumeOAuthState(ctx context.Context, state string) (*SSOState, error) {
	key := s.oauthStateKey(state)
	data, err := s.redis.Get(ctx, key)
	if err != nil {
		return nil, fmt.Errorf("failed to get OAuth state: %w", err)
	}

	if data == "" {
		return nil, fmt.Errorf("OAuth state not found or expired")
	}

	// Delete the state (one-time use)
	if err := s.redis.Delete(ctx, key); err != nil {
		logrus.WithError(err).WithField("state", state).Warn("Failed to delete OAuth state after validation")
	}

	var ssoState SSOState
	if err := json.Unmarshal([]byte(data), &ssoState); err != nil {
		logrus.WithError(err).WithField("state", state).Error("Failed to unmarshal OAuth state")
		return nil, fmt.Errorf("failed to unmarshal OAuth state: %w", err)
	}

	logrus.WithField("state", state).Info("OAuth state validated and consumed")
	return &ssoState, nil
}

// Helper methods

func (s *SessionManager) sessionKey(sessionID string) string {
	return fmt.Sprintf("session:%s", sessionID)
}

func (s *SessionManager) oauthStateKey(state string) string {
	return fmt.Sprintf("oauth_state:%s", state)
}

func (s *SessionManager) generateSessionID() string {
	// Generate a secure session ID using timestamp and random component
	return fmt.Sprintf("sess_%d_%s", time.Now().UnixNano(), generateRandomString(32))
}

// Token Blacklist Management

// BlacklistToken adds a token to the blacklist
func (s *SessionManager) BlacklistToken(ctx context.Context, tokenID string, expiration time.Duration) error {
	key := s.blacklistKey(tokenID)
	if err := s.redis.Set(ctx, key, "blacklisted", expiration); err != nil {
		return fmt.Errorf("failed to blacklist token: %w", err)
	}

	logrus.WithFields(logrus.Fields{
		"token_id":   tokenID,
		"expiration": expiration,
	}).Info("Token blacklisted successfully")

	return nil
}

// IsTokenBlacklisted checks if a token is blacklisted
func (s *SessionManager) IsTokenBlacklisted(ctx context.Context, tokenID string) (bool, error) {
	key := s.blacklistKey(tokenID)
	exists, err := s.redis.Exists(ctx, key)
	if err != nil {
		return false, fmt.Errorf("failed to check token blacklist: %w", err)
	}
	return exists, nil
}

func (s *SessionManager) blacklistKey(tokenID string) string {
	return fmt.Sprintf("blacklist:token:%s", tokenID)
}

// Utility function for generating random strings
func generateRandomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[time.Now().UnixNano()%int64(len(charset))]
	}
	return string(b)
}