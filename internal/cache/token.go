package cache

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"github.com/sirupsen/logrus"
)

// TokenManager handles token operations using Redis
type TokenManager struct {
	redis *RedisClient
}

// NewTokenManager creates a new token manager
func NewTokenManager(redis *RedisClient) *TokenManager {
	return &TokenManager{
		redis: redis,
	}
}

// Token Blacklist Operations

// BlacklistToken adds a JWT token to the blacklist
func (t *TokenManager) BlacklistToken(ctx context.Context, tokenID string, expiration time.Duration) error {
	key := t.blacklistKey(tokenID)
	blacklistedAt := time.Now().Unix()
	
	if err := t.redis.Set(ctx, key, blacklistedAt, expiration); err != nil {
		return fmt.Errorf("failed to blacklist token: %w", err)
	}

	logrus.WithFields(logrus.Fields{
		"token_id":   tokenID,
		"expiration": expiration,
	}).Info("Token blacklisted successfully")

	return nil
}

// IsTokenBlacklisted checks if a token is in the blacklist
func (t *TokenManager) IsTokenBlacklisted(ctx context.Context, tokenID string) (bool, error) {
	key := t.blacklistKey(tokenID)
	exists, err := t.redis.Exists(ctx, key)
	if err != nil {
		return false, fmt.Errorf("failed to check token blacklist: %w", err)
	}
	return exists, nil
}

// GetTokenBlacklistTime returns when the token was blacklisted
func (t *TokenManager) GetTokenBlacklistTime(ctx context.Context, tokenID string) (time.Time, error) {
	key := t.blacklistKey(tokenID)
	timestampStr, err := t.redis.Get(ctx, key)
	if err != nil {
		return time.Time{}, fmt.Errorf("failed to get blacklist time: %w", err)
	}

	if timestampStr == "" {
		return time.Time{}, fmt.Errorf("token not blacklisted")
	}

	timestamp, err := strconv.ParseInt(timestampStr, 10, 64)
	if err != nil {
		return time.Time{}, fmt.Errorf("failed to parse blacklist timestamp: %w", err)
	}

	return time.Unix(timestamp, 0), nil
}

// RemoveFromBlacklist removes a token from the blacklist (for testing or manual intervention)
func (t *TokenManager) RemoveFromBlacklist(ctx context.Context, tokenID string) error {
	key := t.blacklistKey(tokenID)
	if err := t.redis.Delete(ctx, key); err != nil {
		return fmt.Errorf("failed to remove token from blacklist: %w", err)
	}

	logrus.WithField("token_id", tokenID).Info("Token removed from blacklist")
	return nil
}

// Token Whitelist Operations (for trusted tokens)

// WhitelistToken adds a token to the whitelist with expiration
func (t *TokenManager) WhitelistToken(ctx context.Context, tokenID string, expiration time.Duration) error {
	key := t.whitelistKey(tokenID)
	whitelistedAt := time.Now().Unix()
	
	if err := t.redis.Set(ctx, key, whitelistedAt, expiration); err != nil {
		return fmt.Errorf("failed to whitelist token: %w", err)
	}

	logrus.WithFields(logrus.Fields{
		"token_id":   tokenID,
		"expiration": expiration,
	}).Info("Token whitelisted successfully")

	return nil
}

// IsTokenWhitelisted checks if a token is in the whitelist
func (t *TokenManager) IsTokenWhitelisted(ctx context.Context, tokenID string) (bool, error) {
	key := t.whitelistKey(tokenID)
	exists, err := t.redis.Exists(ctx, key)
	if err != nil {
		return false, fmt.Errorf("failed to check token whitelist: %w", err)
	}
	return exists, nil
}

// Rate Limiting Operations

// CheckRateLimit checks if a rate limit has been exceeded for a given key
func (t *TokenManager) CheckRateLimit(ctx context.Context, key string, limit int64, window time.Duration) (bool, int64, error) {
	rateLimitKey := t.rateLimitKey(key)
	
	// Get current count
	current, err := t.redis.Increment(ctx, rateLimitKey)
	if err != nil {
		return false, 0, fmt.Errorf("failed to increment rate limit counter: %w", err)
	}

	// Set expiration on first increment
	if current == 1 {
		if err := t.redis.GetClient().Expire(ctx, rateLimitKey, window).Err(); err != nil {
			logrus.WithError(err).WithField("key", key).Error("Failed to set rate limit expiration")
		}
	}

	remaining := limit - current
	if remaining < 0 {
		remaining = 0
	}

	exceeded := current > limit
	
	if exceeded {
		logrus.WithFields(logrus.Fields{
			"key":       key,
			"current":   current,
			"limit":     limit,
			"window":    window,
		}).Warn("Rate limit exceeded")
	}

	return exceeded, remaining, nil
}

// ResetRateLimit resets the rate limit counter for a key
func (t *TokenManager) ResetRateLimit(ctx context.Context, key string) error {
	rateLimitKey := t.rateLimitKey(key)
	if err := t.redis.Delete(ctx, rateLimitKey); err != nil {
		return fmt.Errorf("failed to reset rate limit: %w", err)
	}

	logrus.WithField("key", key).Info("Rate limit reset")
	return nil
}

// API Key Caching Operations

// CacheAPIKeyValidation caches API key validation results
func (t *TokenManager) CacheAPIKeyValidation(ctx context.Context, keyHash string, isValid bool, userID string, expiration time.Duration) error {
	cacheKey := t.apiKeyCacheKey(keyHash)
	
	validationData := map[string]interface{}{
		"valid":      isValid,
		"user_id":    userID,
		"cached_at":  time.Now().Unix(),
	}

	data, err := json.Marshal(validationData)
	if err != nil {
		return fmt.Errorf("failed to marshal API key validation data: %w", err)
	}

	if err := t.redis.Set(ctx, cacheKey, data, expiration); err != nil {
		return fmt.Errorf("failed to cache API key validation: %w", err)
	}

	return nil
}

// GetCachedAPIKeyValidation retrieves cached API key validation
func (t *TokenManager) GetCachedAPIKeyValidation(ctx context.Context, keyHash string) (bool, string, bool, error) {
	cacheKey := t.apiKeyCacheKey(keyHash)
	data, err := t.redis.Get(ctx, cacheKey)
	if err != nil {
		return false, "", false, fmt.Errorf("failed to get cached API key validation: %w", err)
	}

	if data == "" {
		return false, "", false, nil // Not cached
	}

	var validationData map[string]interface{}
	if err := json.Unmarshal([]byte(data), &validationData); err != nil {
		return false, "", false, fmt.Errorf("failed to unmarshal cached validation data: %w", err)
	}

	isValid, _ := validationData["valid"].(bool)
	userID, _ := validationData["user_id"].(string)

	return true, userID, isValid, nil
}

// Token Statistics

// IncrementTokenUsage increments usage statistics for a token
func (t *TokenManager) IncrementTokenUsage(ctx context.Context, tokenID string, expiration time.Duration) (int64, error) {
	key := t.tokenUsageKey(tokenID)
	count, err := t.redis.IncrementWithExpiry(ctx, key, expiration)
	if err != nil {
		return 0, fmt.Errorf("failed to increment token usage: %w", err)
	}
	return count, nil
}

// GetTokenUsage gets the usage count for a token
func (t *TokenManager) GetTokenUsage(ctx context.Context, tokenID string) (int64, error) {
	key := t.tokenUsageKey(tokenID)
	countStr, err := t.redis.Get(ctx, key)
	if err != nil {
		return 0, fmt.Errorf("failed to get token usage: %w", err)
	}

	if countStr == "" {
		return 0, nil
	}

	count, err := strconv.ParseInt(countStr, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("failed to parse token usage count: %w", err)
	}

	return count, nil
}

// Helper methods for key generation

func (t *TokenManager) blacklistKey(tokenID string) string {
	return fmt.Sprintf("token:blacklist:%s", tokenID)
}

func (t *TokenManager) whitelistKey(tokenID string) string {
	return fmt.Sprintf("token:whitelist:%s", tokenID)
}

func (t *TokenManager) rateLimitKey(key string) string {
	return fmt.Sprintf("ratelimit:%s", key)
}

func (t *TokenManager) apiKeyCacheKey(keyHash string) string {
	return fmt.Sprintf("apikey:cache:%s", keyHash)
}

func (t *TokenManager) tokenUsageKey(tokenID string) string {
	return fmt.Sprintf("token:usage:%s", tokenID)
}