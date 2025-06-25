package cache

import (
	"context"
	"fmt"
	"time"

	"adc-sso-service/internal/config"

	"github.com/redis/go-redis/v9"
	"github.com/sirupsen/logrus"
)

// RedisClient wraps the Redis client with additional functionality
type RedisClient struct {
	client *redis.Client
	config *config.Config
}

// NewRedisClient creates a new Redis client instance
func NewRedisClient(cfg *config.Config) (*RedisClient, error) {
	// Parse Redis URL
	opts, err := redis.ParseURL(cfg.RedisURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse Redis URL: %w", err)
	}

	// Override with specific config if provided
	if cfg.RedisPassword != "" {
		opts.Password = cfg.RedisPassword
	}
	opts.DB = cfg.RedisDB

	// Create Redis client
	client := redis.NewClient(opts)

	// Test connection
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := client.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("failed to connect to Redis: %w", err)
	}

	logrus.WithFields(logrus.Fields{
		"redis_url": cfg.RedisURL,
		"redis_db":  cfg.RedisDB,
	}).Info("Successfully connected to Redis")

	return &RedisClient{
		client: client,
		config: cfg,
	}, nil
}

// Get retrieves a value from Redis
func (r *RedisClient) Get(ctx context.Context, key string) (string, error) {
	result := r.client.Get(ctx, key)
	if err := result.Err(); err != nil {
		if err == redis.Nil {
			return "", nil // Key doesn't exist
		}
		logrus.WithError(err).WithField("key", key).Error("Failed to get value from Redis")
		return "", err
	}
	return result.Val(), nil
}

// Set stores a value in Redis with expiration
func (r *RedisClient) Set(ctx context.Context, key string, value interface{}, expiration time.Duration) error {
	err := r.client.Set(ctx, key, value, expiration).Err()
	if err != nil {
		logrus.WithError(err).WithFields(logrus.Fields{
			"key":        key,
			"expiration": expiration,
		}).Error("Failed to set value in Redis")
		return err
	}
	return nil
}

// Delete removes a key from Redis
func (r *RedisClient) Delete(ctx context.Context, key string) error {
	err := r.client.Del(ctx, key).Err()
	if err != nil {
		logrus.WithError(err).WithField("key", key).Error("Failed to delete key from Redis")
		return err
	}
	return nil
}

// Exists checks if a key exists in Redis
func (r *RedisClient) Exists(ctx context.Context, key string) (bool, error) {
	result := r.client.Exists(ctx, key)
	if err := result.Err(); err != nil {
		logrus.WithError(err).WithField("key", key).Error("Failed to check key existence in Redis")
		return false, err
	}
	return result.Val() > 0, nil
}

// SetNX sets a key only if it doesn't exist (atomic operation)
func (r *RedisClient) SetNX(ctx context.Context, key string, value interface{}, expiration time.Duration) (bool, error) {
	result := r.client.SetNX(ctx, key, value, expiration)
	if err := result.Err(); err != nil {
		logrus.WithError(err).WithFields(logrus.Fields{
			"key":        key,
			"expiration": expiration,
		}).Error("Failed to set value with SetNX in Redis")
		return false, err
	}
	return result.Val(), nil
}

// Increment atomically increments a counter
func (r *RedisClient) Increment(ctx context.Context, key string) (int64, error) {
	result := r.client.Incr(ctx, key)
	if err := result.Err(); err != nil {
		logrus.WithError(err).WithField("key", key).Error("Failed to increment counter in Redis")
		return 0, err
	}
	return result.Val(), nil
}

// IncrementWithExpiry atomically increments a counter and sets expiration
func (r *RedisClient) IncrementWithExpiry(ctx context.Context, key string, expiration time.Duration) (int64, error) {
	pipe := r.client.Pipeline()
	incrCmd := pipe.Incr(ctx, key)
	pipe.Expire(ctx, key, expiration)
	
	if _, err := pipe.Exec(ctx); err != nil {
		logrus.WithError(err).WithFields(logrus.Fields{
			"key":        key,
			"expiration": expiration,
		}).Error("Failed to increment with expiry in Redis")
		return 0, err
	}
	
	return incrCmd.Val(), nil
}

// GetTTL returns the time-to-live for a key
func (r *RedisClient) GetTTL(ctx context.Context, key string) (time.Duration, error) {
	result := r.client.TTL(ctx, key)
	if err := result.Err(); err != nil {
		logrus.WithError(err).WithField("key", key).Error("Failed to get TTL from Redis")
		return 0, err
	}
	return result.Val(), nil
}

// Health checks Redis connectivity
func (r *RedisClient) Health(ctx context.Context) error {
	return r.client.Ping(ctx).Err()
}

// Close closes the Redis connection
func (r *RedisClient) Close() error {
	return r.client.Close()
}

// GetClient returns the underlying Redis client for advanced operations
func (r *RedisClient) GetClient() *redis.Client {
	return r.client
}

// Stats returns Redis connection statistics
func (r *RedisClient) Stats() *redis.PoolStats {
	return r.client.PoolStats()
}