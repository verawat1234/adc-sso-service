package handlers

import (
	"context"
	"net/http"
	"time"

	"adc-sso-service/internal/cache"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

type HealthHandler struct {
	db    *gorm.DB
	redis *cache.RedisClient
}

func NewHealthHandler(db *gorm.DB, redis *cache.RedisClient) *HealthHandler {
	return &HealthHandler{
		db:    db,
		redis: redis,
	}
}

func (h *HealthHandler) Health(c *gin.Context) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	response := gin.H{
		"status":    "healthy",
		"service":   "ADC SSO Service",
		"version":   "2.0.0", // Updated version to reflect Redis integration
		"timestamp": time.Now().UTC(),
	}

	// Check database connection
	sqlDB, err := h.db.DB()
	if err != nil {
		response["status"] = "unhealthy"
		response["database"] = "disconnected"
		response["error"] = err.Error()
		c.JSON(http.StatusServiceUnavailable, response)
		return
	}

	if err := sqlDB.Ping(); err != nil {
		response["status"] = "unhealthy"
		response["database"] = "unreachable"
		response["error"] = err.Error()
		c.JSON(http.StatusServiceUnavailable, response)
		return
	}

	response["database"] = "connected"

	// Check Redis connection
	if err := h.redis.Health(ctx); err != nil {
		response["status"] = "degraded"
		response["redis"] = "disconnected"
		response["redis_error"] = err.Error()
		c.JSON(http.StatusOK, response) // Still return 200 as service can work without Redis
		return
	}

	// Get Redis connection stats
	stats := h.redis.Stats()
	response["redis"] = gin.H{
		"status":       "connected",
		"hits":         stats.Hits,
		"misses":       stats.Misses,
		"timeouts":     stats.Timeouts,
		"total_conns":  stats.TotalConns,
		"idle_conns":   stats.IdleConns,
		"stale_conns":  stats.StaleConns,
	}

	c.JSON(http.StatusOK, response)
}