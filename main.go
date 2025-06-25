package main

import (
	"log"
	"net/http"
	"os"
	"time"

	"adc-sso-service/internal/auth"
	"adc-sso-service/internal/cache"
	"adc-sso-service/internal/config"
	"adc-sso-service/internal/database"
	"adc-sso-service/internal/handlers"
	"adc-sso-service/internal/middleware"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
)

func main() {
	// Initialize logger
	logrus.SetFormatter(&logrus.JSONFormatter{})
	logrus.SetLevel(logrus.InfoLevel)

	// Load configuration
	cfg := config.Load()
	
	// Connect to database
	db, err := database.Connect(cfg.DatabaseURL)
	if err != nil {
		log.Fatal("Failed to connect to database:", err)
	}

	// Connect to Redis
	redisClient, err := cache.NewRedisClient(cfg)
	if err != nil {
		log.Fatal("Failed to connect to Redis:", err)
	}
	defer redisClient.Close()

	// Initialize cache services
	sessionManager := cache.NewSessionManager(redisClient)
	_ = cache.NewTokenManager(redisClient) // Token manager for future use

	// Initialize services
	authService := auth.NewAuthService(cfg.JWTSecret)
	authMiddleware := middleware.NewAuthMiddleware(authService, db)

	// Initialize handlers
	authHandler := handlers.NewAuthHandler(db, authService, cfg, sessionManager)
	healthHandler := handlers.NewHealthHandler(db, redisClient)
	orgHandler := handlers.NewOrganizationHandler(db)
	apiKeyHandler := handlers.NewAPIKeyHandler(db)

	// Setup router
	router := gin.Default()

	// Middleware
	router.Use(middleware.Logger())
	router.Use(middleware.Recovery())
	router.Use(cors.New(cors.Config{
		AllowOrigins:     []string{"*"}, // Configure for production
		AllowMethods:     []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowHeaders:     []string{"*"},
		ExposeHeaders:    []string{"*"},
		AllowCredentials: true,
		MaxAge:           12 * time.Hour,
	}))

	// Health check
	router.GET("/health", healthHandler.Health)

	// SSO routes
	ssoGroup := router.Group("/sso")
	{
		ssoGroup.GET("/login", authHandler.RedirectToSSO)
		ssoGroup.GET("/callback", authHandler.HandleSSOCallback)
		ssoGroup.POST("/validate", authHandler.ValidateToken)
		ssoGroup.POST("/refresh", authHandler.RefreshToken)
	}

	// Protected API routes
	api := router.Group("/api/v1")
	{
		// Organization management
		organizations := api.Group("/organizations")
		organizations.Use(authMiddleware.FlexibleAuthMiddleware())
		{
			organizations.POST("", orgHandler.CreateOrganization)
			organizations.GET("", orgHandler.ListOrganizations)
			
			// Organization-specific routes
			orgRoutes := organizations.Group("/:org_id")
			orgRoutes.Use(authMiddleware.RequireOrganizationAccess())
			{
				orgRoutes.GET("", orgHandler.GetOrganization)
				orgRoutes.PUT("", orgHandler.UpdateOrganization)
				orgRoutes.DELETE("", orgHandler.DeleteOrganization)
				orgRoutes.GET("/members", orgHandler.ListOrganizationMembers)
				
				// API Key management
				apiKeys := orgRoutes.Group("/api-keys")
				{
					apiKeys.POST("", apiKeyHandler.CreateAPIKey)
					apiKeys.GET("", apiKeyHandler.ListAPIKeys)
					apiKeys.GET("/:key_id", apiKeyHandler.GetAPIKey)
					apiKeys.PUT("/:key_id", apiKeyHandler.UpdateAPIKey)
					apiKeys.DELETE("/:key_id", apiKeyHandler.DeleteAPIKey)
					apiKeys.POST("/:key_id/regenerate", apiKeyHandler.RegenerateAPIKey)
				}
			}
		}
		
		// Authentication and token management
		auth := api.Group("/auth")
		{
			auth.POST("/validate", authHandler.ValidateToken)
			auth.POST("/refresh", authHandler.RefreshToken)
		}
	}

	// API documentation
	router.GET("/", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"service": "ADC SSO Service - Enhanced",
			"version": "2.0.0",
			"description": "Centralized authentication and authorization service for ADC ecosystem",
			"features": []string{
				"JWT Authentication",
				"API Key Management", 
				"Organization Multi-tenancy",
				"Role-based Access Control",
				"SSO Integration (Keycloak)",
				"Comprehensive Audit Logging",
			},
			"endpoints": gin.H{
				"health":             "GET /health",
				"sso_login":          "GET /sso/login",
				"sso_callback":       "GET /sso/callback",
				"validate_token":     "POST /api/v1/auth/validate",
				"refresh_token":      "POST /api/v1/auth/refresh",
				"current_user":       "GET /api/v1/auth/me",
				"organizations":      "GET|POST /api/v1/organizations",
				"organization":       "GET|PUT|DELETE /api/v1/organizations/{id}",
				"api_keys":          "GET|POST /api/v1/organizations/{id}/api-keys",
				"admin_users":       "GET /api/v1/admin/users",
				"admin_audit":       "GET /api/v1/admin/audit-logs",
			},
		})
	})

	port := os.Getenv("PORT")
	if port == "" {
		port = "9000"
	}

	logrus.WithField("port", port).Info("Starting ADC SSO Service")
	
	if err := router.Run(":" + port); err != nil {
		log.Fatal("Failed to start server:", err)
	}
}