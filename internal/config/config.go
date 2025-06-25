package config

import (
	"os"
	"strconv"
)

type Config struct {
	// Server
	Port string

	// Database
	DatabaseURL string

	// Redis
	RedisURL      string
	RedisPassword string
	RedisDB       int

	// JWT
	JWTSecret string

	// Keycloak SSO
	KeycloakURL        string
	KeycloakRealm      string
	KeycloakClientID   string
	KeycloakClientSecret string
	KeycloakRedirectURI string

	// Frontend
	FrontendURL string

	// Security
	AllowedOrigins []string
}

func Load() *Config {
	return &Config{
		Port:        getEnvOrDefault("PORT", "9000"),
		DatabaseURL: getEnvOrDefault("DATABASE_URL", "postgresql://postgres.rifsieaejflaeaqwwjvk:KL3hWne8KKYAUzZM@aws-0-ap-southeast-1.pooler.supabase.com:6543/postgres"),
		
		// Redis Configuration
		RedisURL:      getEnvOrDefault("REDIS_URL", "redis://default:dvr6imnAnMm1bEH1Sb3YGPtqnnDl6Ecj@redis-18465.c62.us-east-1-4.ec2.redns.redis-cloud.com:18465"),
		RedisPassword: getEnvOrDefault("REDIS_PASSWORD", "dvr6imnAnMm1bEH1Sb3YGPtqnnDl6Ecj"),
		RedisDB:       getEnvAsIntOrDefault("REDIS_DB", 0),
		
		JWTSecret:   getEnvOrDefault("JWT_SECRET", "your-super-secret-jwt-key-change-in-production"),

		// Keycloak Configuration
		KeycloakURL:          getEnvOrDefault("KEYCLOAK_URL", "http://localhost:8180"),
		KeycloakRealm:        getEnvOrDefault("KEYCLOAK_REALM", "adc-brandkit"),
		KeycloakClientID:     getEnvOrDefault("KEYCLOAK_CLIENT_ID", "adc-brandkit-app"),
		KeycloakClientSecret: getEnvOrDefault("KEYCLOAK_CLIENT_SECRET", "adc-brandkit-client-secret"),
		KeycloakRedirectURI:  getEnvOrDefault("KEYCLOAK_REDIRECT_URI", "http://localhost:3000/auth/sso/callback"),

		FrontendURL: getEnvOrDefault("FRONTEND_URL", "http://localhost:3000"),
		AllowedOrigins: []string{
			getEnvOrDefault("FRONTEND_URL", "http://localhost:3000"),
			"http://localhost:3000",
			"http://localhost:8080",
		},
	}
}

func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getEnvAsIntOrDefault(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		if intValue, err := strconv.Atoi(value); err == nil {
			return intValue
		}
	}
	return defaultValue
}

func getEnvAsBoolOrDefault(key string, defaultValue bool) bool {
	if value := os.Getenv(key); value != "" {
		if boolValue, err := strconv.ParseBool(value); err == nil {
			return boolValue
		}
	}
	return defaultValue
}