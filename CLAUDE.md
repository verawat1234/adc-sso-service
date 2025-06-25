# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

ADC SSO Service is a standalone Single Sign-On microservice built in Go using the Gin framework. It provides centralized authentication for all ADC applications using Keycloak as the identity provider. The service offers enterprise-grade security with JWT tokens, API key management, multi-tenant organization support, and comprehensive audit logging.

## Development Commands

### Infrastructure Management
```bash
# Start all infrastructure services (Keycloak, PostgreSQL, Redis)
./start.sh

# Stop infrastructure services
docker-compose down

# Check service health
curl http://localhost:9000/health
curl http://localhost:8180/health/ready
```

### Running the Service
```bash
# Set database connection
export DATABASE_URL="postgresql://adc_user:adc_password@localhost:5434/adc_sso"

# Run the service (default port 9000)
go run main.go

# Run with custom port
export PORT=8080
go run main.go
```

### Database Operations
```bash
# Access SSO service database
docker exec -it adc-sso-db psql -U adc_user -d adc_sso

# Access Keycloak database
docker exec -it adc-keycloak-db psql -U keycloak -d keycloak
```

### Testing and Development
```bash
# Run working tests (auth and utils components)
go test ./internal/auth ./internal/utils -v

# Run with coverage for working components
go test -cover ./internal/auth ./internal/utils

# Run specific working test suites
go test -v ./internal/auth          # ✅ PASSING - 15 test cases
go test -v ./internal/utils         # ✅ PASSING - 15 test cases

# PostgreSQL-based test suites (individual tests work, concurrent execution has issues)
go test ./internal/models -run "TestAPIKeyModelTestSuite/TestGenerateAPIKey" -v  # ✅ PASSING
go test ./internal/models -run "TestUserModelTestSuite/TestUserHelperMethods" -v # ✅ PASSING

# Test suites with remaining issues
# go test -v ./internal/models      # ❌ Prepared statement conflicts with concurrent execution
# go test -v ./internal/middleware  # ❌ Prepared statement conflicts
# go test -v ./internal/handlers    # ❌ Import cycle issues
# go test -v ./e2e_test.go          # ❌ Route setup issues

# Manual API testing
curl http://localhost:9000/sso/login
curl -X POST http://localhost:9000/sso/validate \
  -H "Content-Type: application/json" \
  -d '{"access_token":"your-jwt-token"}'
curl http://localhost:9000/health
curl http://localhost:8180/health/ready
```

### Test Architecture
The codebase includes comprehensive test implementation with current status:

**Unit Tests**:
- ✅ `internal/auth/auth_test.go` - JWT token generation/validation, refresh tokens (15 tests)
- ✅ `internal/utils/response_test.go` - API response formatting (15 tests)
- ❌ `internal/models/user_test.go` - Database models (SQLite compatibility issues)

**Integration Tests**:
- ❌ `internal/middleware/auth_test.go` - Authentication middleware (SQLite compatibility)
- ❌ `internal/handlers/*_test.go` - API endpoints (import cycle issues)
  - `auth_test.go` - SSO flows, token validation
  - `organization_test.go` - Organization CRUD, member management
  - `apikey_test.go` - API key lifecycle, permissions
  - `health_test.go` - Health checks

**End-to-End Tests**:
- ❌ `e2e_test.go` - Complete workflows (SQLite compatibility issues)

**Test Utilities** (`internal/testutils/`):
- `database.go` - In-memory SQLite test database setup
- `fixtures.go` - Test data creation helpers
- `mocks.go` - Mock Keycloak server for SSO testing
- `helpers.go` - HTTP testing utilities, authentication helpers

**Working Test Coverage (30 test cases passing)**:
- JWT token generation, validation, and refresh logic
- Token expiration and security validations
- Concurrent token operations
- HTTP response helpers and error handling
- Response consistency and edge cases

**PostgreSQL Migration Success**:
✅ **Database Migration**: Successfully migrated from SQLite to PostgreSQL (Supabase)
✅ **UUID Generation**: PostgreSQL `gen_random_uuid()` function now working correctly
✅ **Model Validation**: Individual model tests pass with real database constraints
✅ **API Key Generation**: Full API key lifecycle tests working

**Remaining Issues**:
1. **Prepared Statement Conflicts**: Concurrent test execution causes PostgreSQL prepared statement conflicts
2. **Import Cycles**: Test utilities create circular dependencies with handlers/middleware  
3. **Route Setup**: E2E tests have router configuration issues

**Database Configuration**:
- **Production**: Supabase PostgreSQL with full schema and constraints
- **Testing**: Same Supabase PostgreSQL database for realistic testing
- **Connection**: `postgresql://postgres.rifsieaejflaeaqwwjvk:KL3hWne8KKYAUzZM@aws-0-ap-southeast-1.pooler.supabase.com:6543/postgres`

**Recommended Test Execution**:
```bash
# Run core business logic tests (always working)
go test ./internal/auth ./internal/utils -v -cover

# Run individual PostgreSQL-based tests
go test ./internal/models -run "TestAPIKeyModelTestSuite/TestGenerateAPIKey" -v
go test ./internal/models -run "TestUserModelTestSuite/TestUserHelperMethods" -v
```

## Architecture

### Core Components
- **Authentication Service**: JWT token generation and validation
- **SSO Integration**: Keycloak OAuth2/OpenID Connect flow
- **Multi-tenancy**: Organization-based access control
- **API Key Management**: Programmatic access with permissions
- **Audit Logging**: Comprehensive security event tracking

### Database Schema
The service uses PostgreSQL with the following key models:
- `User`: User accounts with roles and status
- `Organization`: Multi-tenant organizations
- `UserOrganization`: Many-to-many user-organization relationships
- `APIKey`: API keys for programmatic access
- `SSOUserMapping`: SSO provider mappings
- `AuditLog`: Security and access audit events

### Key Packages
- `internal/auth`: JWT and authentication logic
- `internal/handlers`: HTTP request handlers for all endpoints
- `internal/middleware`: Authentication and authorization middleware
- `internal/models`: Database models and business logic
- `internal/config`: Configuration management
- `internal/database`: Database connection and setup
- `sdk/`: Go SDK for client applications

## Configuration

### Environment Variables
```bash
# Service Configuration
PORT=9000
DATABASE_URL=postgresql://adc_user:adc_password@localhost:5434/adc_sso
JWT_SECRET=your-super-secret-jwt-key

# Keycloak Configuration
KEYCLOAK_URL=http://localhost:8180
KEYCLOAK_REALM=adc-brandkit
KEYCLOAK_CLIENT_ID=adc-brandkit-app
KEYCLOAK_CLIENT_SECRET=adc-brandkit-client-secret
KEYCLOAK_REDIRECT_URI=http://localhost:3000/auth/sso/callback

# Frontend Integration
FRONTEND_URL=http://localhost:3000
```

### Service URLs and Ports
- **SSO Service**: http://localhost:9000
- **Keycloak**: http://localhost:8180 (admin: admin/admin_password)
- **PostgreSQL (SSO)**: localhost:5434
- **PostgreSQL (Keycloak)**: localhost:5433
- **Redis**: localhost:6379

## API Structure

### Core SSO Endpoints
- `GET /sso/login` - Generate SSO login URL
- `GET /sso/callback` - Handle OAuth callback from Keycloak
- `POST /sso/validate` - Validate JWT tokens
- `POST /sso/refresh` - Refresh access tokens

### Organization Management
- `GET|POST /api/v1/organizations` - List/create organizations
- `GET|PUT|DELETE /api/v1/organizations/{id}` - Manage specific organization
- `GET /api/v1/organizations/{id}/members` - Organization members

### API Key Management
- `POST /api/v1/organizations/{id}/api-keys` - Create API key
- `GET /api/v1/organizations/{id}/api-keys` - List API keys
- `PUT|DELETE /api/v1/organizations/{id}/api-keys/{key_id}` - Manage API key

### Authentication Methods
The service supports flexible authentication:
1. **JWT Bearer tokens** - For user sessions
2. **API keys** - For programmatic access (header: `X-API-Key` or query: `api_key`)
3. **Flexible middleware** - Accepts either JWT or API key

### Middleware Chain
- `Logger()` - Request logging
- `Recovery()` - Panic recovery
- `CORS` - Cross-origin resource sharing
- `FlexibleAuthMiddleware()` - JWT or API key authentication
- `RequireOrganizationAccess()` - Organization-level authorization
- `RequireRole()` - Role-based access control

## Integration Patterns

### Client Integration (using SDK)
```go
import "github.com/verawat1234/adc-sso-service/sdk"

ssoClient := sdk.NewSSOClient("http://localhost:9000")
loginResp, err := ssoClient.GetSSOLoginURL()
callbackResp, err := ssoClient.HandleSSOCallback(code, state)
validationResp, err := ssoClient.ValidateToken(accessToken)
```

### Authentication Middleware Pattern
For protecting routes in client applications:
```go
func AuthMiddleware(ssoClient *sdk.SSOClient) gin.HandlerFunc {
    return func(c *gin.Context) {
        token := extractBearerToken(c)
        validation, err := ssoClient.ValidateToken(token)
        if err != nil || !validation.Valid {
            c.JSON(401, gin.H{"error": "Unauthorized"})
            c.Abort()
            return
        }
        // Set user context and continue
        c.Set("user_id", validation.UserID)
        c.Next()
    }
}
```

## Security Features

### Token Management
- **JWT Access Tokens**: 24-hour expiration
- **Secure State Parameters**: CSRF protection for OAuth flows
- **Refresh Tokens**: Long-lived tokens for session renewal
- **API Key Hashing**: SHA256 hashing with secure random generation

### Audit and Monitoring
- **Comprehensive Logging**: All authentication and authorization events
- **Request Tracking**: IP address, User-Agent, Request ID logging
- **Usage Analytics**: API key usage tracking and statistics
- **Security Events**: Failed auth attempts, permission denials

### Multi-tenancy
- **Organization Isolation**: Data scoped to organization boundaries
- **Role-based Access**: User, Admin, Owner roles within organizations
- **API Key Scoping**: API keys scoped to specific organizations and permissions

## Development Guidelines

### Code Patterns
- Use `utils.NewResponseHelper(c)` for consistent API responses
- All database operations should include error handling
- Use UUID for all primary keys
- Implement proper GORM hooks for model initialization
- Use structured logging with logrus

### Security Practices
- Never log sensitive data (passwords, tokens, API keys)
- Always hash API keys before storage
- Use secure random generation for tokens and states
- Implement proper CORS configuration for production
- Validate all input parameters and sanitize data

### Error Handling
- Use appropriate HTTP status codes
- Provide helpful error messages without exposing internal details
- Log errors with sufficient context for debugging
- Handle database errors gracefully

This SSO service is designed to be the central authentication hub for all ADC applications, providing secure, scalable, and maintainable identity management.