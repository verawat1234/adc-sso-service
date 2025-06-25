# SSO Service Integration Guide

## Quick Start

### 1. Start SSO Service Infrastructure

```bash
cd /Users/weerawat/Desktop/adc/adc-sso-service
./start.sh
```

This starts:
- Keycloak (port 8180)
- PostgreSQL for Keycloak (port 5433)
- PostgreSQL for SSO service (port 5434)
- Redis (port 6379)

### 2. Start SSO Service

```bash
cd /Users/weerawat/Desktop/adc/adc-sso-service
export DATABASE_URL="postgresql://adc_user:adc_password@localhost:5434/adc_sso"
go run main.go
```

The SSO service will be available at `http://localhost:9000`

### 3. Integrate with ADC BrandKit

Update adc-brandkit's environment:

```bash
# Add to backend/.env
SSO_SERVICE_URL=http://localhost:9000
```

Start adc-brandkit backend:

```bash
cd /Users/weerawat/Desktop/adc/adc-brandkit/backend
go run main.go
```

## Integration Pattern for Other Services

### 1. Add SDK Dependency

```bash
go get github.com/verawat1234/adc-sso-service/sdk
```

### 2. Initialize SSO Client

```go
import "github.com/verawat1234/adc-sso-service/sdk"

ssoClient := sdk.NewSSOClient("http://localhost:9000")
```

### 3. Add SSO Routes

```go
// Get SSO login URL
router.GET("/auth/sso/login", func(c *gin.Context) {
    loginResp, err := ssoClient.GetSSOLoginURL()
    if err != nil {
        c.JSON(500, gin.H{"error": err.Error()})
        return
    }
    c.Redirect(302, loginResp.RedirectURL)
})

// Handle SSO callback
router.GET("/auth/sso/callback", func(c *gin.Context) {
    code := c.Query("code")
    state := c.Query("state")
    
    callbackResp, err := ssoClient.HandleSSOCallback(code, state)
    if err != nil {
        c.JSON(500, gin.H{"error": err.Error()})
        return
    }
    
    // Process user in local database
    // Store tokens in session
    c.JSON(200, callbackResp)
})
```

### 4. Token Validation Middleware

```go
func SSOAuthMiddleware(ssoClient *sdk.SSOClient) gin.HandlerFunc {
    return func(c *gin.Context) {
        token := c.GetHeader("Authorization")
        if token == "" {
            c.JSON(401, gin.H{"error": "Missing token"})
            c.Abort()
            return
        }
        
        if len(token) > 7 && token[:7] == "Bearer " {
            token = token[7:]
        }
        
        validationResp, err := ssoClient.ValidateToken(token)
        if err != nil || !validationResp.Valid {
            c.JSON(401, gin.H{"error": "Invalid token"})
            c.Abort()
            return
        }
        
        c.Set("user_id", validationResp.UserID)
        c.Set("email", validationResp.Email)
        c.Next()
    }
}
```

## Service URLs

| Service | URL | Description |
|---------|-----|-------------|
| SSO Service | http://localhost:9000 | Main SSO API |
| Keycloak Admin | http://localhost:8180/admin | Admin console (admin/admin_password) |
| Health Check | http://localhost:9000/health | Service health |

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/sso/login` | Get SSO login URL |
| GET | `/sso/callback` | Handle OAuth callback |
| POST | `/sso/validate` | Validate access token |
| POST | `/sso/refresh` | Refresh access token |
| GET | `/health` | Health check |

## Environment Variables

```bash
# SSO Service Configuration
PORT=9000
DATABASE_URL=postgresql://adc_user:adc_password@localhost:5434/adc_sso
JWT_SECRET=your-super-secret-jwt-key

# Keycloak Configuration
KEYCLOAK_URL=http://localhost:8180
KEYCLOAK_REALM=adc-brandkit
KEYCLOAK_CLIENT_ID=adc-brandkit-app
KEYCLOAK_CLIENT_SECRET=adc-brandkit-client-secret
KEYCLOAK_REDIRECT_URI=http://localhost:3000/auth/sso/callback

# Client Services
FRONTEND_URL=http://localhost:3000
```

## Testing

```bash
# Test SSO service health
curl http://localhost:9000/health

# Test SSO login URL generation
curl http://localhost:9000/sso/login

# Test token validation
curl -X POST http://localhost:9000/sso/validate \
  -H "Content-Type: application/json" \
  -d '{"access_token":"your-jwt-token"}'
```

## Production Deployment

1. **Deploy SSO Service:**
   - Use Docker image or binary deployment
   - Configure production database
   - Set up Keycloak with HTTPS

2. **Update Client Services:**
   - Set `SSO_SERVICE_URL` to production URL
   - Update Keycloak redirect URIs
   - Configure production secrets

3. **Security Considerations:**
   - Use HTTPS in production
   - Secure JWT secrets
   - Configure CORS properly
   - Set up proper firewall rules

## Troubleshooting

### SSO Service Won't Start

1. Check database connection
2. Verify environment variables
3. Check port availability

### Keycloak Issues

1. Check Keycloak logs: `docker logs adc-keycloak`
2. Verify realm configuration
3. Check client credentials

### Token Validation Fails

1. Check token expiration
2. Verify JWT secret consistency
3. Check user status in database