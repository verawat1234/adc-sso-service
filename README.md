# ADC SSO Service - Standalone Authentication Microservice

🔐 **Standalone SSO service for all ADC applications**

## Overview

This standalone SSO service provides **centralized authentication** for all ADC applications, powered by **Keycloak** as the identity provider. It offers enterprise-grade security, scalability, and support for multiple authentication providers.

**Supported Applications:**
- adc-brandkit
- adc-account-web  
- adc-credit
- adc-shop
- adc-restaurant
- Any future ADC services

## Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Frontend      │    │   Backend       │    │   Keycloak      │
│   (Next.js)     │    │   (Go API)      │    │   (SSO Service) │
│   Port: 3000    │    │   Port: 8800    │    │   Port: 8180    │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         │              ┌─────────────────┐              │
         └──────────────│   PostgreSQL    │──────────────┘
                        │   (Database)    │
                        │   Port: 5432    │
                        └─────────────────┘
                                 │
                        ┌─────────────────┐
                        │     Redis       │
                        │    (Cache)      │
                        │   Port: 6379    │
                        └─────────────────┘
```

## Benefits of SSO Microservice

✅ **Security Isolation**: SSO logic separated from business logic  
✅ **Independent Scaling**: Scale authentication based on demand  
✅ **Multi-Application Support**: One SSO service for multiple apps  
✅ **Enterprise Standards**: SAML, OIDC, OAuth2 support  
✅ **Provider Management**: Easy addition of new identity providers  
✅ **Audit & Compliance**: Comprehensive authentication logging  

## Quick Start

### 1. Start All Services

```bash
# Start infrastructure services (Keycloak, PostgreSQL, Redis)
./start-sso-services.sh

# Start backend API
cd backend && ./adc-brandkit-backend

# Start frontend (in another terminal)
npm run dev
```

### 2. Access Services

- **Application**: http://localhost:3000
- **Keycloak Admin**: http://localhost:8180/admin (admin/admin_password)
- **API Documentation**: http://localhost:8800/api/v1/health

## SSO Authentication Flow

```mermaid
sequenceDiagram
    participant U as User
    participant F as Frontend
    participant B as Backend
    participant K as Keycloak

    U->>F: Click "Sign in with SSO"
    F->>B: GET /api/v1/auth/sso/login
    B->>B: Generate state parameter
    B->>F: Return Keycloak redirect URL
    F->>K: Redirect to Keycloak login
    K->>U: Show login form
    U->>K: Enter credentials
    K->>F: Redirect with auth code
    F->>B: GET /api/v1/auth/sso/callback?code=...
    B->>K: Exchange code for tokens
    K->>B: Return access token + user info
    B->>B: Create/update local user
    B->>F: Return JWT token + user data
    F->>U: User logged in
```

## Environment Configuration

### Backend (.env.keycloak)

```env
# Keycloak SSO Configuration
KEYCLOAK_URL=http://localhost:8180
KEYCLOAK_REALM=adc-brandkit
KEYCLOAK_CLIENT_ID=adc-brandkit-app
KEYCLOAK_CLIENT_SECRET=adc-brandkit-client-secret
KEYCLOAK_REDIRECT_URI=http://localhost:3000/auth/sso/callback

# Backend Configuration
PORT=8800
DATABASE_URL=postgresql://adc_user:adc_password@localhost:5432/adc_brandkit
REDIS_URL=redis://localhost:6379
JWT_SECRET=your-super-secret-jwt-key
```

### Production Configuration

For production deployment, update URLs to use your actual domains:

```env
KEYCLOAK_URL=https://sso.yourdomain.com
KEYCLOAK_REDIRECT_URI=https://app.yourdomain.com/auth/sso/callback
FRONTEND_URL=https://app.yourdomain.com
```

## API Endpoints

### SSO Authentication

```bash
# Get SSO login URL
GET /api/v1/auth/sso/login
Response: {
  "redirect_url": "https://keycloak.../auth?...",
  "state": "secure-state-token"
}

# Handle SSO callback
GET /api/v1/auth/sso/callback?code=...&state=...
Response: {
  "auth": {
    "user": {...},
    "access_token": "jwt-token",
    "refresh_token": "refresh-token"
  },
  "is_new_user": false,
  "sso_source": "keycloak"
}
```

### Traditional Authentication (Still Available)

```bash
# Register new user
POST /api/v1/auth/register

# Login with username/password
POST /api/v1/auth/login

# Refresh JWT token
POST /api/v1/auth/refresh
```

## Keycloak Configuration

### Adding Identity Providers

1. Access Keycloak Admin: http://localhost:8180/admin
2. Select "adc-brandkit" realm
3. Go to Identity Providers
4. Add provider (Google, GitHub, Microsoft, etc.)
5. Configure client credentials

### Example: Google OAuth Setup

1. Create Google OAuth app at https://console.cloud.google.com
2. Add redirect URI: `http://localhost:8180/realms/adc-brandkit/broker/google/endpoint`
3. In Keycloak:
   - Provider: Google
   - Client ID: `your-google-client-id`
   - Client Secret: `your-google-client-secret`

## Database Schema Changes

**Migration v1.6.0** removed embedded SSO models:
- ❌ `sso_providers` (moved to Keycloak)
- ❌ `sso_user_mappings` (handled by user email linking)
- ❌ `sso_sessions` (handled by Keycloak sessions)
- ❌ `sso_audits` (available in Keycloak logs)

Users are now linked to SSO providers through email matching.

## Development Commands

```bash
# Start/stop infrastructure
./start-sso-services.sh
docker-compose -f docker-compose.sso.yml down

# Backend development
cd backend
go run main.go

# View Keycloak logs
docker logs adc-keycloak -f

# Access Keycloak database
docker exec -it adc-keycloak-db psql -U keycloak -d keycloak

# Backend with SSO environment
cd backend
source .env.keycloak
./adc-brandkit-backend
```

## Testing SSO Integration

```bash
# Test SSO login URL generation
curl http://localhost:8800/api/v1/auth/sso/login

# Test Keycloak health
curl http://localhost:8180/health/ready

# Test traditional auth (still works)
curl -X POST http://localhost:8800/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin123"}'
```

## Production Deployment

### Docker Compose Production

```yaml
services:
  keycloak:
    environment:
      KC_HOSTNAME: sso.yourdomain.com
      KC_HOSTNAME_STRICT_HTTPS: true
      KC_PROXY: edge
      KEYCLOAK_ADMIN: admin
      KEYCLOAK_ADMIN_PASSWORD: ${KEYCLOAK_ADMIN_PASSWORD}
    volumes:
      - ./ssl:/opt/keycloak/conf/ssl
```

### SSL/TLS Configuration

1. Obtain SSL certificates for your domain
2. Configure reverse proxy (nginx/cloudflare)
3. Update Keycloak to use HTTPS
4. Update all redirect URIs to HTTPS

## Troubleshooting

### Common Issues

**Keycloak won't start**
```bash
# Check logs
docker logs adc-keycloak

# Common cause: Port already in use
docker-compose -f docker-compose.sso.yml down
./start-sso-services.sh
```

**SSO callback fails**
- Verify redirect URI in Keycloak client configuration
- Check that state parameter is properly validated
- Ensure cookies are enabled for state management

**User creation fails**
- Check PostgreSQL connection
- Verify user email format
- Check for duplicate usernames

### Logs and Monitoring

```bash
# Backend logs (structured JSON)
tail -f backend/logs/app.log

# Keycloak authentication logs
docker exec adc-keycloak cat /opt/keycloak/data/log/keycloak.log

# Database query logs
docker logs adc-postgres
```

## Security Considerations

✅ **State Parameter**: CSRF protection with secure random state  
✅ **JWT Tokens**: Short-lived access tokens (24h) with refresh capability  
✅ **Secure Cookies**: HTTPOnly, Secure flags in production  
✅ **HTTPS Only**: All authentication flows over TLS in production  
✅ **Client Secrets**: Stored securely, never exposed to frontend  
✅ **Session Management**: Handled by Keycloak with configurable timeouts  

## Migration from Embedded SSO

If upgrading from the previous embedded SSO implementation:

1. **Backup your database** before migration
2. **Run migration v1.6.0** to remove old SSO tables
3. **Update environment variables** to use Keycloak
4. **Configure identity providers** in Keycloak admin
5. **Test authentication flows** thoroughly

## Support

For SSO-related issues:
- Check Keycloak documentation: https://www.keycloak.org/docs/
- Review backend logs for integration issues
- Verify identity provider configurations
- Test with Keycloak's built-in account console