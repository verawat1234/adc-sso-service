# CI/CD Documentation

## Overview

This document describes the Continuous Integration and Continuous Deployment (CI/CD) pipeline for the ADC SSO Service.

## Pipeline Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Development   │    │     Staging     │    │   Production    │
│                 │    │                 │    │                 │
│ • Local testing │───▶│ • Integration   │───▶│ • Live service  │
│ • Unit tests    │    │ • E2E tests     │    │ • Monitoring    │
│ • Linting       │    │ • Performance   │    │ • Alerts        │
└─────────────────┘    └─────────────────┘    └─────────────────┘
        │                       │                       │
        ▼                       ▼                       ▼
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   GitHub        │    │   GitHub        │    │   GitHub        │
│   Actions       │    │   Actions       │    │   Actions       │
│   (CI/CD)       │    │   (Deploy)      │    │   (Deploy)      │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

## Workflows

### 1. Main CI/CD Pipeline (`.github/workflows/ci.yml`)

**Triggers:**
- Push to `main` or `develop` branches
- Pull requests to `main` or `develop`
- Release creation

**Jobs:**
1. **Code Quality & Security**
   - Go vet analysis
   - Static code analysis (staticcheck)
   - Security scanning (gosec)
   - Linting (golangci-lint)

2. **Unit Tests**
   - Tests on Go 1.22 and 1.23
   - PostgreSQL and Redis integration
   - Coverage reporting to Codecov

3. **Integration Tests**
   - Docker Compose environment
   - End-to-end testing
   - Service health verification

4. **Performance Tests**
   - Load testing with custom framework
   - Redis performance validation
   - Throughput and latency metrics

5. **Build & Push**
   - Multi-platform Docker builds (AMD64, ARM64)
   - Container registry push (GHCR)
   - Image tagging strategy

6. **Deployment**
   - Staging deployment (develop branch)
   - Production deployment (main branch)

### 2. Dependency Scanning (`.github/workflows/dependency-scan.yml`)

**Triggers:**
- Daily schedule (2 AM UTC)
- Push/PR to main branches

**Features:**
- Go module vulnerability scanning (Nancy, govulncheck)
- Docker image security scanning (Trivy)
- Dockerfile linting (Hadolint)
- License compliance checking
- Automated dependency updates

### 3. Environment Deployments

#### Staging (`.github/workflows/deploy-staging.yml`)
- Deploys from `develop` branch
- Runs post-deployment verification
- Performance testing against staging

#### Production (`.github/workflows/deploy-production.yml`)
- Deploys from `main` branch or releases
- Pre-deployment security scans
- Health verification
- Rollback capabilities
- Monitoring setup

## Environment Configuration

### Required Secrets

#### Staging Environment
```
STAGING_KUBE_CONFIG          # Kubernetes config (base64 encoded)
STAGING_DATABASE_URL         # PostgreSQL connection string
STAGING_REDIS_URL           # Redis connection string
STAGING_JWT_SECRET          # JWT signing secret
STAGING_KEYCLOAK_CLIENT_SECRET # Keycloak client secret
```

#### Production Environment
```
PRODUCTION_KUBE_CONFIG       # Kubernetes config (base64 encoded)
PRODUCTION_DATABASE_URL      # PostgreSQL connection string
PRODUCTION_REDIS_URL        # Redis connection string
PRODUCTION_JWT_SECRET       # JWT signing secret
PRODUCTION_KEYCLOAK_CLIENT_SECRET # Keycloak client secret
```

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `DATABASE_URL` | PostgreSQL connection | Required |
| `REDIS_URL` | Redis connection | Required |
| `JWT_SECRET` | JWT signing key | Required |
| `KEYCLOAK_URL` | Keycloak server URL | Required |
| `KEYCLOAK_REALM` | Keycloak realm | `adc-brandkit` |
| `KEYCLOAK_CLIENT_ID` | OAuth client ID | `adc-brandkit-app` |
| `KEYCLOAK_CLIENT_SECRET` | OAuth client secret | Required |
| `FRONTEND_URL` | Frontend application URL | Required |
| `PORT` | Service port | `9000` |
| `GIN_MODE` | Gin framework mode | `release` |

## Container Strategy

### Base Images
- **Build Stage**: `golang:1.23-alpine`
- **Runtime Stage**: `alpine:latest`

### Security Features
- Non-root user execution
- Read-only filesystem
- Dropped capabilities
- Security context enforcement

### Health Checks
- HTTP health endpoint (`/health`)
- 30-second intervals
- 3-retry failure tolerance

## Kubernetes Deployment

### Resources
```yaml
requests:
  memory: "256Mi"
  cpu: "250m"
limits:
  memory: "512Mi"
  cpu: "500m"
```

### Scaling
- **Staging**: 2 replicas
- **Production**: 3 replicas

### Probes
- **Liveness**: `/health` endpoint, 30s interval
- **Readiness**: `/health` endpoint, 5s interval

## Monitoring & Alerting

### Health Checks
- Application health endpoint
- Database connectivity
- Redis connectivity
- Response time monitoring

### Performance Metrics
- Request throughput
- Response latency (P95, P99)
- Error rates
- Cache hit/miss ratios

### Deployment Verification
- Automated smoke tests
- Performance baseline validation
- Rollback triggers on failure

## Development Workflow

### Branch Strategy
```
main (production)
├── develop (staging)
│   ├── feature/redis-integration
│   ├── feature/performance-testing
│   └── hotfix/security-patch
└── release/v2.0.0
```

### Testing Strategy
1. **Local Development**
   ```bash
   make test                    # Unit tests
   make perf-smoke             # Quick performance test
   docker-compose up           # Integration testing
   ```

2. **Pull Request**
   - Automated CI/CD pipeline
   - Code quality checks
   - Security scanning
   - Unit and integration tests

3. **Staging Deployment**
   - Automatic on merge to `develop`
   - Full integration testing
   - Performance validation

4. **Production Deployment**
   - Automatic on merge to `main`
   - Security verification
   - Gradual rollout
   - Monitoring validation

## Manual Deployment

### Deploy Specific Version
```bash
# Trigger manual deployment
gh workflow run deploy-staging.yml -f image_tag=v2.0.1
gh workflow run deploy-production.yml -f image_tag=v2.0.1
```

### Emergency Rollback
```bash
# Rollback to previous version
kubectl rollout undo deployment/adc-sso-service -n adc-sso-production
```

## Troubleshooting

### Common Issues

1. **Test Failures**
   - Check database connectivity
   - Verify Redis availability
   - Review environment variables

2. **Deployment Failures**
   - Validate Kubernetes configuration
   - Check secret availability
   - Review resource limits

3. **Performance Issues**
   - Monitor Redis performance
   - Check database query performance
   - Verify network latency

### Debug Commands
```bash
# Check deployment status
kubectl get pods -n adc-sso-production

# View application logs
kubectl logs -f deployment/adc-sso-service -n adc-sso-production

# Port forward for debugging
kubectl port-forward service/adc-sso-service 8080:80 -n adc-sso-production

# Check health endpoint
curl http://localhost:8080/health
```

## Security Considerations

### Image Scanning
- Trivy vulnerability scanning
- Base image security updates
- Dependency vulnerability checks

### Runtime Security
- Non-root container execution
- Read-only root filesystem
- Security context enforcement
- Network policies (recommended)

### Secrets Management
- Kubernetes secrets for sensitive data
- Secret rotation procedures
- Environment-specific configurations

## Performance Optimization

### Build Optimization
- Multi-stage Docker builds
- Layer caching strategy
- Minimal runtime images

### Runtime Optimization
- Connection pooling
- Redis caching strategy
- Database query optimization
- Horizontal pod autoscaling

## Maintenance

### Regular Tasks
- Dependency updates (automated weekly)
- Security patch reviews
- Performance monitoring review
- Log analysis and cleanup

### Scheduled Maintenance
- Monthly security reviews
- Quarterly performance analysis
- Annual architecture review