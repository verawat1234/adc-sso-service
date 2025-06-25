#!/bin/bash

# ADC SSO Service - Standalone SSO Microservice
# This script starts the SSO service and all required infrastructure

set -e

echo "🚀 Starting ADC SSO Service..."

# Start infrastructure services (database, cache, SSO)
echo "📦 Starting infrastructure services..."
docker-compose up -d

# Wait for services to be ready
echo "⏳ Waiting for services to be ready..."
sleep 30

# Check Keycloak health
echo "🔐 Checking Keycloak SSO service..."
until curl -s http://localhost:8180/health/ready > /dev/null; do
  echo "   Waiting for Keycloak to be ready..."
  sleep 5
done
echo "✅ Keycloak SSO service is ready"

# Check PostgreSQL health for SSO service
echo "🗄️  Checking SSO PostgreSQL database..."
until docker exec adc-sso-db pg_isready -U adc_user -d adc_sso > /dev/null 2>&1; do
  echo "   Waiting for SSO PostgreSQL to be ready..."
  sleep 2
done
echo "✅ SSO PostgreSQL database is ready"

# Check Redis health
echo "🔴 Checking Redis cache..."
until docker exec adc-redis redis-cli ping > /dev/null 2>&1; do
  echo "   Waiting for Redis to be ready..."
  sleep 2
done
echo "✅ Redis cache is ready"

echo ""
echo "🎉 All infrastructure services are ready!"
echo ""
echo "📋 Service URLs:"
echo "   🔐 Keycloak Admin: http://localhost:8180/admin (admin/admin_password)"
echo "   🔐 Keycloak Realm: http://localhost:8180/realms/adc-brandkit"
echo "   🗄️  PostgreSQL (Keycloak): localhost:5433"
echo "   🗄️  PostgreSQL (SSO):      localhost:5434 (adc_user/adc_password)"
echo "   🔴 Redis:                 localhost:6379"
echo ""
echo "🚀 To start the SSO service manually:"
echo "   export DATABASE_URL=postgresql://adc_user:adc_password@localhost:5434/adc_sso"
echo "   go run main.go"
echo ""
echo "🔗 SSO Service Endpoints (Port 9000):"
echo "   Health:       http://localhost:9000/health"
echo "   SSO Login:    http://localhost:9000/sso/login"
echo "   SSO Callback: http://localhost:9000/sso/callback"
echo "   Validate:     POST http://localhost:9000/sso/validate"
echo "   Refresh:      POST http://localhost:9000/sso/refresh"
echo ""
echo "🛠️  To stop services: docker-compose down"