# ADC SSO Service Makefile

.PHONY: build run test perf-test clean lint fmt

# Build the main application
build:
	go build -o bin/adc-sso-service main.go

# Build the performance testing tool
build-perf:
	go build -o bin/perf-test cmd/perf-test/main.go

# Run the SSO service
run:
	go run main.go

# Run the SSO service in background
run-bg:
	nohup go run main.go > app.log 2>&1 &
	@echo "Service started in background, check app.log for logs"

# Stop background service
stop:
	@pkill -f "go run main.go" || pkill -f "adc-sso-service" || echo "No service found running"

# Run unit tests
test:
	go test ./... -v

# Run performance tests
perf-test: build-perf
	./bin/perf-test

# Run specific performance test scenario
perf-smoke: build-perf
	./bin/perf-test -scenario smoke_test

perf-load: build-perf
	./bin/perf-test -scenario load_test

perf-stress: build-perf
	./bin/perf-test -scenario stress_test

perf-redis: build-perf
	./bin/perf-test -benchmarks -scenario redis_benchmark

perf-all: build-perf
	./bin/perf-test -all

# List available performance test scenarios
perf-list: build-perf
	./bin/perf-test -list

# Development helpers
lint:
	golangci-lint run ./...

fmt:
	go fmt ./...

# Database migrations (if needed)
migrate-up:
	@echo "Running database migrations..."
	# Add migration commands here if using a migration tool

migrate-down:
	@echo "Rolling back database migrations..."
	# Add rollback commands here if using a migration tool

# Docker operations
docker-build:
	docker build -t adc-sso-service .

docker-run:
	docker run -p 9000:9000 adc-sso-service

docker-compose-up:
	docker-compose up -d

docker-compose-down:
	docker-compose down

# Redis operations
redis-cli:
	redis-cli -u redis://default:dvr6imnAnMm1bEH1Sb3YGPtqnnDl6Ecj@redis-18465.c62.us-east-1-4.ec2.redns.redis-cloud.com:18465

redis-monitor:
	redis-cli -u redis://default:dvr6imnAnMm1bEH1Sb3YGPtqnnDl6Ecj@redis-18465.c62.us-east-1-4.ec2.redns.redis-cloud.com:18465 monitor

redis-info:
	redis-cli -u redis://default:dvr6imnAnMm1bEH1Sb3YGPtqnnDl6Ecj@redis-18465.c62.us-east-1-4.ec2.redns.redis-cloud.com:18465 info

# Clean up build artifacts and logs
clean:
	rm -rf bin/
	rm -rf test-results/
	rm -f app.log
	rm -f *.log

# Health checks
health:
	curl -s http://localhost:9000/health | jq .

health-simple:
	curl -s http://localhost:9000/health

# API testing
test-sso-login:
	curl -s "http://localhost:9000/sso/login" | jq .

test-service-info:
	curl -s "http://localhost:9000/" | jq .

# Performance monitoring during tests
monitor-resources:
	@echo "Monitoring system resources during test..."
	@echo "Press Ctrl+C to stop monitoring"
	while true; do \
		echo "=== $(date) ==="; \
		echo "Memory usage:"; \
		ps aux | grep -E "(main.go|adc-sso-service)" | grep -v grep; \
		echo "Port 9000 connections:"; \
		lsof -i :9000 | wc -l; \
		echo ""; \
		sleep 5; \
	done

# Load testing with resource monitoring
perf-test-with-monitoring: build-perf
	@echo "Starting service..."
	$(MAKE) run-bg
	@sleep 5
	@echo "Starting resource monitoring in background..."
	$(MAKE) monitor-resources > resource-monitor.log 2>&1 &
	@echo "Running performance tests..."
	./bin/perf-test -scenario load_test
	@echo "Stopping monitoring and service..."
	@pkill -f "monitor-resources" || true
	$(MAKE) stop

# Quick development cycle
dev: stop clean build run

# Full test cycle
full-test: build test perf-smoke
	@echo "All tests completed successfully!"

# Help
help:
	@echo "ADC SSO Service - Available Commands:"
	@echo ""
	@echo "Building:"
	@echo "  build                 - Build the main application"
	@echo "  build-perf           - Build the performance testing tool"
	@echo ""
	@echo "Running:"
	@echo "  run                  - Run the SSO service (foreground)"
	@echo "  run-bg               - Run the SSO service (background)"
	@echo "  stop                 - Stop background service"
	@echo ""
	@echo "Testing:"
	@echo "  test                 - Run unit tests"
	@echo "  perf-test           - Run performance tests (interactive)"
	@echo "  perf-list           - List available performance scenarios"
	@echo "  perf-smoke          - Run smoke test"
	@echo "  perf-load           - Run load test"
	@echo "  perf-stress         - Run stress test"
	@echo "  perf-redis          - Run Redis benchmark"
	@echo "  perf-all            - Run all performance tests"
	@echo ""
	@echo "Health & Monitoring:"
	@echo "  health              - Check service health (JSON)"
	@echo "  health-simple       - Check service health (simple)"
	@echo "  monitor-resources   - Monitor system resources"
	@echo ""
	@echo "Redis:"
	@echo "  redis-cli           - Connect to Redis CLI"
	@echo "  redis-monitor       - Monitor Redis commands"
	@echo "  redis-info          - Get Redis server info"
	@echo ""
	@echo "Development:"
	@echo "  lint                - Run linter"
	@echo "  fmt                 - Format code"
	@echo "  clean               - Clean build artifacts"
	@echo "  dev                 - Quick development cycle"
	@echo "  full-test          - Run complete test suite"
	@echo ""