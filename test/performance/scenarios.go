package performance

import (
	"time"
)

// GetDefaultScenarios returns predefined test scenarios
func GetDefaultScenarios() map[string]LoadTestConfig {
	baseURL := "http://localhost:9000"
	
	return map[string]LoadTestConfig{
		"smoke_test": {
			BaseURL:         baseURL,
			TotalRequests:   100,
			ConcurrentUsers: 5,
			Duration:        0, // Request-based test
			TestType:        "load",
			Endpoints: []EndpointTest{
				{
					Name:     "health_check",
					Method:   "GET",
					Path:     "/health",
					Weight:   30,
					AuthType: "none",
				},
				{
					Name:     "service_info",
					Method:   "GET",
					Path:     "/",
					Weight:   20,
					AuthType: "none",
				},
				{
					Name:     "sso_login",
					Method:   "GET",
					Path:     "/sso/login",
					Weight:   25,
					AuthType: "none",
				},
				{
					Name:     "validate_token",
					Method:   "POST",
					Path:     "/sso/validate",
					Weight:   25,
					AuthType: "none",
					Headers: map[string]string{
						"Content-Type": "application/json",
					},
					Body: map[string]interface{}{
						"access_token": "mock_token_for_testing",
					},
				},
			},
		},
		
		"load_test": {
			BaseURL:         baseURL,
			TotalRequests:   0, // Duration-based test
			ConcurrentUsers: 50,
			Duration:        5 * time.Minute,
			RampUpTime:      30 * time.Second,
			TestType:        "load",
			Endpoints: []EndpointTest{
				{
					Name:     "health_check",
					Method:   "GET",
					Path:     "/health",
					Weight:   40,
					AuthType: "none",
				},
				{
					Name:     "service_info",
					Method:   "GET",
					Path:     "/",
					Weight:   20,
					AuthType: "none",
				},
				{
					Name:     "sso_login",
					Method:   "GET",
					Path:     "/sso/login",
					Weight:   15,
					AuthType: "none",
				},
				{
					Name:     "validate_token",
					Method:   "POST",
					Path:     "/sso/validate",
					Weight:   15,
					AuthType: "none",
					Headers: map[string]string{
						"Content-Type": "application/json",
					},
					Body: map[string]interface{}{
						"access_token": "mock_token_for_testing",
					},
				},
				{
					Name:     "refresh_token",
					Method:   "POST",
					Path:     "/sso/refresh",
					Weight:   10,
					AuthType: "none",
					Headers: map[string]string{
						"Content-Type": "application/json",
					},
					Body: map[string]interface{}{
						"refresh_token": "mock_refresh_token_for_testing",
					},
				},
			},
		},
		
		"stress_test": {
			BaseURL:         baseURL,
			TotalRequests:   0, // Duration-based test
			ConcurrentUsers: 200,
			Duration:        10 * time.Minute,
			RampUpTime:      2 * time.Minute,
			TestType:        "stress",
			Endpoints: []EndpointTest{
				{
					Name:     "health_check",
					Method:   "GET",
					Path:     "/health",
					Weight:   35,
					AuthType: "none",
				},
				{
					Name:     "service_info",
					Method:   "GET",
					Path:     "/",
					Weight:   15,
					AuthType: "none",
				},
				{
					Name:     "sso_login",
					Method:   "GET",
					Path:     "/sso/login",
					Weight:   20,
					AuthType: "none",
				},
				{
					Name:     "validate_token",
					Method:   "POST",
					Path:     "/sso/validate",
					Weight:   20,
					AuthType: "none",
					Headers: map[string]string{
						"Content-Type": "application/json",
					},
					Body: map[string]interface{}{
						"access_token": "mock_token_for_testing",
					},
				},
				{
					Name:     "refresh_token",
					Method:   "POST",
					Path:     "/sso/refresh",
					Weight:   10,
					AuthType: "none",
					Headers: map[string]string{
						"Content-Type": "application/json",
					},
					Body: map[string]interface{}{
						"refresh_token": "mock_refresh_token_for_testing",
					},
				},
			},
		},
		
		"spike_test": {
			BaseURL:         baseURL,
			TotalRequests:   0, // Duration-based test
			ConcurrentUsers: 500,
			Duration:        8 * time.Minute,
			RampUpTime:      1 * time.Minute,
			TestType:        "spike",
			Endpoints: []EndpointTest{
				{
					Name:     "health_check",
					Method:   "GET",
					Path:     "/health",
					Weight:   50,
					AuthType: "none",
				},
				{
					Name:     "service_info",
					Method:   "GET",
					Path:     "/",
					Weight:   10,
					AuthType: "none",
				},
				{
					Name:     "sso_login",
					Method:   "GET",
					Path:     "/sso/login",
					Weight:   20,
					AuthType: "none",
				},
				{
					Name:     "validate_token",
					Method:   "POST",
					Path:     "/sso/validate",
					Weight:   20,
					AuthType: "none",
					Headers: map[string]string{
						"Content-Type": "application/json",
					},
					Body: map[string]interface{}{
						"access_token": "mock_token_for_testing",
					},
				},
			},
		},
		
		"endurance_test": {
			BaseURL:         baseURL,
			TotalRequests:   0, // Duration-based test
			ConcurrentUsers: 30,
			Duration:        2 * time.Hour,
			RampUpTime:      5 * time.Minute,
			TestType:        "endurance",
			Endpoints: []EndpointTest{
				{
					Name:     "health_check",
					Method:   "GET",
					Path:     "/health",
					Weight:   40,
					AuthType: "none",
				},
				{
					Name:     "service_info",
					Method:   "GET",
					Path:     "/",
					Weight:   10,
					AuthType: "none",
				},
				{
					Name:     "sso_login",
					Method:   "GET",
					Path:     "/sso/login",
					Weight:   25,
					AuthType: "none",
				},
				{
					Name:     "validate_token",
					Method:   "POST",
					Path:     "/sso/validate",
					Weight:   25,
					AuthType: "none",
					Headers: map[string]string{
						"Content-Type": "application/json",
					},
					Body: map[string]interface{}{
						"access_token": "mock_token_for_testing",
					},
				},
			},
		},
		
		"redis_intensive": {
			BaseURL:         baseURL,
			TotalRequests:   0, // Duration-based test
			ConcurrentUsers: 100,
			Duration:        3 * time.Minute,
			RampUpTime:      30 * time.Second,
			TestType:        "load",
			Endpoints: []EndpointTest{
				{
					Name:     "health_check_redis",
					Method:   "GET",
					Path:     "/health",
					Weight:   60, // Heavy focus on Redis monitoring
					AuthType: "none",
				},
				{
					Name:     "multiple_sso_logins",
					Method:   "GET",
					Path:     "/sso/login?redirect_url=test",
					Weight:   40, // This will test Redis session management
					AuthType: "none",
				},
			},
		},
		
		"api_performance": {
			BaseURL:         baseURL,
			TotalRequests:   5000,
			ConcurrentUsers: 25,
			Duration:        0, // Request-based test
			TestType:        "load",
			Endpoints: []EndpointTest{
				{
					Name:     "organizations_list",
					Method:   "GET",
					Path:     "/api/v1/organizations",
					Weight:   30,
					AuthType: "jwt",
					Headers: map[string]string{
						"Content-Type": "application/json",
					},
				},
				{
					Name:     "auth_validate",
					Method:   "POST",
					Path:     "/api/v1/auth/validate",
					Weight:   40,
					AuthType: "none",
					Headers: map[string]string{
						"Content-Type": "application/json",
					},
					Body: map[string]interface{}{
						"access_token": "mock_token_for_testing",
					},
				},
				{
					Name:     "auth_refresh",
					Method:   "POST",
					Path:     "/api/v1/auth/refresh",
					Weight:   30,
					AuthType: "none",
					Headers: map[string]string{
						"Content-Type": "application/json",
					},
					Body: map[string]interface{}{
						"refresh_token": "mock_refresh_token_for_testing",
					},
				},
			},
		},
	}
}

// GetCustomScenario creates a custom test scenario
func GetCustomScenario(name string, users int, duration time.Duration, endpoints []EndpointTest) LoadTestConfig {
	return LoadTestConfig{
		BaseURL:         "http://localhost:9000",
		TotalRequests:   0,
		ConcurrentUsers: users,
		Duration:        duration,
		RampUpTime:      duration / 10, // 10% of duration for ramp-up
		TestType:        "load",
		Endpoints:       endpoints,
	}
}

// GetBenchmarkScenarios returns scenarios for benchmarking specific functionality
func GetBenchmarkScenarios() map[string]LoadTestConfig {
	baseURL := "http://localhost:9000"
	
	return map[string]LoadTestConfig{
		"health_benchmark": {
			BaseURL:         baseURL,
			TotalRequests:   10000,
			ConcurrentUsers: 50,
			Duration:        0,
			TestType:        "load",
			Endpoints: []EndpointTest{
				{
					Name:     "health_only",
					Method:   "GET",
					Path:     "/health",
					Weight:   100,
					AuthType: "none",
				},
			},
		},
		
		"redis_benchmark": {
			BaseURL:         baseURL,
			TotalRequests:   5000,
			ConcurrentUsers: 20,
			Duration:        0,
			TestType:        "load",
			Endpoints: []EndpointTest{
				{
					Name:     "redis_health_check",
					Method:   "GET",
					Path:     "/health",
					Weight:   100,
					AuthType: "none",
				},
			},
		},
		
		"auth_benchmark": {
			BaseURL:         baseURL,
			TotalRequests:   3000,
			ConcurrentUsers: 30,
			Duration:        0,
			TestType:        "load",
			Endpoints: []EndpointTest{
				{
					Name:     "token_validation",
					Method:   "POST",
					Path:     "/sso/validate",
					Weight:   100,
					AuthType: "none",
					Headers: map[string]string{
						"Content-Type": "application/json",
					},
					Body: map[string]interface{}{
						"access_token": "mock_token_for_testing",
					},
				},
			},
		},
		
		"sso_session_benchmark": {
			BaseURL:         baseURL,
			TotalRequests:   2000,
			ConcurrentUsers: 25,
			Duration:        0,
			TestType:        "load",
			Endpoints: []EndpointTest{
				{
					Name:     "sso_state_generation",
					Method:   "GET",
					Path:     "/sso/login?redirect_url=benchmark_test",
					Weight:   100,
					AuthType: "none",
				},
			},
		},
	}
}