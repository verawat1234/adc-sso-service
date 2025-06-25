package performance

import (
	"time"
)

// LoadTestConfig holds configuration for load testing
type LoadTestConfig struct {
	BaseURL         string
	TotalRequests   int
	ConcurrentUsers int
	Duration        time.Duration
	RampUpTime      time.Duration
	TestType        string // "load", "stress", "spike", "endurance"
	Endpoints       []EndpointTest
}

// EndpointTest defines a test scenario for an endpoint
type EndpointTest struct {
	Name     string
	Method   string
	Path     string
	Headers  map[string]string
	Body     interface{}
	Weight   int // Probability weight for this endpoint
	AuthType string // "none", "jwt", "api_key"
}

// LoadTestResult contains the results of a load test
type LoadTestResult struct {
	TestConfig      LoadTestConfig
	StartTime       time.Time
	EndTime         time.Time
	TotalRequests   int
	SuccessRequests int
	FailedRequests  int
	AverageLatency  time.Duration
	P95Latency      time.Duration
	P99Latency      time.Duration
	MaxLatency      time.Duration
	MinLatency      time.Duration
	ThroughputRPS   float64
	ErrorRate       float64
	EndpointStats   map[string]*EndpointStats
	Errors          map[string]int
}

// EndpointStats contains statistics for a specific endpoint
type EndpointStats struct {
	TotalRequests   int
	SuccessRequests int
	FailedRequests  int
	AverageLatency  time.Duration
	MaxLatency      time.Duration
	MinLatency      time.Duration
	StatusCodes     map[int]int
}

// RequestResult represents the result of a single request
type RequestResult struct {
	Endpoint      string
	StatusCode    int
	Latency       time.Duration
	Error         error
	ResponseSize  int
	Timestamp     time.Time
}