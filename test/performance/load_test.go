package performance

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

// Types are now defined in types.go

// LoadTester manages and executes load tests
type LoadTester struct {
	config     LoadTestConfig
	client     *http.Client
	results    chan RequestResult
	wg         sync.WaitGroup
	ctx        context.Context
	cancel     context.CancelFunc
	authTokens []string
	apiKeys    []string
}

// NewLoadTester creates a new load tester instance
func NewLoadTester(config LoadTestConfig) *LoadTester {
	ctx, cancel := context.WithCancel(context.Background())
	
	return &LoadTester{
		config: config,
		client: &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				MaxIdleConns:        100,
				MaxIdleConnsPerHost: 10,
				IdleConnTimeout:     90 * time.Second,
			},
		},
		results: make(chan RequestResult, config.TotalRequests),
		ctx:     ctx,
		cancel:  cancel,
	}
}

// Run executes the load test
func (lt *LoadTester) Run() (*LoadTestResult, error) {
	logrus.WithFields(logrus.Fields{
		"test_type":        lt.config.TestType,
		"total_requests":   lt.config.TotalRequests,
		"concurrent_users": lt.config.ConcurrentUsers,
		"duration":         lt.config.Duration,
	}).Info("Starting load test")

	startTime := time.Now()
	
	// Prepare authentication tokens if needed
	if err := lt.prepareAuth(); err != nil {
		return nil, fmt.Errorf("failed to prepare authentication: %w", err)
	}

	// Start result collector
	resultsChan := make(chan RequestResult, lt.config.TotalRequests)
	go lt.collectResults(resultsChan)

	// Execute the test based on type
	switch lt.config.TestType {
	case "load":
		lt.runLoadTest(resultsChan)
	case "stress":
		lt.runStressTest(resultsChan)
	case "spike":
		lt.runSpikeTest(resultsChan)
	case "endurance":
		lt.runEnduranceTest(resultsChan)
	default:
		lt.runLoadTest(resultsChan)
	}

	lt.wg.Wait()
	close(resultsChan)

	endTime := time.Now()
	
	// Process results
	result := lt.processResults(startTime, endTime)
	
	logrus.WithFields(logrus.Fields{
		"duration":         endTime.Sub(startTime),
		"total_requests":   result.TotalRequests,
		"success_rate":     (1 - result.ErrorRate) * 100,
		"avg_latency":      result.AverageLatency,
		"throughput_rps":   result.ThroughputRPS,
	}).Info("Load test completed")

	return result, nil
}

// runLoadTest executes a standard load test
func (lt *LoadTester) runLoadTest(results chan<- RequestResult) {
	if lt.config.Duration > 0 {
		lt.runDurationBasedTest(results)
	} else {
		lt.runRequestBasedTest(results)
	}
}

// runStressTest gradually increases load to find breaking point
func (lt *LoadTester) runStressTest(results chan<- RequestResult) {
	steps := 5
	stepDuration := lt.config.Duration / time.Duration(steps)
	
	for step := 1; step <= steps; step++ {
		concurrent := (lt.config.ConcurrentUsers * step) / steps
		logrus.WithFields(logrus.Fields{
			"step":        step,
			"concurrent":  concurrent,
			"duration":    stepDuration,
		}).Info("Stress test step")
		
		lt.runStepWithConcurrency(results, concurrent, stepDuration)
	}
}

// runSpikeTest simulates sudden traffic spikes
func (lt *LoadTester) runSpikeTest(results chan<- RequestResult) {
	normalLoad := lt.config.ConcurrentUsers / 4
	spikeLoad := lt.config.ConcurrentUsers
	
	phases := []struct {
		load     int
		duration time.Duration
	}{
		{normalLoad, lt.config.Duration / 4},     // Normal load
		{spikeLoad, lt.config.Duration / 2},      // Spike
		{normalLoad, lt.config.Duration / 4},     // Back to normal
	}
	
	for i, phase := range phases {
		logrus.WithFields(logrus.Fields{
			"phase":      i + 1,
			"load":       phase.load,
			"duration":   phase.duration,
		}).Info("Spike test phase")
		
		lt.runStepWithConcurrency(results, phase.load, phase.duration)
	}
}

// runEnduranceTest runs for extended period to test stability
func (lt *LoadTester) runEnduranceTest(results chan<- RequestResult) {
	lt.runDurationBasedTest(results)
}

// runRequestBasedTest runs until target request count is reached
func (lt *LoadTester) runRequestBasedTest(results chan<- RequestResult) {
	requestsPerWorker := lt.config.TotalRequests / lt.config.ConcurrentUsers
	remainder := lt.config.TotalRequests % lt.config.ConcurrentUsers
	
	for i := 0; i < lt.config.ConcurrentUsers; i++ {
		requests := requestsPerWorker
		if i < remainder {
			requests++
		}
		
		lt.wg.Add(1)
		go lt.worker(results, requests, 0)
	}
}

// runDurationBasedTest runs for a specific duration
func (lt *LoadTester) runDurationBasedTest(results chan<- RequestResult) {
	ctx, cancel := context.WithTimeout(lt.ctx, lt.config.Duration)
	defer cancel()
	
	for i := 0; i < lt.config.ConcurrentUsers; i++ {
		lt.wg.Add(1)
		go lt.workerWithContext(ctx, results)
	}
}

// runStepWithConcurrency runs a test step with specific concurrency
func (lt *LoadTester) runStepWithConcurrency(results chan<- RequestResult, concurrency int, duration time.Duration) {
	ctx, cancel := context.WithTimeout(lt.ctx, duration)
	defer cancel()
	
	var stepWg sync.WaitGroup
	for i := 0; i < concurrency; i++ {
		stepWg.Add(1)
		go func() {
			defer stepWg.Done()
			lt.workerWithContext(ctx, results)
		}()
	}
	stepWg.Wait()
}

// worker executes requests for a specific number of iterations
func (lt *LoadTester) worker(results chan<- RequestResult, requestCount int, delay time.Duration) {
	defer lt.wg.Done()
	
	for i := 0; i < requestCount; i++ {
		select {
		case <-lt.ctx.Done():
			return
		default:
			result := lt.executeRequest()
			results <- result
			
			if delay > 0 {
				time.Sleep(delay)
			}
		}
	}
}

// workerWithContext executes requests until context is cancelled
func (lt *LoadTester) workerWithContext(ctx context.Context, results chan<- RequestResult) {
	defer lt.wg.Done()
	
	for {
		select {
		case <-ctx.Done():
			return
		default:
			result := lt.executeRequest()
			results <- result
		}
	}
}

// executeRequest performs a single HTTP request
func (lt *LoadTester) executeRequest() RequestResult {
	endpoint := lt.selectRandomEndpoint()
	startTime := time.Now()
	
	req, err := lt.buildRequest(endpoint)
	if err != nil {
		return RequestResult{
			Endpoint:  endpoint.Name,
			Error:     err,
			Latency:   time.Since(startTime),
			Timestamp: startTime,
		}
	}
	
	resp, err := lt.client.Do(req)
	latency := time.Since(startTime)
	
	result := RequestResult{
		Endpoint:  endpoint.Name,
		Latency:   latency,
		Timestamp: startTime,
	}
	
	if err != nil {
		result.Error = err
		return result
	}
	
	defer resp.Body.Close()
	
	// Read response body to get size
	body, _ := io.ReadAll(resp.Body)
	result.StatusCode = resp.StatusCode
	result.ResponseSize = len(body)
	
	if resp.StatusCode >= 400 {
		result.Error = fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	
	return result
}

// selectRandomEndpoint selects an endpoint based on weight
func (lt *LoadTester) selectRandomEndpoint() EndpointTest {
	totalWeight := 0
	for _, endpoint := range lt.config.Endpoints {
		totalWeight += endpoint.Weight
	}
	
	if totalWeight == 0 {
		return lt.config.Endpoints[rand.Intn(len(lt.config.Endpoints))]
	}
	
	random := rand.Intn(totalWeight)
	currentWeight := 0
	
	for _, endpoint := range lt.config.Endpoints {
		currentWeight += endpoint.Weight
		if random < currentWeight {
			return endpoint
		}
	}
	
	return lt.config.Endpoints[0]
}

// buildRequest creates an HTTP request for the given endpoint
func (lt *LoadTester) buildRequest(endpoint EndpointTest) (*http.Request, error) {
	fullURL := lt.config.BaseURL + endpoint.Path
	
	var body io.Reader
	if endpoint.Body != nil {
		jsonBody, err := json.Marshal(endpoint.Body)
		if err != nil {
			return nil, err
		}
		body = bytes.NewBuffer(jsonBody)
	}
	
	req, err := http.NewRequestWithContext(lt.ctx, endpoint.Method, fullURL, body)
	if err != nil {
		return nil, err
	}
	
	// Set headers
	for key, value := range endpoint.Headers {
		req.Header.Set(key, value)
	}
	
	// Add authentication
	if err := lt.addAuthentication(req, endpoint.AuthType); err != nil {
		return nil, err
	}
	
	return req, nil
}

// addAuthentication adds appropriate authentication to the request
func (lt *LoadTester) addAuthentication(req *http.Request, authType string) error {
	switch authType {
	case "jwt":
		if len(lt.authTokens) > 0 {
			token := lt.authTokens[rand.Intn(len(lt.authTokens))]
			req.Header.Set("Authorization", "Bearer "+token)
		}
	case "api_key":
		if len(lt.apiKeys) > 0 {
			apiKey := lt.apiKeys[rand.Intn(len(lt.apiKeys))]
			req.Header.Set("X-API-Key", apiKey)
		}
	}
	return nil
}

// prepareAuth prepares authentication tokens for testing
func (lt *LoadTester) prepareAuth() error {
	// For now, we'll create mock tokens
	// In a real scenario, you would authenticate and get real tokens
	
	// Generate mock JWT tokens
	for i := 0; i < 10; i++ {
		lt.authTokens = append(lt.authTokens, fmt.Sprintf("mock_jwt_token_%d", i))
	}
	
	// Generate mock API keys
	for i := 0; i < 5; i++ {
		lt.apiKeys = append(lt.apiKeys, fmt.Sprintf("mock_api_key_%d", i))
	}
	
	return nil
}

// collectResults collects and stores test results
func (lt *LoadTester) collectResults(results <-chan RequestResult) {
	for result := range results {
		lt.results <- result
	}
}

// processResults processes collected results and generates statistics
func (lt *LoadTester) processResults(startTime, endTime time.Time) *LoadTestResult {
	results := make([]RequestResult, 0)
	
	// Collect all results
	close(lt.results)
	for result := range lt.results {
		results = append(results, result)
	}
	
	if len(results) == 0 {
		return &LoadTestResult{
			TestConfig: lt.config,
			StartTime:  startTime,
			EndTime:    endTime,
		}
	}
	
	// Calculate basic statistics
	totalRequests := len(results)
	successCount := 0
	latencies := make([]time.Duration, 0, totalRequests)
	endpointStats := make(map[string]*EndpointStats)
	errors := make(map[string]int)
	
	for _, result := range results {
		// Count successes
		if result.Error == nil && result.StatusCode < 400 {
			successCount++
		}
		
		// Collect latencies
		latencies = append(latencies, result.Latency)
		
		// Track endpoint statistics
		if endpointStats[result.Endpoint] == nil {
			endpointStats[result.Endpoint] = &EndpointStats{
				StatusCodes: make(map[int]int),
				MinLatency:  result.Latency,
				MaxLatency:  result.Latency,
			}
		}
		
		stat := endpointStats[result.Endpoint]
		stat.TotalRequests++
		
		if result.Error == nil && result.StatusCode < 400 {
			stat.SuccessRequests++
		} else {
			stat.FailedRequests++
			if result.Error != nil {
				errors[result.Error.Error()]++
			}
		}
		
		stat.StatusCodes[result.StatusCode]++
		
		if result.Latency < stat.MinLatency {
			stat.MinLatency = result.Latency
		}
		if result.Latency > stat.MaxLatency {
			stat.MaxLatency = result.Latency
		}
	}
	
	// Calculate latency statistics
	avgLatency, p95, p99, minLat, maxLat := calculateLatencyStats(latencies)
	
	// Calculate endpoint average latencies
	for endpoint, stat := range endpointStats {
		endpointLatencies := make([]time.Duration, 0)
		for _, result := range results {
			if result.Endpoint == endpoint {
				endpointLatencies = append(endpointLatencies, result.Latency)
			}
		}
		stat.AverageLatency, _, _, _, _ = calculateLatencyStats(endpointLatencies)
	}
	
	duration := endTime.Sub(startTime)
	throughput := float64(totalRequests) / duration.Seconds()
	errorRate := float64(totalRequests-successCount) / float64(totalRequests)
	
	return &LoadTestResult{
		TestConfig:      lt.config,
		StartTime:       startTime,
		EndTime:         endTime,
		TotalRequests:   totalRequests,
		SuccessRequests: successCount,
		FailedRequests:  totalRequests - successCount,
		AverageLatency:  avgLatency,
		P95Latency:      p95,
		P99Latency:      p99,
		MaxLatency:      maxLat,
		MinLatency:      minLat,
		ThroughputRPS:   throughput,
		ErrorRate:       errorRate,
		EndpointStats:   endpointStats,
		Errors:          errors,
	}
}

// calculateLatencyStats calculates latency percentiles and statistics
func calculateLatencyStats(latencies []time.Duration) (avg, p95, p99, min, max time.Duration) {
	if len(latencies) == 0 {
		return
	}
	
	// Sort latencies
	for i := 0; i < len(latencies); i++ {
		for j := i + 1; j < len(latencies); j++ {
			if latencies[i] > latencies[j] {
				latencies[i], latencies[j] = latencies[j], latencies[i]
			}
		}
	}
	
	// Calculate statistics
	var total time.Duration
	for _, lat := range latencies {
		total += lat
	}
	avg = total / time.Duration(len(latencies))
	
	min = latencies[0]
	max = latencies[len(latencies)-1]
	
	p95Index := int(float64(len(latencies)) * 0.95)
	if p95Index >= len(latencies) {
		p95Index = len(latencies) - 1
	}
	p95 = latencies[p95Index]
	
	p99Index := int(float64(len(latencies)) * 0.99)
	if p99Index >= len(latencies) {
		p99Index = len(latencies) - 1
	}
	p99 = latencies[p99Index]
	
	return
}

// Stop gracefully stops the load test
func (lt *LoadTester) Stop() {
	lt.cancel()
}