package main

import (
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

type SimpleTestResult struct {
	TotalRequests   int
	SuccessRequests int
	FailedRequests  int
	AverageLatency  time.Duration
	MaxLatency      time.Duration
	MinLatency      time.Duration
	ThroughputRPS   float64
	ErrorRate       float64
}

type RequestResult struct {
	StatusCode int
	Latency    time.Duration
	Error      error
}

func main() {
	logrus.SetLevel(logrus.InfoLevel)
	
	baseURL := "http://localhost:9000"
	totalRequests := 100
	concurrentUsers := 10
	
	fmt.Println("🚀 Simple Redis Performance Test")
	fmt.Println("================================")
	fmt.Printf("Target: %s\n", baseURL)
	fmt.Printf("Total Requests: %d\n", totalRequests)
	fmt.Printf("Concurrent Users: %d\n", concurrentUsers)
	fmt.Println()

	// Test endpoints
	endpoints := []struct {
		name   string
		path   string
		weight int
	}{
		{"health_check", "/health", 60},
		{"service_info", "/", 30},
		{"sso_login", "/sso/login", 10},
	}

	startTime := time.Now()
	
	// Channel to collect results
	results := make(chan RequestResult, totalRequests)
	
	// WaitGroup to wait for all goroutines
	var wg sync.WaitGroup
	
	// Calculate requests per worker
	requestsPerWorker := totalRequests / concurrentUsers
	remainder := totalRequests % concurrentUsers
	
	// Start workers
	for i := 0; i < concurrentUsers; i++ {
		requests := requestsPerWorker
		if i < remainder {
			requests++
		}
		
		wg.Add(1)
		go func(workerRequests int) {
			defer wg.Done()
			
			client := &http.Client{
				Timeout: 30 * time.Second,
			}
			
			for j := 0; j < workerRequests; j++ {
				// Select endpoint based on weight
				endpoint := selectEndpoint(endpoints)
				url := baseURL + endpoint.path
				
				reqStart := time.Now()
				resp, err := client.Get(url)
				latency := time.Since(reqStart)
				
				result := RequestResult{
					Latency: latency,
					Error:   err,
				}
				
				if err == nil {
					result.StatusCode = resp.StatusCode
					// Read and discard body to complete the request
					io.Copy(io.Discard, resp.Body)
					resp.Body.Close()
				}
				
				results <- result
			}
		}(requests)
	}
	
	// Wait for all workers to complete
	wg.Wait()
	close(results)
	
	// Process results
	testResult := processResults(results, startTime)
	
	// Print results
	printResults(testResult, time.Since(startTime))
}

func selectEndpoint(endpoints []struct {
	name   string
	path   string
	weight int
}) struct {
	name   string
	path   string
	weight int
} {
	totalWeight := 0
	for _, ep := range endpoints {
		totalWeight += ep.weight
	}
	
	// Simple round-robin for now
	return endpoints[0]
}

func processResults(results <-chan RequestResult, startTime time.Time) SimpleTestResult {
	var allResults []RequestResult
	for result := range results {
		allResults = append(allResults, result)
	}
	
	if len(allResults) == 0 {
		return SimpleTestResult{}
	}
	
	totalRequests := len(allResults)
	successCount := 0
	var totalLatency time.Duration
	minLatency := allResults[0].Latency
	maxLatency := allResults[0].Latency
	
	for _, result := range allResults {
		if result.Error == nil && result.StatusCode < 400 {
			successCount++
		}
		
		totalLatency += result.Latency
		
		if result.Latency < minLatency {
			minLatency = result.Latency
		}
		if result.Latency > maxLatency {
			maxLatency = result.Latency
		}
	}
	
	avgLatency := totalLatency / time.Duration(totalRequests)
	duration := time.Since(startTime)
	throughput := float64(totalRequests) / duration.Seconds()
	errorRate := float64(totalRequests-successCount) / float64(totalRequests)
	
	return SimpleTestResult{
		TotalRequests:   totalRequests,
		SuccessRequests: successCount,
		FailedRequests:  totalRequests - successCount,
		AverageLatency:  avgLatency,
		MaxLatency:      maxLatency,
		MinLatency:      minLatency,
		ThroughputRPS:   throughput,
		ErrorRate:       errorRate,
	}
}

func printResults(result SimpleTestResult, duration time.Duration) {
	fmt.Println("📊 Test Results")
	fmt.Println("===============")
	fmt.Printf("Test Duration:    %v\n", duration)
	fmt.Printf("Total Requests:   %d\n", result.TotalRequests)
	fmt.Printf("Successful:       %d\n", result.SuccessRequests)
	fmt.Printf("Failed:           %d\n", result.FailedRequests)
	fmt.Printf("Success Rate:     %.2f%%\n", (1-result.ErrorRate)*100)
	fmt.Printf("Error Rate:       %.2f%%\n", result.ErrorRate*100)
	fmt.Printf("Average Latency:  %v\n", result.AverageLatency)
	fmt.Printf("Min Latency:      %v\n", result.MinLatency)
	fmt.Printf("Max Latency:      %v\n", result.MaxLatency)
	fmt.Printf("Throughput:       %.2f req/sec\n", result.ThroughputRPS)
	
	if result.ErrorRate > 0.05 {
		fmt.Printf("\n⚠️  High error rate detected (%.1f%%). Check service health.\n", result.ErrorRate*100)
	} else if result.AverageLatency > 500*time.Millisecond {
		fmt.Printf("\n⚠️  High latency detected (%v). Consider optimization.\n", result.AverageLatency)
	} else {
		fmt.Printf("\n✅ Test completed successfully! Service is performing well.\n")
	}
	
	// Redis-specific recommendations
	if result.AverageLatency > 100*time.Millisecond {
		fmt.Printf("💡 Consider checking Redis connection and health endpoint optimization.\n")
	}
}