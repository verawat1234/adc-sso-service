package main

import (
	"fmt"
	"time"

	"adc-sso-service/test/performance"
	
	"github.com/sirupsen/logrus"
)

func main() {
	logrus.SetLevel(logrus.InfoLevel)
	
	// Create a simple smoke test scenario
	config := performance.LoadTestConfig{
		BaseURL:         "http://localhost:9000",
		TotalRequests:   50,
		ConcurrentUsers: 5,
		Duration:        0, // Request-based test
		TestType:        "load",
		Endpoints: []performance.EndpointTest{
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
				Weight:   50,
				AuthType: "none",
			},
		},
	}

	fmt.Println("🚀 Running Simple Performance Test")
	fmt.Println("=================================")
	fmt.Printf("Target: %s\n", config.BaseURL)
	fmt.Printf("Requests: %d\n", config.TotalRequests)
	fmt.Printf("Concurrent Users: %d\n", config.ConcurrentUsers)
	fmt.Println()

	startTime := time.Now()
	
	tester := performance.NewLoadTester(config)
	result, err := tester.Run()
	if err != nil {
		logrus.WithError(err).Fatal("Failed to run performance test")
	}

	duration := time.Since(startTime)

	fmt.Println("📊 Test Results")
	fmt.Println("===============")
	fmt.Printf("Total Duration:   %v\n", duration)
	fmt.Printf("Total Requests:   %d\n", result.TotalRequests)
	fmt.Printf("Success Rate:     %.2f%%\n", (1-result.ErrorRate)*100)
	fmt.Printf("Error Rate:       %.2f%%\n", result.ErrorRate*100)
	fmt.Printf("Average Latency:  %v\n", result.AverageLatency)
	fmt.Printf("95th Percentile:  %v\n", result.P95Latency)
	fmt.Printf("99th Percentile:  %v\n", result.P99Latency)
	fmt.Printf("Throughput:       %.2f req/sec\n", result.ThroughputRPS)
	
	if len(result.EndpointStats) > 0 {
		fmt.Println("\n🎯 Endpoint Performance:")
		for endpoint, stats := range result.EndpointStats {
			successRate := float64(stats.SuccessRequests) / float64(stats.TotalRequests) * 100
			fmt.Printf("   %s: %dms avg, %.1f%% success (%d/%d)\n", 
				endpoint, 
				stats.AverageLatency.Milliseconds(),
				successRate,
				stats.SuccessRequests,
				stats.TotalRequests)
		}
	}
	
	if result.ErrorRate > 0.05 {
		fmt.Printf("\n⚠️  High error rate detected (%.1f%%). Check service health.\n", result.ErrorRate*100)
	} else {
		fmt.Printf("\n✅ Test completed successfully! Service is performing well.\n")
	}
}