package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

type HealthResponse struct {
	Status    string                 `json:"status"`
	Service   string                 `json:"service"`
	Version   string                 `json:"version"`
	Timestamp string                 `json:"timestamp"`
	Database  string                 `json:"database"`
	Redis     map[string]interface{} `json:"redis"`
}

func main() {
	logrus.SetLevel(logrus.InfoLevel)
	
	baseURL := "http://localhost:9000"
	totalRequests := 50
	concurrentUsers := 5
	
	fmt.Println("🔍 Redis Health Endpoint Performance Test")
	fmt.Println("========================================")
	fmt.Printf("Target: %s/health\n", baseURL)
	fmt.Printf("Total Requests: %d\n", totalRequests)
	fmt.Printf("Concurrent Users: %d\n", concurrentUsers)
	fmt.Println()

	startTime := time.Now()
	
	// Channel to collect results
	results := make(chan struct {
		StatusCode int
		Latency    time.Duration
		Error      error
		Response   *HealthResponse
	}, totalRequests)
	
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
				url := baseURL + "/health"
				
				reqStart := time.Now()
				resp, err := client.Get(url)
				latency := time.Since(reqStart)
				
				result := struct {
					StatusCode int
					Latency    time.Duration
					Error      error
					Response   *HealthResponse
				}{
					Latency: latency,
					Error:   err,
				}
				
				if err == nil {
					result.StatusCode = resp.StatusCode
					
					// Parse the health response
					body, readErr := io.ReadAll(resp.Body)
					resp.Body.Close()
					
					if readErr == nil && resp.StatusCode == 200 {
						var healthResp HealthResponse
						if json.Unmarshal(body, &healthResp) == nil {
							result.Response = &healthResp
						}
					}
				}
				
				results <- result
			}
		}(requests)
	}
	
	// Wait for all workers to complete
	wg.Wait()
	close(results)
	
	// Process results
	var allResults []struct {
		StatusCode int
		Latency    time.Duration
		Error      error
		Response   *HealthResponse
	}
	
	for result := range results {
		allResults = append(allResults, result)
	}
	
	// Analyze results
	totalRequests = len(allResults)
	successCount := 0
	redisConnectedCount := 0
	var totalLatency time.Duration
	minLatency := allResults[0].Latency
	maxLatency := allResults[0].Latency
	
	for _, result := range allResults {
		if result.Error == nil && result.StatusCode == 200 {
			successCount++
			
			// Check Redis connection status
			if result.Response != nil {
				if redisInfo, ok := result.Response.Redis["status"]; ok {
					if redisInfo == "connected" {
						redisConnectedCount++
					}
				}
			}
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
	redisConnectionRate := float64(redisConnectedCount) / float64(successCount)
	
	// Print results
	fmt.Println("📊 Health Endpoint Test Results")
	fmt.Println("===============================")
	fmt.Printf("Test Duration:      %v\n", duration)
	fmt.Printf("Total Requests:     %d\n", totalRequests)
	fmt.Printf("Successful:         %d\n", successCount)
	fmt.Printf("Failed:             %d\n", totalRequests-successCount)
	fmt.Printf("Success Rate:       %.2f%%\n", (1-errorRate)*100)
	fmt.Printf("Average Latency:    %v\n", avgLatency)
	fmt.Printf("Min Latency:        %v\n", minLatency)
	fmt.Printf("Max Latency:        %v\n", maxLatency)
	fmt.Printf("Throughput:         %.2f req/sec\n", throughput)
	fmt.Println()
	
	fmt.Println("🔗 Redis Connection Analysis")
	fmt.Println("============================")
	fmt.Printf("Redis Connected:    %d/%d requests\n", redisConnectedCount, successCount)
	if successCount > 0 {
		fmt.Printf("Redis Success Rate: %.2f%%\n", redisConnectionRate*100)
	}
	
	// Show sample Redis stats from last successful response
	for i := len(allResults) - 1; i >= 0; i-- {
		if allResults[i].Response != nil && allResults[i].Response.Redis != nil {
			redis := allResults[i].Response.Redis
			fmt.Println("\n📈 Sample Redis Statistics:")
			
			if status, ok := redis["status"]; ok {
				fmt.Printf("   Status:        %v\n", status)
			}
			if hits, ok := redis["hits"]; ok {
				fmt.Printf("   Cache Hits:    %v\n", hits)
			}
			if misses, ok := redis["misses"]; ok {
				fmt.Printf("   Cache Misses:  %v\n", misses)
			}
			if totalConns, ok := redis["total_conns"]; ok {
				fmt.Printf("   Total Conns:   %v\n", totalConns)
			}
			if idleConns, ok := redis["idle_conns"]; ok {
				fmt.Printf("   Idle Conns:    %v\n", idleConns)
			}
			if timeouts, ok := redis["timeouts"]; ok {
				fmt.Printf("   Timeouts:      %v\n", timeouts)
			}
			break
		}
	}
	
	fmt.Println("\n🎯 Performance Assessment")
	fmt.Println("=========================")
	
	if errorRate > 0 {
		fmt.Printf("❌ Error Rate: %.1f%% - Service has availability issues\n", errorRate*100)
	} else if redisConnectionRate < 1.0 {
		fmt.Printf("⚠️  Redis Connection Issues: %.1f%% success rate\n", redisConnectionRate*100)
	} else if avgLatency > 200*time.Millisecond {
		fmt.Printf("⚠️  High Latency: %v average (Redis health checks should be under 200ms)\n", avgLatency)
	} else if avgLatency > 100*time.Millisecond {
		fmt.Printf("⚠️  Moderate Latency: %v average (consider optimization)\n", avgLatency)
	} else {
		fmt.Printf("✅ Excellent Performance: %v average latency\n", avgLatency)
	}
	
	if throughput < 20 {
		fmt.Printf("⚠️  Low Throughput: %.1f req/sec (consider scaling)\n", throughput)
	} else {
		fmt.Printf("✅ Good Throughput: %.1f req/sec\n", throughput)
	}
	
	fmt.Println("\n💡 Recommendations:")
	if avgLatency > 100*time.Millisecond {
		fmt.Println("   - Consider implementing Redis connection pooling")
		fmt.Println("   - Review Redis health check implementation")
		fmt.Println("   - Check network latency to Redis server")
	}
	if redisConnectionRate < 1.0 {
		fmt.Println("   - Investigate Redis connection stability")
		fmt.Println("   - Review Redis client configuration")
	}
	if errorRate == 0 && avgLatency <= 100*time.Millisecond {
		fmt.Println("   - Performance is optimal!")
		fmt.Println("   - Consider running longer endurance tests")
	}
}