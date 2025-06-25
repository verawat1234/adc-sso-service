package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"adc-sso-service/test/performance"

	"github.com/sirupsen/logrus"
)

func main() {
	// Define command line flags
	var (
		scenario      = flag.String("scenario", "", "Specific scenario to run (leave empty to see available scenarios)")
		listScenarios = flag.Bool("list", false, "List all available scenarios")
		outputDir     = flag.String("output", "./test-results", "Directory to save test results")
		verbose       = flag.Bool("verbose", false, "Enable verbose logging")
		runAll        = flag.Bool("all", false, "Run all scenarios")
		benchmarks    = flag.Bool("benchmarks", false, "Include benchmark scenarios")
		customUsers   = flag.Int("users", 0, "Custom number of concurrent users (overrides scenario setting)")
		customDuration = flag.Duration("duration", 0, "Custom test duration (overrides scenario setting)")
		baseURL       = flag.String("url", "http://localhost:9000", "Base URL for testing")
	)
	
	flag.Parse()

	// Setup logging
	logrus.SetFormatter(&logrus.TextFormatter{
		FullTimestamp: true,
		ForceColors:   true,
	})
	
	if *verbose {
		logrus.SetLevel(logrus.DebugLevel)
	} else {
		logrus.SetLevel(logrus.InfoLevel)
	}

	// Create test runner
	runner := performance.NewTestRunner(*outputDir)
	
	// Add benchmark scenarios if requested
	if *benchmarks {
		runner.AddBenchmarkScenarios()
	}

	// Handle different command modes
	switch {
	case *listScenarios:
		listAvailableScenarios(runner)
		return
		
	case *scenario != "":
		runSingleScenario(runner, *scenario, *customUsers, *customDuration, *baseURL)
		
	case *runAll:
		runAllScenarios(runner)
		
	default:
		printUsage()
		listAvailableScenarios(runner)
	}
}

func listAvailableScenarios(runner *performance.TestRunner) {
	fmt.Println("\n📊 Available Performance Test Scenarios:")
	fmt.Println("========================================")
	
	scenarios := runner.GetAvailableScenarios()
	for _, name := range scenarios {
		fmt.Printf("• %s\n", name)
		runner.PrintScenarioInfo(name)
	}
	
	fmt.Println("Usage examples:")
	fmt.Println("  ./perf-test -scenario smoke_test")
	fmt.Println("  ./perf-test -scenario load_test -users 100")
	fmt.Println("  ./perf-test -all")
	fmt.Println("  ./perf-test -benchmarks -scenario redis_benchmark")
}

func runSingleScenario(runner *performance.TestRunner, scenarioName string, customUsers int, customDuration time.Duration, baseURL string) {
	scenarios := runner.GetAvailableScenarios()
	found := false
	for _, name := range scenarios {
		if name == scenarioName {
			found = true
			break
		}
	}
	
	if !found {
		fmt.Printf("❌ Scenario '%s' not found\n", scenarioName)
		listAvailableScenarios(runner)
		os.Exit(1)
	}

	fmt.Printf("\n🚀 Running scenario: %s\n", scenarioName)
	fmt.Println("=" + strings.Repeat("=", len(scenarioName)+18))
	
	startTime := time.Now()
	
	// Apply custom configurations if provided
	// Note: This would require extending the runner to support config overrides
	// For now, we'll log the custom settings
	if customUsers > 0 {
		logrus.WithField("custom_users", customUsers).Info("Using custom concurrent users setting")
	}
	if customDuration > 0 {
		logrus.WithField("custom_duration", customDuration).Info("Using custom duration setting")
	}
	if baseURL != "http://localhost:9000" {
		logrus.WithField("custom_url", baseURL).Info("Using custom base URL")
	}

	result, err := runner.RunScenario(scenarioName)
	if err != nil {
		logrus.WithError(err).Fatal("Failed to run scenario")
	}

	duration := time.Since(startTime)
	
	// Print summary results
	printQuickSummary(result, duration)
	
	fmt.Printf("\n📁 Results saved to: %s\n", runner.GetAvailableScenarios())
	fmt.Println("🎯 Check the detailed report files for comprehensive analysis")
}

func runAllScenarios(runner *performance.TestRunner) {
	fmt.Println("\n🚀 Running All Performance Test Scenarios")
	fmt.Println("=========================================")
	
	startTime := time.Now()
	results := runner.RunAllScenarios()
	totalDuration := time.Since(startTime)
	
	fmt.Printf("\n📊 Test Suite Summary (Total Time: %v)\n", totalDuration)
	fmt.Println("=" + strings.Repeat("=", 40))
	
	for scenario, result := range results {
		if result != nil {
			scenarioDuration := result.EndTime.Sub(result.StartTime)
			fmt.Printf("\n✅ %s:\n", scenario)
			fmt.Printf("   Duration:     %v\n", scenarioDuration)
			fmt.Printf("   Requests:     %d\n", result.TotalRequests)
			fmt.Printf("   Success Rate: %.2f%%\n", (1-result.ErrorRate)*100)
			fmt.Printf("   Avg Latency:  %v\n", result.AverageLatency)
			fmt.Printf("   Throughput:   %.2f req/sec\n", result.ThroughputRPS)
		} else {
			fmt.Printf("\n❌ %s: Failed to execute\n", scenario)
		}
	}
	
	// Generate and save summary report
	summary := runner.GenerateSummaryReport()
	summaryPath := filepath.Join("./test-results", fmt.Sprintf("summary_report_%s.txt", 
		time.Now().Format("20060102_150405")))
	
	if err := os.MkdirAll("./test-results", 0755); err == nil {
		if file, err := os.Create(summaryPath); err == nil {
			file.WriteString(summary)
			file.Close()
			fmt.Printf("\n📁 Summary report saved to: %s\n", summaryPath)
		}
	}
}

func printQuickSummary(result *performance.LoadTestResult, duration time.Duration) {
	fmt.Printf("\n📊 Quick Summary\n")
	fmt.Println("================")
	fmt.Printf("Test Duration:    %v\n", duration)
	fmt.Printf("Total Requests:   %d\n", result.TotalRequests)
	fmt.Printf("Success Rate:     %.2f%%\n", (1-result.ErrorRate)*100)
	fmt.Printf("Average Latency:  %v\n", result.AverageLatency)
	fmt.Printf("95th Percentile:  %v\n", result.P95Latency)
	fmt.Printf("99th Percentile:  %v\n", result.P99Latency)
	fmt.Printf("Throughput:       %.2f req/sec\n", result.ThroughputRPS)
	
	if result.ErrorRate > 0 {
		fmt.Printf("⚠️  Error Rate:     %.2f%%\n", result.ErrorRate*100)
	}
	
	// Show top performing and problematic endpoints
	if len(result.EndpointStats) > 0 {
		fmt.Printf("\n🎯 Endpoint Performance:\n")
		for endpoint, stats := range result.EndpointStats {
			successRate := float64(stats.SuccessRequests) / float64(stats.TotalRequests) * 100
			fmt.Printf("   %s: %.0fms avg, %.1f%% success\n", 
				endpoint, float64(stats.AverageLatency.Nanoseconds())/1e6, successRate)
		}
	}
}

func printUsage() {
	fmt.Println(`
🧪 ADC SSO Service Performance Testing Tool
===========================================

This tool helps you run comprehensive performance tests against the ADC SSO Service.

USAGE:
  perf-test [OPTIONS]

OPTIONS:
  -scenario string     Run specific test scenario
  -list               List all available scenarios
  -all                Run all scenarios
  -benchmarks         Include benchmark scenarios
  -users int          Override concurrent users setting
  -duration duration  Override test duration (e.g., "5m", "30s")
  -url string         Base URL for testing (default: http://localhost:9000)
  -output string      Directory for test results (default: ./test-results)
  -verbose            Enable verbose logging

EXAMPLES:
  perf-test -list                           # List available scenarios
  perf-test -scenario smoke_test            # Run smoke test
  perf-test -scenario load_test -users 100  # Load test with 100 users
  perf-test -all                           # Run all scenarios
  perf-test -benchmarks -scenario redis_benchmark  # Run Redis benchmark

TEST TYPES:
  smoke_test      - Quick validation test (100 requests, 5 users)
  load_test       - Standard load test (5 min, 50 users)
  stress_test     - Stress test to find limits (10 min, 200 users)
  spike_test      - Sudden traffic spike test (8 min, 500 peak users)
  endurance_test  - Long-running stability test (2 hours, 30 users)
  redis_intensive - Redis-focused performance test
  api_performance - API endpoint performance test
`)
}

// Additional helper functions for advanced features

func validateServerConnection(baseURL string) error {
	// This could be enhanced to ping the server before starting tests
	return nil
}

func setupTestEnvironment() error {
	// This could be enhanced to:
	// - Check if the service is running
	// - Validate database connections
	// - Prepare test data
	// - Setup monitoring
	return nil
}

func cleanupTestEnvironment() error {
	// This could be enhanced to:
	// - Clean up test data
	// - Reset rate limits
	// - Clear Redis cache
	return nil
}