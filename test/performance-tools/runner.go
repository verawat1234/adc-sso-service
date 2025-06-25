package performance

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/sirupsen/logrus"
)

// TestRunner manages and executes performance tests
type TestRunner struct {
	scenarios map[string]LoadTestConfig
	results   map[string]*LoadTestResult
	outputDir string
}

// NewTestRunner creates a new test runner
func NewTestRunner(outputDir string) *TestRunner {
	return &TestRunner{
		scenarios: GetDefaultScenarios(),
		results:   make(map[string]*LoadTestResult),
		outputDir: outputDir,
	}
}

// AddScenario adds a custom test scenario
func (tr *TestRunner) AddScenario(name string, config LoadTestConfig) {
	tr.scenarios[name] = config
}

// AddBenchmarkScenarios adds benchmark scenarios
func (tr *TestRunner) AddBenchmarkScenarios() {
	benchmarks := GetBenchmarkScenarios()
	for name, config := range benchmarks {
		tr.scenarios[name] = config
	}
}

// RunScenario executes a specific test scenario
func (tr *TestRunner) RunScenario(name string) (*LoadTestResult, error) {
	config, exists := tr.scenarios[name]
	if !exists {
		return nil, fmt.Errorf("scenario '%s' not found", name)
	}

	logrus.WithField("scenario", name).Info("Running performance test scenario")

	tester := NewLoadTester(config)
	result, err := tester.Run()
	if err != nil {
		return nil, fmt.Errorf("failed to run scenario '%s': %w", name, err)
	}

	tr.results[name] = result
	
	// Save results
	if err := tr.saveResult(name, result); err != nil {
		logrus.WithError(err).WithField("scenario", name).Error("Failed to save test results")
	}

	return result, nil
}

// RunAllScenarios executes all configured scenarios
func (tr *TestRunner) RunAllScenarios() map[string]*LoadTestResult {
	results := make(map[string]*LoadTestResult)
	
	for name := range tr.scenarios {
		result, err := tr.RunScenario(name)
		if err != nil {
			logrus.WithError(err).WithField("scenario", name).Error("Failed to run scenario")
			continue
		}
		results[name] = result
	}
	
	return results
}

// RunSelectedScenarios executes only the specified scenarios
func (tr *TestRunner) RunSelectedScenarios(scenarioNames []string) map[string]*LoadTestResult {
	results := make(map[string]*LoadTestResult)
	
	for _, name := range scenarioNames {
		result, err := tr.RunScenario(name)
		if err != nil {
			logrus.WithError(err).WithField("scenario", name).Error("Failed to run scenario")
			continue
		}
		results[name] = result
	}
	
	return results
}

// saveResult saves test results to files
func (tr *TestRunner) saveResult(scenarioName string, result *LoadTestResult) error {
	if err := os.MkdirAll(tr.outputDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	timestamp := time.Now().Format("20060102_150405")
	filename := fmt.Sprintf("%s_%s.json", scenarioName, timestamp)
	filePath := filepath.Join(tr.outputDir, filename)

	// Save JSON result
	if err := tr.saveJSONResult(filePath, result); err != nil {
		return err
	}

	// Save human-readable report
	reportPath := filepath.Join(tr.outputDir, fmt.Sprintf("%s_%s_report.txt", scenarioName, timestamp))
	if err := tr.saveTextReport(reportPath, result); err != nil {
		return err
	}

	logrus.WithFields(logrus.Fields{
		"scenario":    scenarioName,
		"json_file":   filePath,
		"report_file": reportPath,
	}).Info("Test results saved")

	return nil
}

// saveJSONResult saves results in JSON format
func (tr *TestRunner) saveJSONResult(filePath string, result *LoadTestResult) error {
	file, err := os.Create(filePath)
	if err != nil {
		return fmt.Errorf("failed to create JSON file: %w", err)
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(result); err != nil {
		return fmt.Errorf("failed to encode JSON: %w", err)
	}

	return nil
}

// saveTextReport saves human-readable report
func (tr *TestRunner) saveTextReport(filePath string, result *LoadTestResult) error {
	file, err := os.Create(filePath)
	if err != nil {
		return fmt.Errorf("failed to create report file: %w", err)
	}
	defer file.Close()

	report := tr.generateTextReport(result)
	if _, err := file.WriteString(report); err != nil {
		return fmt.Errorf("failed to write report: %w", err)
	}

	return nil
}

// generateTextReport generates a human-readable test report
func (tr *TestRunner) generateTextReport(result *LoadTestResult) string {
	duration := result.EndTime.Sub(result.StartTime)
	
	report := fmt.Sprintf(`
===============================================================================
PERFORMANCE TEST REPORT
===============================================================================

Test Configuration:
  Test Type:           %s
  Base URL:            %s
  Concurrent Users:    %d
  Total Requests:      %d
  Test Duration:       %v
  Start Time:          %s
  End Time:            %s

===============================================================================
OVERALL RESULTS
===============================================================================

Summary:
  Total Requests:      %d
  Successful Requests: %d
  Failed Requests:     %d
  Success Rate:        %.2f%%
  Error Rate:          %.2f%%

Performance Metrics:
  Average Latency:     %v
  95th Percentile:     %v
  99th Percentile:     %v
  Min Latency:         %v
  Max Latency:         %v
  Throughput:          %.2f req/sec

===============================================================================
ENDPOINT STATISTICS
===============================================================================

`,
		result.TestConfig.TestType,
		result.TestConfig.BaseURL,
		result.TestConfig.ConcurrentUsers,
		result.TestConfig.TotalRequests,
		duration,
		result.StartTime.Format("2006-01-02 15:04:05"),
		result.EndTime.Format("2006-01-02 15:04:05"),
		result.TotalRequests,
		result.SuccessRequests,
		result.FailedRequests,
		(1-result.ErrorRate)*100,
		result.ErrorRate*100,
		result.AverageLatency,
		result.P95Latency,
		result.P99Latency,
		result.MinLatency,
		result.MaxLatency,
		result.ThroughputRPS,
	)

	for endpoint, stats := range result.EndpointStats {
		successRate := float64(stats.SuccessRequests) / float64(stats.TotalRequests) * 100
		report += fmt.Sprintf(`
Endpoint: %s
  Total Requests:      %d
  Successful:          %d
  Failed:              %d
  Success Rate:        %.2f%%
  Average Latency:     %v
  Min Latency:         %v
  Max Latency:         %v
  
  Status Code Distribution:`,
			endpoint,
			stats.TotalRequests,
			stats.SuccessRequests,
			stats.FailedRequests,
			successRate,
			stats.AverageLatency,
			stats.MinLatency,
			stats.MaxLatency,
		)

		for code, count := range stats.StatusCodes {
			percentage := float64(count) / float64(stats.TotalRequests) * 100
			report += fmt.Sprintf("\n    %d: %d (%.1f%%)", code, count, percentage)
		}
		report += "\n"
	}

	if len(result.Errors) > 0 {
		report += "\n===============================================================================\n"
		report += "ERROR SUMMARY\n"
		report += "===============================================================================\n\n"

		for error, count := range result.Errors {
			percentage := float64(count) / float64(result.TotalRequests) * 100
			report += fmt.Sprintf("  %s: %d (%.2f%%)\n", error, count, percentage)
		}
	}

	report += "\n===============================================================================\n"
	report += "RECOMMENDATIONS\n"
	report += "===============================================================================\n\n"

	report += tr.generateRecommendations(result)

	return report
}

// generateRecommendations generates performance recommendations based on results
func (tr *TestRunner) generateRecommendations(result *LoadTestResult) string {
	recommendations := ""

	// Error rate analysis
	if result.ErrorRate > 0.05 { // > 5% error rate
		recommendations += "⚠️  HIGH ERROR RATE: Error rate is above 5%. Investigate error causes and consider:\n"
		recommendations += "   - Increasing timeout values\n"
		recommendations += "   - Reviewing database connection pool settings\n"
		recommendations += "   - Checking Redis connection stability\n\n"
	}

	// Latency analysis
	if result.AverageLatency > 500*time.Millisecond {
		recommendations += "⚠️  HIGH LATENCY: Average latency exceeds 500ms. Consider:\n"
		recommendations += "   - Optimizing database queries\n"
		recommendations += "   - Implementing Redis caching for frequently accessed data\n"
		recommendations += "   - Reviewing application bottlenecks\n\n"
	}

	// P95 vs average latency
	if result.P95Latency > result.AverageLatency*2 {
		recommendations += "⚠️  LATENCY VARIANCE: 95th percentile is significantly higher than average. Consider:\n"
		recommendations += "   - Investigating slow requests\n"
		recommendations += "   - Implementing connection pooling\n"
		recommendations += "   - Reviewing garbage collection impact\n\n"
	}

	// Throughput analysis
	expectedThroughput := float64(result.TestConfig.ConcurrentUsers) * 2 // 2 RPS per user as baseline
	if result.ThroughputRPS < expectedThroughput {
		recommendations += "⚠️  LOW THROUGHPUT: Throughput is below expected baseline. Consider:\n"
		recommendations += "   - Scaling horizontally (more instances)\n"
		recommendations += "   - Optimizing critical code paths\n"
		recommendations += "   - Reviewing resource constraints\n\n"
	}

	// Redis-specific recommendations
	for endpoint, stats := range result.EndpointStats {
		if endpoint == "health_check" || endpoint == "health_check_redis" {
			if stats.AverageLatency > 100*time.Millisecond {
				recommendations += "⚠️  SLOW HEALTH CHECKS: Health endpoint latency is high. Consider:\n"
				recommendations += "   - Optimizing Redis health check implementation\n"
				recommendations += "   - Using Redis connection pooling\n"
				recommendations += "   - Implementing health check caching\n\n"
			}
		}
	}

	if recommendations == "" {
		recommendations = "✅ GOOD PERFORMANCE: No significant issues detected. Current configuration appears optimal.\n\n"
		recommendations += "💡 OPTIMIZATION SUGGESTIONS:\n"
		recommendations += "   - Monitor performance under production load\n"
		recommendations += "   - Consider implementing more comprehensive monitoring\n"
		recommendations += "   - Run endurance tests to verify long-term stability\n"
	}

	return recommendations
}

// GenerateSummaryReport creates a summary report across multiple test runs
func (tr *TestRunner) GenerateSummaryReport() string {
	if len(tr.results) == 0 {
		return "No test results available for summary report."
	}

	summary := `
===============================================================================
PERFORMANCE TESTING SUMMARY REPORT
===============================================================================

`

	for scenario, result := range tr.results {
		duration := result.EndTime.Sub(result.StartTime)
		summary += fmt.Sprintf(`
Scenario: %s
  Type:                %s
  Duration:            %v
  Total Requests:      %d
  Success Rate:        %.2f%%
  Average Latency:     %v
  Throughput:          %.2f req/sec
  
`,
			scenario,
			result.TestConfig.TestType,
			duration,
			result.TotalRequests,
			(1-result.ErrorRate)*100,
			result.AverageLatency,
			result.ThroughputRPS,
		)
	}

	return summary
}

// GetAvailableScenarios returns list of available test scenarios
func (tr *TestRunner) GetAvailableScenarios() []string {
	scenarios := make([]string, 0, len(tr.scenarios))
	for name := range tr.scenarios {
		scenarios = append(scenarios, name)
	}
	return scenarios
}

// PrintScenarioInfo prints information about a specific scenario
func (tr *TestRunner) PrintScenarioInfo(name string) {
	config, exists := tr.scenarios[name]
	if !exists {
		fmt.Printf("Scenario '%s' not found\n", name)
		return
	}

	fmt.Printf(`
Scenario: %s
  Test Type:           %s
  Base URL:            %s
  Concurrent Users:    %d
  Total Requests:      %d
  Duration:            %v
  Ramp-up Time:        %v
  
  Endpoints:
`, name, config.TestType, config.BaseURL, config.ConcurrentUsers, 
   config.TotalRequests, config.Duration, config.RampUpTime)

	for _, endpoint := range config.Endpoints {
		fmt.Printf("    %s: %s %s (Weight: %d, Auth: %s)\n", 
			endpoint.Name, endpoint.Method, endpoint.Path, endpoint.Weight, endpoint.AuthType)
	}
	fmt.Println()
}