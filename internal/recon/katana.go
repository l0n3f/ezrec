package recon

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/ezrec/ezrec/internal/config"
	"github.com/ezrec/ezrec/internal/log"
	"github.com/ezrec/ezrec/internal/output"
	"github.com/ezrec/ezrec/internal/runner"
	"github.com/ezrec/ezrec/internal/util"
)

// KatanaCrawler handles web crawling using katana
type KatanaCrawler struct {
	config   *config.Config
	executor *runner.Executor
	logger   *log.Logger
}

// KatanaResult represents the JSON output from katana
type KatanaResult struct {
	Timestamp string         `json:"timestamp"`
	Request   KatanaRequest  `json:"request"`
	Response  KatanaResponse `json:"response"`
	Source    string         `json:"source"`
	Tag       []string       `json:"tag"`
	Attribute string         `json:"attribute"`
}

// KatanaRequest represents the request information
type KatanaRequest struct {
	Method  string            `json:"method"`
	URL     string            `json:"endpoint"`
	Raw     string            `json:"raw"`
	Headers map[string]string `json:"headers"`
}

// KatanaResponse represents the response information
type KatanaResponse struct {
	StatusCode    int               `json:"status_code"`
	Headers       map[string]string `json:"headers"`
	Body          string            `json:"body"`
	Technologies  []string          `json:"technologies"`
	ContentLength int               `json:"content_length"`
}

// NewKatanaCrawler creates a new katana crawler
func NewKatanaCrawler(cfg *config.Config, logger *log.Logger) *KatanaCrawler {
	return &KatanaCrawler{
		config:   cfg,
		executor: runner.NewExecutor(logger),
		logger:   logger,
	}
}

// CrawlEndpoints performs web crawling on a list of URLs
func (kc *KatanaCrawler) CrawlEndpoints(ctx context.Context, urls []string) ([]string, []output.Finding, error) {
	if !kc.executor.CheckTool("katana") {
		return nil, nil, fmt.Errorf("katana not found in PATH")
	}

	kc.logger.Progress("Starting web crawling", "urls", len(urls))

	// Create temporary files
	tempDir := filepath.Join(os.TempDir(), "ezrec-katana-"+util.GenerateTimestamp())
	if err := os.MkdirAll(tempDir, 0755); err != nil {
		return nil, nil, fmt.Errorf("failed to create temp directory: %w", err)
	}
	defer os.RemoveAll(tempDir)

	inputFile := filepath.Join(tempDir, "urls.txt")
	outputFile := filepath.Join(tempDir, "katana-output.json")

	// Write URLs to input file
	input := strings.Join(urls, "\n")
	if err := os.WriteFile(inputFile, []byte(input), 0644); err != nil {
		return nil, nil, fmt.Errorf("failed to write input file: %w", err)
	}

	// Build katana command
	args := kc.buildKatanaArgs(inputFile, outputFile)

	// Execute katana
	result, err := kc.executor.Execute(ctx, "katana", args...)
	if err != nil {
		return nil, nil, fmt.Errorf("katana execution failed: %w", err)
	}

	if !result.Successful {
		kc.logger.Warn("Katana completed with errors", "error", result.Error)
	}

	// Parse results
	crawledURLs, findings, err := kc.parseKatanaResults(outputFile)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse katana results: %w", err)
	}

	kc.logger.Success("Web crawling completed", "crawled_urls", len(crawledURLs), "findings", len(findings))
	return crawledURLs, findings, nil
}

// buildKatanaArgs constructs the command line arguments for katana
func (kc *KatanaCrawler) buildKatanaArgs(inputFile, outputFile string) []string {
	args := []string{
		"-list", inputFile,
		"-output", outputFile,
		"-json",
		"-silent",
		"-no-color",
	}

	// Add depth
	if kc.config.Tools.Katana.MaxDepth > 0 {
		args = append(args, "-depth", strconv.Itoa(kc.config.Tools.Katana.MaxDepth))
	}

	// Add concurrency
	if kc.config.Tools.Katana.Concurrency > 0 {
		args = append(args, "-concurrency", strconv.Itoa(kc.config.Tools.Katana.Concurrency))
	}

	// Add delay
	if kc.config.Tools.Katana.Delay > 0 {
		args = append(args, "-delay", strconv.Itoa(kc.config.Tools.Katana.Delay))
	}

	// Add max pages
	if kc.config.Tools.Katana.MaxPages > 0 {
		args = append(args, "-crawl-limit", strconv.Itoa(kc.config.Tools.Katana.MaxPages))
	}

	// Add extensions
	if len(kc.config.Tools.Katana.Extensions) > 0 {
		args = append(args, "-extensions", strings.Join(kc.config.Tools.Katana.Extensions, ","))
	}

	// Add custom headers
	if len(kc.config.Headers) > 0 {
		for key, value := range kc.config.Headers {
			args = append(args, "-header", fmt.Sprintf("%s: %s", key, value))
		}
	}

	// Additional useful flags
	args = append(args,
		"-field-scope", "rdn", // Stay within root domain
		"-crawl-scope", "rdn", // Crawl scope to root domain
		"-display-out-scope",   // Display out of scope URLs
		"-form-extraction",     // Extract forms
		"-passive",             // Use passive sources
		"-automatic-form-fill", // Automatically fill forms
		"-js-crawl",            // Enable JavaScript crawling
		"-xhr-extraction",      // Extract XHR requests
		"-known-files",         // Check for known files
	)

	return args
}

// parseKatanaResults parses the JSON output from katana
func (kc *KatanaCrawler) parseKatanaResults(outputFile string) ([]string, []output.Finding, error) {
	// Check if output file exists
	if _, err := os.Stat(outputFile); os.IsNotExist(err) {
		kc.logger.Warn("Katana output file not found, no URLs crawled")
		return []string{}, []output.Finding{}, nil
	}

	content, err := os.ReadFile(outputFile)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read katana output: %w", err)
	}

	var crawledURLs []string
	var findings []output.Finding

	// Parse each line as JSON
	lines := strings.Split(string(content), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		var result KatanaResult
		if err := json.Unmarshal([]byte(line), &result); err != nil {
			kc.logger.Debug("Failed to parse katana result line", "line", line, "error", err)
			continue
		}

		// Add URL to crawled URLs
		if result.Request.URL != "" {
			crawledURLs = append(crawledURLs, result.Request.URL)
		}

		// Create finding
		finding := output.Finding{
			Timestamp:   time.Now(),
			Stage:       "crawl",
			Type:        kc.determineURLType(result.Request.URL),
			Target:      result.Source,
			Value:       result.Request.URL,
			Description: kc.buildDescription(result),
			Metadata:    kc.buildMetadata(result),
		}

		findings = append(findings, finding)

		// Add interesting findings
		kc.addInterestingFindings(&findings, result)
	}

	crawledURLs = util.DeduplicateStrings(crawledURLs)
	return crawledURLs, findings, nil
}

// determineURLType determines the type of URL based on its characteristics
func (kc *KatanaCrawler) determineURLType(urlStr string) string {
	parsed, err := url.Parse(urlStr)
	if err != nil {
		return "url"
	}

	path := strings.ToLower(parsed.Path)
	query := strings.ToLower(parsed.RawQuery)

	// Check for API endpoints
	if strings.Contains(path, "/api/") || strings.Contains(path, "/v1/") ||
		strings.Contains(path, "/v2/") || strings.Contains(path, "/rest/") {
		return "api_endpoint"
	}

	// Check for admin panels
	if strings.Contains(path, "/admin") || strings.Contains(path, "/dashboard") ||
		strings.Contains(path, "/manage") || strings.Contains(path, "/control") {
		return "admin_endpoint"
	}

	// Check for login pages
	if strings.Contains(path, "/login") || strings.Contains(path, "/signin") ||
		strings.Contains(path, "/auth") {
		return "auth_endpoint"
	}

	// Check for file uploads
	if strings.Contains(path, "/upload") || strings.Contains(path, "/file") {
		return "upload_endpoint"
	}

	// Check for parameters
	if query != "" {
		return "parameterized_url"
	}

	// Check file extensions
	if strings.HasSuffix(path, ".js") {
		return "javascript_file"
	} else if strings.HasSuffix(path, ".css") {
		return "css_file"
	} else if strings.HasSuffix(path, ".json") {
		return "json_file"
	} else if strings.HasSuffix(path, ".xml") {
		return "xml_file"
	}

	return "url"
}

// buildDescription creates a human-readable description
func (kc *KatanaCrawler) buildDescription(result KatanaResult) string {
	parts := []string{
		fmt.Sprintf("Method: %s", result.Request.Method),
	}

	if result.Response.StatusCode > 0 {
		parts = append(parts, fmt.Sprintf("Status: %d", result.Response.StatusCode))
	}

	if len(result.Response.Technologies) > 0 {
		parts = append(parts, fmt.Sprintf("Tech: %s", strings.Join(result.Response.Technologies, ", ")))
	}

	if result.Source != "" {
		parts = append(parts, fmt.Sprintf("Source: %s", result.Source))
	}

	return strings.Join(parts, " | ")
}

// buildMetadata creates metadata map for the finding
func (kc *KatanaCrawler) buildMetadata(result KatanaResult) map[string]string {
	metadata := map[string]string{
		"tool":   "katana",
		"method": result.Request.Method,
		"source": result.Source,
	}

	if result.Response.StatusCode > 0 {
		metadata["status_code"] = strconv.Itoa(result.Response.StatusCode)
	}

	if result.Response.ContentLength > 0 {
		metadata["content_length"] = strconv.Itoa(result.Response.ContentLength)
	}

	if len(result.Response.Technologies) > 0 {
		metadata["technologies"] = strings.Join(result.Response.Technologies, ",")
	}

	if len(result.Tag) > 0 {
		metadata["tags"] = strings.Join(result.Tag, ",")
	}

	if result.Attribute != "" {
		metadata["attribute"] = result.Attribute
	}

	return metadata
}

// addInterestingFindings adds additional findings based on interesting conditions
func (kc *KatanaCrawler) addInterestingFindings(findings *[]output.Finding, result KatanaResult) {
	urlStr := result.Request.URL
	parsed, err := url.Parse(urlStr)
	if err != nil {
		return
	}

	// Check for sensitive parameters
	if parsed.RawQuery != "" {
		sensitiveParams := []string{
			"password", "passwd", "pwd", "pass",
			"token", "key", "secret", "api_key",
			"session", "sessionid", "sid",
			"admin", "debug", "test",
		}

		query := strings.ToLower(parsed.RawQuery)
		for _, param := range sensitiveParams {
			if strings.Contains(query, param) {
				*findings = append(*findings, output.Finding{
					Timestamp:   time.Now(),
					Stage:       "crawl",
					Type:        "sensitive_parameter",
					Target:      urlStr,
					Value:       param,
					Severity:    "medium",
					Description: fmt.Sprintf("Sensitive parameter '%s' found in URL", param),
					Metadata: map[string]string{
						"tool":      "katana",
						"parameter": param,
						"url":       urlStr,
					},
				})
			}
		}
	}

	// Check for interesting file extensions
	path := strings.ToLower(parsed.Path)
	interestingExtensions := map[string]string{
		".bak":    "backup_file",
		".backup": "backup_file",
		".old":    "backup_file",
		".orig":   "backup_file",
		".conf":   "config_file",
		".config": "config_file",
		".env":    "environment_file",
		".sql":    "database_file",
		".db":     "database_file",
		".log":    "log_file",
	}

	for ext, fileType := range interestingExtensions {
		if strings.HasSuffix(path, ext) {
			*findings = append(*findings, output.Finding{
				Timestamp:   time.Now(),
				Stage:       "crawl",
				Type:        fileType,
				Target:      urlStr,
				Value:       parsed.Path,
				Severity:    "medium",
				Description: fmt.Sprintf("Interesting file with extension %s found", ext),
				Metadata: map[string]string{
					"tool":      "katana",
					"extension": ext,
					"file_type": fileType,
				},
			})
		}
	}

	// Check for status codes that might indicate issues
	if result.Response.StatusCode == 500 {
		*findings = append(*findings, output.Finding{
			Timestamp:   time.Now(),
			Stage:       "crawl",
			Type:        "server_error",
			Target:      urlStr,
			Value:       "HTTP 500 Internal Server Error",
			Severity:    "low",
			Description: "Server error detected during crawling",
			Metadata: map[string]string{
				"tool":        "katana",
				"status_code": "500",
			},
		})
	}
}

// CrawlWithCustomDepth performs crawling with a custom depth
func (kc *KatanaCrawler) CrawlWithCustomDepth(ctx context.Context, urls []string, depth int) ([]string, []output.Finding, error) {
	// Temporarily override depth in config
	originalDepth := kc.config.Tools.Katana.MaxDepth
	kc.config.Tools.Katana.MaxDepth = depth
	defer func() {
		kc.config.Tools.Katana.MaxDepth = originalDepth
	}()

	return kc.CrawlEndpoints(ctx, urls)
}

// ExtractJavaScriptURLs specifically crawls for JavaScript files and extracts URLs
func (kc *KatanaCrawler) ExtractJavaScriptURLs(ctx context.Context, urls []string) ([]string, []output.Finding, error) {
	if !kc.executor.CheckTool("katana") {
		return nil, nil, fmt.Errorf("katana not found in PATH")
	}

	kc.logger.Progress("Extracting JavaScript URLs", "urls", len(urls))

	// Create temporary files
	tempDir := filepath.Join(os.TempDir(), "ezrec-katana-js-"+util.GenerateTimestamp())
	if err := os.MkdirAll(tempDir, 0755); err != nil {
		return nil, nil, fmt.Errorf("failed to create temp directory: %w", err)
	}
	defer os.RemoveAll(tempDir)

	inputFile := filepath.Join(tempDir, "urls.txt")
	outputFile := filepath.Join(tempDir, "katana-js-output.json")

	// Write URLs to input file
	input := strings.Join(urls, "\n")
	if err := os.WriteFile(inputFile, []byte(input), 0644); err != nil {
		return nil, nil, fmt.Errorf("failed to write input file: %w", err)
	}

	// Build katana command for JavaScript extraction
	args := []string{
		"-list", inputFile,
		"-output", outputFile,
		"-json",
		"-silent",
		"-no-color",
		"-js-crawl",
		"-xhr-extraction",
		"-extensions", "js",
		"-depth", "1",
	}

	// Execute katana
	result, err := kc.executor.Execute(ctx, "katana", args...)
	if err != nil {
		return nil, nil, fmt.Errorf("katana JavaScript extraction failed: %w", err)
	}

	if !result.Successful {
		kc.logger.Warn("Katana JavaScript extraction completed with errors", "error", result.Error)
	}

	// Parse results
	jsURLs, findings, err := kc.parseKatanaResults(outputFile)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse katana JavaScript results: %w", err)
	}

	kc.logger.Success("JavaScript URL extraction completed", "js_urls", len(jsURLs))
	return jsURLs, findings, nil
}

// GetAvailableTools returns a list of available crawling tools
func (kc *KatanaCrawler) GetAvailableTools() []string {
	var tools []string

	if kc.executor.CheckTool("katana") {
		tools = append(tools, "katana")
	}

	return tools
}
