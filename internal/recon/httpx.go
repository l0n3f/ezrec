package recon

import (
	"context"
	"encoding/json"
	"fmt"
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

// HttpxProber handles HTTP probing and fingerprinting using httpx
type HttpxProber struct {
	config   *config.Config
	executor *runner.Executor
	logger   *log.Logger
}

// HttpxResult represents the JSON output from httpx
type HttpxResult struct {
	Timestamp     string   `json:"timestamp"`
	Hash          string   `json:"hash"`
	Port          string   `json:"port"`
	URL           string   `json:"url"`
	Input         string   `json:"input"`
	Title         string   `json:"title"`
	Scheme        string   `json:"scheme"`
	Webserver     string   `json:"webserver"`
	ContentType   string   `json:"content_type"`
	Method        string   `json:"method"`
	Host          string   `json:"host"`
	Path          string   `json:"path"`
	Favicon       string   `json:"favicon"`
	StatusCode    int      `json:"status_code"`
	ContentLength int      `json:"content_length"`
	Words         int      `json:"words"`
	Lines         int      `json:"lines"`
	Tech          []string `json:"tech"`
	Time          string   `json:"time"`
	Failed        bool     `json:"failed"`
	A             []string `json:"a"`
	CNAME         []string `json:"cname"`
}

// NewHttpxProber creates a new httpx prober
func NewHttpxProber(cfg *config.Config, logger *log.Logger) *HttpxProber {
	return &HttpxProber{
		config:   cfg,
		executor: runner.NewExecutor(logger),
		logger:   logger,
	}
}

// ProbeHosts performs HTTP probing on a list of hosts
func (hp *HttpxProber) ProbeHosts(ctx context.Context, hosts []string) ([]string, []output.Finding, error) {
	if !hp.executor.CheckTool("httpx") {
		return nil, nil, fmt.Errorf("httpx not found in PATH")
	}

	hp.logger.Progress("Starting HTTP probing", "hosts", len(hosts))

	// Create temporary input file
	tempDir := filepath.Join(os.TempDir(), "ezrec-httpx-"+util.GenerateTimestamp())
	if err := os.MkdirAll(tempDir, 0755); err != nil {
		return nil, nil, fmt.Errorf("failed to create temp directory: %w", err)
	}
	defer os.RemoveAll(tempDir)

	inputFile := filepath.Join(tempDir, "hosts.txt")
	outputFile := filepath.Join(tempDir, "httpx-output.json")

	// Write hosts to input file
	input := strings.Join(hosts, "\n")
	if err := os.WriteFile(inputFile, []byte(input), 0644); err != nil {
		return nil, nil, fmt.Errorf("failed to write input file: %w", err)
	}

	// Build httpx command
	args := hp.buildHttpxArgs(inputFile, outputFile)

	// Execute httpx
	result, err := hp.executor.Execute(ctx, "httpx", args...)
	if err != nil {
		return nil, nil, fmt.Errorf("httpx execution failed: %w", err)
	}

	if !result.Successful {
		hp.logger.Warn("Httpx completed with errors", "error", result.Error)
	}

	// Parse results
	liveHosts, findings, err := hp.parseHttpxResults(outputFile)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse httpx results: %w", err)
	}

	hp.logger.Success("HTTP probing completed", "live_hosts", len(liveHosts), "total_findings", len(findings))
	return liveHosts, findings, nil
}

// buildHttpxArgs constructs the command line arguments for httpx
func (hp *HttpxProber) buildHttpxArgs(inputFile, outputFile string) []string {
	args := []string{
		"-l", inputFile,
		"-o", outputFile,
		"-json",
		"-silent",
		"-no-color",
	}

	// Add threads
	if hp.config.Tools.Httpx.Threads > 0 {
		args = append(args, "-threads", strconv.Itoa(hp.config.Tools.Httpx.Threads))
	}

	// Add timeout
	if hp.config.Tools.Httpx.Timeout > 0 {
		args = append(args, "-timeout", strconv.Itoa(hp.config.Tools.Httpx.Timeout))
	}

	// Add max redirects
	if hp.config.Tools.Httpx.MaxRedirects > 0 {
		args = append(args, "-max-redirects", strconv.Itoa(hp.config.Tools.Httpx.MaxRedirects))
	}

	// Add status codes
	if len(hp.config.Tools.Httpx.StatusCodes) > 0 {
		statusCodes := make([]string, len(hp.config.Tools.Httpx.StatusCodes))
		for i, code := range hp.config.Tools.Httpx.StatusCodes {
			statusCodes[i] = strconv.Itoa(code)
		}
		args = append(args, "-mc", strings.Join(statusCodes, ","))
	}

	// Add ports
	if len(hp.config.Tools.Httpx.Ports) > 0 {
		args = append(args, "-ports", strings.Join(hp.config.Tools.Httpx.Ports, ","))
	}

	// Add technology detection
	if hp.config.Tools.Httpx.TechDetect {
		args = append(args, "-tech-detect")
	}

	// Add screenshot capability
	if hp.config.Tools.Httpx.Screenshot {
		args = append(args, "-screenshot")
	}

	// Add custom headers
	if len(hp.config.Headers) > 0 {
		for key, value := range hp.config.Headers {
			args = append(args, "-H", fmt.Sprintf("%s: %s", key, value))
		}
	}

	// Additional useful flags
	args = append(args,
		"-title",          // Extract page title
		"-server",         // Extract server header
		"-content-length", // Extract content length
		"-content-type",   // Extract content type
		"-method",         // Extract HTTP method
		"-websocket",      // Check for websocket upgrade
		"-ip",             // Include IP addresses
		"-cname",          // Include CNAME records
		"-asn",            // Include ASN information
		"-cdn",            // Check for CDN
		"-probe",          // Probe all ports
	)

	return args
}

// parseHttpxResults parses the JSON output from httpx
func (hp *HttpxProber) parseHttpxResults(outputFile string) ([]string, []output.Finding, error) {
	// Check if output file exists
	if _, err := os.Stat(outputFile); os.IsNotExist(err) {
		hp.logger.Warn("Httpx output file not found, no live hosts detected")
		return []string{}, []output.Finding{}, nil
	}

	content, err := os.ReadFile(outputFile)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read httpx output: %w", err)
	}

	var liveHosts []string
	var findings []output.Finding

	// Parse each line as JSON
	lines := strings.Split(string(content), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		var result HttpxResult
		if err := json.Unmarshal([]byte(line), &result); err != nil {
			hp.logger.Debug("Failed to parse httpx result line", "line", line, "error", err)
			continue
		}

		// Skip failed probes
		if result.Failed {
			continue
		}

		// Add to live hosts
		if result.URL != "" {
			liveHosts = append(liveHosts, result.URL)
		}

		// Create finding
		finding := output.Finding{
			Timestamp:   time.Now(),
			Stage:       "httpx",
			Type:        "live_host",
			Target:      result.Input,
			Value:       result.URL,
			Description: hp.buildDescription(result),
			Metadata:    hp.buildMetadata(result),
		}

		findings = append(findings, finding)

		// Add technology findings
		for _, tech := range result.Tech {
			techFinding := output.Finding{
				Timestamp:   time.Now(),
				Stage:       "httpx",
				Type:        "technology",
				Target:      result.URL,
				Value:       tech,
				Description: fmt.Sprintf("Technology detected: %s", tech),
				Metadata: map[string]string{
					"tool":        "httpx",
					"host":        result.Host,
					"status_code": strconv.Itoa(result.StatusCode),
				},
			}
			findings = append(findings, techFinding)
		}

		// Add interesting findings based on status codes and content
		hp.addInterestingFindings(&findings, result)
	}

	liveHosts = util.DeduplicateStrings(liveHosts)
	return liveHosts, findings, nil
}

// buildDescription creates a human-readable description for the finding
func (hp *HttpxProber) buildDescription(result HttpxResult) string {
	parts := []string{
		fmt.Sprintf("Status: %d", result.StatusCode),
	}

	if result.Title != "" {
		parts = append(parts, fmt.Sprintf("Title: %s", result.Title))
	}

	if result.Webserver != "" {
		parts = append(parts, fmt.Sprintf("Server: %s", result.Webserver))
	}

	if len(result.Tech) > 0 {
		parts = append(parts, fmt.Sprintf("Tech: %s", strings.Join(result.Tech, ", ")))
	}

	return strings.Join(parts, " | ")
}

// buildMetadata creates metadata map for the finding
func (hp *HttpxProber) buildMetadata(result HttpxResult) map[string]string {
	metadata := map[string]string{
		"tool":           "httpx",
		"status_code":    strconv.Itoa(result.StatusCode),
		"content_length": strconv.Itoa(result.ContentLength),
		"words":          strconv.Itoa(result.Words),
		"lines":          strconv.Itoa(result.Lines),
		"scheme":         result.Scheme,
		"method":         result.Method,
		"host":           result.Host,
		"port":           result.Port,
	}

	if result.Title != "" {
		metadata["title"] = result.Title
	}

	if result.Webserver != "" {
		metadata["webserver"] = result.Webserver
	}

	if result.ContentType != "" {
		metadata["content_type"] = result.ContentType
	}

	if len(result.Tech) > 0 {
		metadata["tech"] = strings.Join(result.Tech, ",")
	}

	if len(result.A) > 0 {
		metadata["ip_addresses"] = strings.Join(result.A, ",")
	}

	if len(result.CNAME) > 0 {
		metadata["cname"] = strings.Join(result.CNAME, ",")
	}

	return metadata
}

// addInterestingFindings adds additional findings based on interesting conditions
func (hp *HttpxProber) addInterestingFindings(findings *[]output.Finding, result HttpxResult) {
	// Interesting status codes
	switch result.StatusCode {
	case 401:
		*findings = append(*findings, output.Finding{
			Timestamp:   time.Now(),
			Stage:       "httpx",
			Type:        "authentication_required",
			Target:      result.URL,
			Value:       "HTTP 401 Unauthorized",
			Severity:    "medium",
			Description: "Authentication required - potential protected resource",
			Metadata: map[string]string{
				"tool":        "httpx",
				"status_code": "401",
				"title":       result.Title,
			},
		})
	case 403:
		*findings = append(*findings, output.Finding{
			Timestamp:   time.Now(),
			Stage:       "httpx",
			Type:        "access_forbidden",
			Target:      result.URL,
			Value:       "HTTP 403 Forbidden",
			Severity:    "low",
			Description: "Access forbidden - potential protected resource",
			Metadata: map[string]string{
				"tool":        "httpx",
				"status_code": "403",
				"title":       result.Title,
			},
		})
	case 500, 502, 503:
		*findings = append(*findings, output.Finding{
			Timestamp:   time.Now(),
			Stage:       "httpx",
			Type:        "server_error",
			Target:      result.URL,
			Value:       fmt.Sprintf("HTTP %d Server Error", result.StatusCode),
			Severity:    "low",
			Description: "Server error detected - potential information disclosure",
			Metadata: map[string]string{
				"tool":        "httpx",
				"status_code": strconv.Itoa(result.StatusCode),
				"title":       result.Title,
			},
		})
	}

	// Interesting titles
	if result.Title != "" {
		title := strings.ToLower(result.Title)
		interestingTitles := []string{
			"admin", "administrator", "dashboard", "control panel",
			"login", "sign in", "authentication", "phpmyadmin",
			"webmail", "cpanel", "plesk", "directadmin",
		}

		for _, keyword := range interestingTitles {
			if strings.Contains(title, keyword) {
				*findings = append(*findings, output.Finding{
					Timestamp:   time.Now(),
					Stage:       "httpx",
					Type:        "interesting_title",
					Target:      result.URL,
					Value:       result.Title,
					Severity:    "medium",
					Description: fmt.Sprintf("Interesting page title containing '%s'", keyword),
					Metadata: map[string]string{
						"tool":        "httpx",
						"keyword":     keyword,
						"status_code": strconv.Itoa(result.StatusCode),
					},
				})
				break
			}
		}
	}

	// Interesting servers
	if result.Webserver != "" {
		server := strings.ToLower(result.Webserver)
		if strings.Contains(server, "apache") && strings.Contains(server, "test") ||
			strings.Contains(server, "nginx") && strings.Contains(server, "dev") {
			*findings = append(*findings, output.Finding{
				Timestamp:   time.Now(),
				Stage:       "httpx",
				Type:        "development_server",
				Target:      result.URL,
				Value:       result.Webserver,
				Severity:    "low",
				Description: "Potential development or test server detected",
				Metadata: map[string]string{
					"tool":   "httpx",
					"server": result.Webserver,
				},
			})
		}
	}
}

// ProbeWithCustomPorts probes hosts with custom ports
func (hp *HttpxProber) ProbeWithCustomPorts(ctx context.Context, hosts []string, ports []string) ([]string, []output.Finding, error) {
	// Temporarily override ports in config
	originalPorts := hp.config.Tools.Httpx.Ports
	hp.config.Tools.Httpx.Ports = ports
	defer func() {
		hp.config.Tools.Httpx.Ports = originalPorts
	}()

	return hp.ProbeHosts(ctx, hosts)
}

// GetAvailableTools returns a list of available HTTP probing tools
func (hp *HttpxProber) GetAvailableTools() []string {
	var tools []string

	if hp.executor.CheckTool("httpx") {
		tools = append(tools, "httpx")
	}

	return tools
}
