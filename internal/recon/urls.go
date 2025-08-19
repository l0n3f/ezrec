package recon

import (
	"context"
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

// URLDiscoverer handles historical URL discovery using multiple tools
type URLDiscoverer struct {
	config   *config.Config
	executor *runner.Executor
	logger   *log.Logger
}

// NewURLDiscoverer creates a new URL discoverer
func NewURLDiscoverer(cfg *config.Config, logger *log.Logger) *URLDiscoverer {
	return &URLDiscoverer{
		config:   cfg,
		executor: runner.NewExecutor(logger),
		logger:   logger,
	}
}

// DiscoverHistoricalURLs performs comprehensive historical URL discovery
func (ud *URLDiscoverer) DiscoverHistoricalURLs(ctx context.Context, domains []string) ([]string, []output.Finding, error) {
	ud.logger.Progress("Starting historical URL discovery", "domains", len(domains))

	var allURLs []string
	var findings []output.Finding

	// Run gau
	if ud.executor.CheckTool("gau") {
		ud.logger.Info("Running gau")
		gauResults, gauFindings, err := ud.runGau(ctx, domains)
		if err != nil {
			ud.logger.Warn("GAU failed", "error", err)
		} else {
			allURLs = append(allURLs, gauResults...)
			findings = append(findings, gauFindings...)
			ud.logger.Success("GAU completed", "urls", len(gauResults))
		}
	} else {
		ud.logger.Warn("GAU not found in PATH, skipping")
	}

	// Run waybackurls
	if ud.executor.CheckTool("waybackurls") {
		ud.logger.Info("Running waybackurls")
		waybackResults, waybackFindings, err := ud.runWaybackurls(ctx, domains)
		if err != nil {
			ud.logger.Warn("Waybackurls failed", "error", err)
		} else {
			allURLs = append(allURLs, waybackResults...)
			findings = append(findings, waybackFindings...)
			ud.logger.Success("Waybackurls completed", "urls", len(waybackResults))
		}
	} else {
		ud.logger.Warn("Waybackurls not found in PATH, skipping")
	}

	// Deduplicate results
	allURLs = ud.filterAndDeduplicateURLs(allURLs)

	ud.logger.Success("Historical URL discovery completed", "total_urls", len(allURLs))
	return allURLs, findings, nil
}

// runGau executes gau for historical URL discovery
func (ud *URLDiscoverer) runGau(ctx context.Context, domains []string) ([]string, []output.Finding, error) {
	var allURLs []string
	var findings []output.Finding

	for _, domain := range domains {
		ud.logger.Debug("Running gau for domain", "domain", domain)

		args := []string{domain}

		// Add configuration options
		if len(ud.config.Tools.Gau.Providers) > 0 {
			args = append(args, "--providers", strings.Join(ud.config.Tools.Gau.Providers, ","))
		}

		if ud.config.Tools.Gau.MaxPages > 0 {
			args = append(args, "--pages", strconv.Itoa(ud.config.Tools.Gau.MaxPages))
		}

		if ud.config.Tools.Gau.Threads > 0 {
			args = append(args, "--threads", strconv.Itoa(ud.config.Tools.Gau.Threads))
		}

		// Add additional useful flags
		args = append(args,
			"--subs",                                                         // Include subdomains
			"--blacklist", "ttf,woff,woff2,eot,svg,png,jpg,jpeg,gif,ico,css", // Exclude static files
		)

		result, err := ud.executor.Execute(ctx, "gau", args...)
		if err != nil {
			return nil, nil, fmt.Errorf("gau execution failed: %w", err)
		}

		if !result.Successful {
			ud.logger.Warn("GAU failed for domain", "domain", domain, "error", result.Error)
			continue
		}

		// Process results
		for _, urlStr := range result.Output {
			urlStr = strings.TrimSpace(urlStr)
			if urlStr != "" && util.IsValidURL(urlStr) {
				allURLs = append(allURLs, urlStr)

				findings = append(findings, output.Finding{
					Timestamp: time.Now(),
					Stage:     "urls",
					Type:      ud.determineURLType(urlStr),
					Target:    domain,
					Value:     urlStr,
					Metadata: map[string]string{
						"tool":   "gau",
						"source": "historical",
					},
				})
			}
		}

		ud.logger.Debug("GAU completed for domain", "domain", domain, "urls", len(result.Output))
	}

	return allURLs, findings, nil
}

// runWaybackurls executes waybackurls for historical URL discovery
func (ud *URLDiscoverer) runWaybackurls(ctx context.Context, domains []string) ([]string, []output.Finding, error) {
	// Create temporary input file
	tempDir := filepath.Join(os.TempDir(), "ezrec-wayback-"+util.GenerateTimestamp())
	if err := os.MkdirAll(tempDir, 0755); err != nil {
		return nil, nil, fmt.Errorf("failed to create temp directory: %w", err)
	}
	defer os.RemoveAll(tempDir)

	inputFile := filepath.Join(tempDir, "domains.txt")

	// Write domains to input file
	input := strings.Join(domains, "\n")
	if err := os.WriteFile(inputFile, []byte(input), 0644); err != nil {
		return nil, nil, fmt.Errorf("failed to write input file: %w", err)
	}

	args := []string{}

	// Add configuration options
	if ud.config.Tools.Waybackurls.GetVersions {
		args = append(args, "-get-versions")
	}

	if ud.config.Tools.Waybackurls.NoSubs {
		args = append(args, "-no-subs")
	}

	// Execute waybackurls with input from file
	result, err := ud.executor.ExecuteWithInput(ctx, input, "waybackurls", args...)
	if err != nil {
		return nil, nil, fmt.Errorf("waybackurls execution failed: %w", err)
	}

	if !result.Successful {
		ud.logger.Warn("Waybackurls completed with errors", "error", result.Error)
	}

	var allURLs []string
	var findings []output.Finding

	// Process results
	for _, urlStr := range result.Output {
		urlStr = strings.TrimSpace(urlStr)
		if urlStr != "" && util.IsValidURL(urlStr) {
			allURLs = append(allURLs, urlStr)

			// Determine which domain this URL belongs to
			targetDomain := ud.findTargetDomain(urlStr, domains)

			findings = append(findings, output.Finding{
				Timestamp: time.Now(),
				Stage:     "urls",
				Type:      ud.determineURLType(urlStr),
				Target:    targetDomain,
				Value:     urlStr,
				Metadata: map[string]string{
					"tool":   "waybackurls",
					"source": "wayback_machine",
				},
			})
		}
	}

	ud.logger.Success("Waybackurls completed", "urls", len(allURLs))
	return allURLs, findings, nil
}

// determineURLType determines the type of URL based on its characteristics
func (ud *URLDiscoverer) determineURLType(urlStr string) string {
	urlStr = strings.ToLower(urlStr)

	// Check for API endpoints
	if strings.Contains(urlStr, "/api/") || strings.Contains(urlStr, "/v1/") ||
		strings.Contains(urlStr, "/v2/") || strings.Contains(urlStr, "/rest/") ||
		strings.Contains(urlStr, "/graphql") {
		return "api_endpoint"
	}

	// Check for admin panels
	if strings.Contains(urlStr, "/admin") || strings.Contains(urlStr, "/dashboard") ||
		strings.Contains(urlStr, "/manage") || strings.Contains(urlStr, "/control") {
		return "admin_endpoint"
	}

	// Check for authentication
	if strings.Contains(urlStr, "/login") || strings.Contains(urlStr, "/signin") ||
		strings.Contains(urlStr, "/auth") || strings.Contains(urlStr, "/oauth") {
		return "auth_endpoint"
	}

	// Check for file uploads
	if strings.Contains(urlStr, "/upload") || strings.Contains(urlStr, "/file") {
		return "upload_endpoint"
	}

	// Check for sensitive files
	if strings.Contains(urlStr, ".env") || strings.Contains(urlStr, ".config") ||
		strings.Contains(urlStr, ".bak") || strings.Contains(urlStr, ".backup") {
		return "sensitive_file"
	}

	// Check for database files
	if strings.Contains(urlStr, ".sql") || strings.Contains(urlStr, ".db") ||
		strings.Contains(urlStr, ".sqlite") {
		return "database_file"
	}

	// Check for configuration files
	if strings.Contains(urlStr, "config") || strings.Contains(urlStr, "settings") {
		return "config_file"
	}

	// Check for parameters
	if strings.Contains(urlStr, "?") {
		return "parameterized_url"
	}

	return "historical_url"
}

// findTargetDomain finds which target domain a URL belongs to
func (ud *URLDiscoverer) findTargetDomain(urlStr string, domains []string) string {
	for _, domain := range domains {
		if strings.Contains(urlStr, domain) {
			return domain
		}
	}

	// If no match found, try to extract domain from URL
	if parsed := util.ExtractDomain(urlStr); parsed != "" {
		return parsed
	}

	return "unknown"
}

// filterAndDeduplicateURLs filters and deduplicates URLs
func (ud *URLDiscoverer) filterAndDeduplicateURLs(urls []string) []string {
	seen := make(map[string]bool)
	var filtered []string

	for _, urlStr := range urls {
		urlStr = strings.TrimSpace(urlStr)

		// Skip empty URLs
		if urlStr == "" {
			continue
		}

		// Skip if already seen
		if seen[urlStr] {
			continue
		}
		seen[urlStr] = true

		// Skip common static file extensions
		if ud.isStaticFile(urlStr) {
			continue
		}

		// Validate URL
		if !util.IsValidURL(urlStr) {
			continue
		}

		filtered = append(filtered, urlStr)
	}

	return filtered
}

// isStaticFile checks if a URL points to a static file
func (ud *URLDiscoverer) isStaticFile(urlStr string) bool {
	staticExtensions := []string{
		".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
		".woff", ".woff2", ".ttf", ".eot", ".mp4", ".mp3", ".avi", ".mov",
		".pdf", ".zip", ".rar", ".tar", ".gz",
	}

	urlLower := strings.ToLower(urlStr)
	for _, ext := range staticExtensions {
		if strings.HasSuffix(urlLower, ext) {
			return true
		}
	}

	return false
}

// DiscoverURLsWithFilters discovers URLs with custom filters
func (ud *URLDiscoverer) DiscoverURLsWithFilters(ctx context.Context, domains []string, includePatterns, excludePatterns []string) ([]string, []output.Finding, error) {
	// Get all URLs first
	allURLs, findings, err := ud.DiscoverHistoricalURLs(ctx, domains)
	if err != nil {
		return nil, nil, err
	}

	// Apply filters
	var filteredURLs []string
	for _, urlStr := range allURLs {
		// Check include patterns
		included := len(includePatterns) == 0
		for _, pattern := range includePatterns {
			if strings.Contains(strings.ToLower(urlStr), strings.ToLower(pattern)) {
				included = true
				break
			}
		}

		if !included {
			continue
		}

		// Check exclude patterns
		excluded := false
		for _, pattern := range excludePatterns {
			if strings.Contains(strings.ToLower(urlStr), strings.ToLower(pattern)) {
				excluded = true
				break
			}
		}

		if !excluded {
			filteredURLs = append(filteredURLs, urlStr)
		}
	}

	ud.logger.Success("URL filtering completed", "original", len(allURLs), "filtered", len(filteredURLs))
	return filteredURLs, findings, nil
}

// DiscoverParameterizedURLs specifically looks for URLs with parameters
func (ud *URLDiscoverer) DiscoverParameterizedURLs(ctx context.Context, domains []string) ([]string, []output.Finding, error) {
	allURLs, findings, err := ud.DiscoverHistoricalURLs(ctx, domains)
	if err != nil {
		return nil, nil, err
	}

	var paramURLs []string
	var paramFindings []output.Finding

	for _, urlStr := range allURLs {
		if strings.Contains(urlStr, "?") {
			paramURLs = append(paramURLs, urlStr)

			// Create specific finding for parameterized URL
			finding := output.Finding{
				Timestamp:   time.Now(),
				Stage:       "urls",
				Type:        "parameterized_url",
				Target:      ud.findTargetDomain(urlStr, domains),
				Value:       urlStr,
				Description: "URL with parameters found in historical data",
				Metadata: map[string]string{
					"tool":        "url_discovery",
					"has_params":  "true",
					"param_count": strconv.Itoa(strings.Count(urlStr, "&") + 1),
				},
			}
			paramFindings = append(paramFindings, finding)
		}
	}

	// Add original findings
	paramFindings = append(paramFindings, findings...)

	ud.logger.Success("Parameterized URL discovery completed", "param_urls", len(paramURLs))
	return paramURLs, paramFindings, nil
}

// GetAvailableTools returns a list of available URL discovery tools
func (ud *URLDiscoverer) GetAvailableTools() []string {
	var tools []string

	if ud.executor.CheckTool("gau") {
		tools = append(tools, "gau")
	}

	if ud.executor.CheckTool("waybackurls") {
		tools = append(tools, "waybackurls")
	}

	return tools
}

// GetURLStatistics returns statistics about discovered URLs
func (ud *URLDiscoverer) GetURLStatistics(urls []string) map[string]int {
	stats := make(map[string]int)

	for _, urlStr := range urls {
		urlType := ud.determineURLType(urlStr)
		stats[urlType]++

		// Count parameters
		if strings.Contains(urlStr, "?") {
			stats["with_parameters"]++
		} else {
			stats["without_parameters"]++
		}

		// Count by scheme
		if strings.HasPrefix(urlStr, "https://") {
			stats["https"]++
		} else if strings.HasPrefix(urlStr, "http://") {
			stats["http"]++
		}
	}

	stats["total"] = len(urls)
	return stats
}
