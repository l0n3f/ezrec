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

// FfufFuzzer handles directory and file fuzzing using FFUF
type FfufFuzzer struct {
	config   *config.Config
	executor *runner.Executor
	logger   *log.Logger
}

// FfufResult represents the JSON output from FFUF
type FfufResult struct {
	Input            FfufInput `json:"input"`
	Position         int       `json:"position"`
	StatusCode       int       `json:"status"`
	ContentLength    int       `json:"length"`
	Words            int       `json:"words"`
	Lines            int       `json:"lines"`
	ContentType      string    `json:"content-type"`
	RedirectLocation string    `json:"redirectlocation"`
	URL              string    `json:"url"`
	ResultFile       string    `json:"resultfile"`
	Host             string    `json:"host"`
	HTML             string    `json:"html"`
	Duration         int       `json:"duration"`
}

// FfufInput represents the input data for FFUF
type FfufInput struct {
	FUZZ string `json:"FUZZ"`
}

// FfufConfig represents the configuration section in FFUF output
type FfufConfig struct {
	Method          string            `json:"method"`
	URL             string            `json:"url"`
	Headers         map[string]string `json:"headers"`
	Data            string            `json:"data"`
	Extensions      []string          `json:"extensions"`
	DirSearchCompat bool              `json:"dirsearch_compatibility"`
	Calibration     bool              `json:"calibration"`
	Timeout         int               `json:"timeout"`
	Delay           string            `json:"delay"`
	MaxTime         int               `json:"maxtime"`
	MaxTimeJob      int               `json:"maxtimejob"`
	Threads         int               `json:"threads"`
	MatcherStatus   []int             `json:"matcher_status"`
	FilterStatus    []int             `json:"filter_status"`
	FilterSize      []int             `json:"filter_size"`
	FilterWords     []int             `json:"filter_words"`
	FilterLines     []int             `json:"filter_lines"`
}

// FfufOutput represents the complete FFUF JSON output
type FfufOutput struct {
	CommandLine string       `json:"commandline"`
	Time        string       `json:"time"`
	Results     []FfufResult `json:"results"`
	Config      FfufConfig   `json:"config"`
}

// NewFfufFuzzer creates a new FFUF fuzzer
func NewFfufFuzzer(cfg *config.Config, logger *log.Logger) *FfufFuzzer {
	return &FfufFuzzer{
		config:   cfg,
		executor: runner.NewExecutor(logger),
		logger:   logger,
	}
}

// FuzzDirectories performs directory fuzzing on a list of URLs
func (ff *FfufFuzzer) FuzzDirectories(ctx context.Context, urls []string, options FfufOptions) ([]output.Finding, error) {
	if !ff.executor.CheckTool("ffuf") {
		return nil, fmt.Errorf("ffuf not found in PATH")
	}

	ff.logger.Progress("Starting directory fuzzing", "urls", len(urls))

	var allFindings []output.Finding

	for _, targetURL := range urls {
		ff.logger.Debug("Fuzzing directories for URL", "url", targetURL)

		findings, err := ff.fuzzTarget(ctx, targetURL, "directories", options)
		if err != nil {
			ff.logger.Warn("Directory fuzzing failed for URL", "url", targetURL, "error", err)
			continue
		}

		allFindings = append(allFindings, findings...)
		ff.logger.Debug("Directory fuzzing completed for URL", "url", targetURL, "findings", len(findings))
	}

	ff.logger.Success("Directory fuzzing completed", "total_findings", len(allFindings))
	return allFindings, nil
}

// FuzzFiles performs file fuzzing on a list of URLs
func (ff *FfufFuzzer) FuzzFiles(ctx context.Context, urls []string, options FfufOptions) ([]output.Finding, error) {
	if !ff.executor.CheckTool("ffuf") {
		return nil, fmt.Errorf("ffuf not found in PATH")
	}

	ff.logger.Progress("Starting file fuzzing", "urls", len(urls))

	var allFindings []output.Finding

	for _, targetURL := range urls {
		ff.logger.Debug("Fuzzing files for URL", "url", targetURL)

		findings, err := ff.fuzzTarget(ctx, targetURL, "files", options)
		if err != nil {
			ff.logger.Warn("File fuzzing failed for URL", "url", targetURL, "error", err)
			continue
		}

		allFindings = append(allFindings, findings...)
		ff.logger.Debug("File fuzzing completed for URL", "url", targetURL, "findings", len(findings))
	}

	ff.logger.Success("File fuzzing completed", "total_findings", len(allFindings))
	return allFindings, nil
}

// fuzzTarget performs fuzzing on a single target
func (ff *FfufFuzzer) fuzzTarget(ctx context.Context, targetURL, fuzzType string, options FfufOptions) ([]output.Finding, error) {
	// Create temporary files
	tempDir := filepath.Join(os.TempDir(), "ezrec-ffuf-"+util.GenerateTimestamp())
	if err := os.MkdirAll(tempDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create temp directory: %w", err)
	}
	defer os.RemoveAll(tempDir)

	outputFile := filepath.Join(tempDir, "ffuf-output.json")

	// Build ffuf command
	args := ff.buildFfufArgs(targetURL, outputFile, fuzzType, options)

	// Execute ffuf
	result, err := ff.executor.Execute(ctx, "ffuf", args...)
	if err != nil {
		return nil, fmt.Errorf("ffuf execution failed: %w", err)
	}

	if !result.Successful {
		ff.logger.Debug("FFUF completed with warnings", "error", result.Error)
	}

	// Parse results
	findings, err := ff.parseFfufResults(outputFile, targetURL, fuzzType)
	if err != nil {
		return nil, fmt.Errorf("failed to parse ffuf results: %w", err)
	}

	return findings, nil
}

// buildFfufArgs constructs the command line arguments for FFUF
func (ff *FfufFuzzer) buildFfufArgs(targetURL, outputFile, fuzzType string, options FfufOptions) []string {
	// Determine wordlist
	wordlist := options.Wordlist
	if wordlist == "" && len(ff.config.Tools.Ffuf.Wordlists) > 0 {
		wordlist = ff.config.Tools.Ffuf.Wordlists[0]
	}
	if wordlist == "" {
		wordlist = "./wordlists/common.txt" // Default fallback
	}

	// Build base URL for fuzzing
	var fuzzerURL string
	if fuzzType == "directories" {
		if !strings.HasSuffix(targetURL, "/") {
			targetURL += "/"
		}
		fuzzerURL = targetURL + "FUZZ/"
	} else {
		// Files fuzzing
		parsed, err := url.Parse(targetURL)
		if err != nil {
			fuzzerURL = targetURL + "/FUZZ"
		} else {
			parsed.Path = strings.TrimSuffix(parsed.Path, "/") + "/FUZZ"
			fuzzerURL = parsed.String()
		}
	}

	args := []string{
		"-u", fuzzerURL,
		"-w", wordlist,
		"-o", outputFile,
		"-of", "json",
		"-s", // Silent mode
	}

	// Add threads
	if ff.config.Tools.Ffuf.Threads > 0 {
		args = append(args, "-t", strconv.Itoa(ff.config.Tools.Ffuf.Threads))
	}

	// Add delay
	if ff.config.Tools.Ffuf.Delay != "" {
		args = append(args, "-p", ff.config.Tools.Ffuf.Delay)
	}

	// Add match codes
	if len(ff.config.Tools.Ffuf.MatchCodes) > 0 {
		codes := make([]string, len(ff.config.Tools.Ffuf.MatchCodes))
		for i, code := range ff.config.Tools.Ffuf.MatchCodes {
			codes[i] = strconv.Itoa(code)
		}
		args = append(args, "-mc", strings.Join(codes, ","))
	}

	// Add filter size
	if len(ff.config.Tools.Ffuf.FilterSize) > 0 {
		sizes := make([]string, len(ff.config.Tools.Ffuf.FilterSize))
		for i, size := range ff.config.Tools.Ffuf.FilterSize {
			sizes[i] = strconv.Itoa(size)
		}
		args = append(args, "-fs", strings.Join(sizes, ","))
	}

	// Add filter words
	if len(ff.config.Tools.Ffuf.FilterWords) > 0 {
		words := make([]string, len(ff.config.Tools.Ffuf.FilterWords))
		for i, word := range ff.config.Tools.Ffuf.FilterWords {
			words[i] = strconv.Itoa(word)
		}
		args = append(args, "-fw", strings.Join(words, ","))
	}

	// Add filter lines
	if len(ff.config.Tools.Ffuf.FilterLines) > 0 {
		lines := make([]string, len(ff.config.Tools.Ffuf.FilterLines))
		for i, line := range ff.config.Tools.Ffuf.FilterLines {
			lines[i] = strconv.Itoa(line)
		}
		args = append(args, "-fl", strings.Join(lines, ","))
	}

	// Add extensions for file fuzzing
	if fuzzType == "files" && len(ff.config.Tools.Ffuf.Extensions) > 0 {
		args = append(args, "-e", strings.Join(ff.config.Tools.Ffuf.Extensions, ","))
	}

	// Add recursion if enabled
	if ff.config.Tools.Ffuf.Recursion {
		args = append(args, "-recursion")
		if ff.config.Tools.Ffuf.RecursionDepth > 0 {
			args = append(args, "-recursion-depth", strconv.Itoa(ff.config.Tools.Ffuf.RecursionDepth))
		}
	}

	// Add custom headers
	if len(ff.config.Headers) > 0 {
		for key, value := range ff.config.Headers {
			args = append(args, "-H", fmt.Sprintf("%s: %s", key, value))
		}
	}

	// Add arc limit if specified (FFUF uses -ac flag for auto-calibration and request limits)
	if options.Arcs > 0 {
		// Use -maxtime to limit execution time based on arcs
		maxTime := (options.Arcs / ff.config.Tools.Ffuf.Threads) * 2 // Estimate time
		if maxTime < 60 {
			maxTime = 60 // Minimum 1 minute
		}
		if maxTime > 1800 {
			maxTime = 1800 // Maximum 30 minutes
		}
		args = append(args, "-maxtime", strconv.Itoa(maxTime))
		
		// Also add auto-calibration for better results
		args = append(args, "-ac")
	}

	return args
}

// parseFfufResults parses the JSON output from FFUF
func (ff *FfufFuzzer) parseFfufResults(outputFile, targetURL, fuzzType string) ([]output.Finding, error) {
	// Check if output file exists
	if _, err := os.Stat(outputFile); os.IsNotExist(err) {
		ff.logger.Debug("FFUF output file not found, no results")
		return []output.Finding{}, nil
	}

	content, err := os.ReadFile(outputFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read ffuf output: %w", err)
	}

	var ffufOutput FfufOutput
	if err := json.Unmarshal(content, &ffufOutput); err != nil {
		return nil, fmt.Errorf("failed to parse ffuf JSON output: %w", err)
	}

	var findings []output.Finding

	for _, result := range ffufOutput.Results {
		finding := output.Finding{
			Timestamp:   time.Now(),
			Stage:       "ffuf",
			Type:        ff.determineFindingType(result, fuzzType),
			Target:      targetURL,
			Value:       result.URL,
			Description: ff.buildDescription(result, fuzzType),
			Metadata:    ff.buildMetadata(result, fuzzType),
		}

		// Set severity based on status code and content
		finding.Severity = ff.determineSeverity(result)

		findings = append(findings, finding)

		// Log interesting findings
		if ff.isInterestingFinding(result) {
			ff.logger.Info("Interesting finding discovered",
				"url", result.URL,
				"status", result.StatusCode,
				"size", result.ContentLength,
				"type", fuzzType)
		}
	}

	return findings, nil
}

// determineFindingType determines the type of finding based on the result
func (ff *FfufFuzzer) determineFindingType(result FfufResult, fuzzType string) string {
	url := strings.ToLower(result.URL)

	// Check for admin panels
	if strings.Contains(url, "admin") || strings.Contains(url, "administrator") {
		return "admin_directory"
	}

	// Check for API endpoints
	if strings.Contains(url, "api") || strings.Contains(url, "/v1") || strings.Contains(url, "/v2") {
		return "api_directory"
	}

	// Check for backup files
	if strings.Contains(url, "backup") || strings.Contains(url, ".bak") || strings.Contains(url, ".old") {
		return "backup_file"
	}

	// Check for config files
	if strings.Contains(url, "config") || strings.Contains(url, ".env") || strings.Contains(url, "settings") {
		return "config_file"
	}

	// Check for upload directories
	if strings.Contains(url, "upload") || strings.Contains(url, "file") {
		return "upload_directory"
	}

	// Default based on fuzz type
	if fuzzType == "directories" {
		return "directory"
	} else {
		return "file"
	}
}

// buildDescription creates a human-readable description
func (ff *FfufFuzzer) buildDescription(result FfufResult, fuzzType string) string {
	parts := []string{
		fmt.Sprintf("Status: %d", result.StatusCode),
		fmt.Sprintf("Size: %d", result.ContentLength),
		fmt.Sprintf("Words: %d", result.Words),
		fmt.Sprintf("Lines: %d", result.Lines),
	}

	if result.ContentType != "" {
		parts = append(parts, fmt.Sprintf("Type: %s", result.ContentType))
	}

	if result.RedirectLocation != "" {
		parts = append(parts, fmt.Sprintf("Redirect: %s", result.RedirectLocation))
	}

	return strings.Join(parts, " | ")
}

// buildMetadata creates metadata map for the finding
func (ff *FfufFuzzer) buildMetadata(result FfufResult, fuzzType string) map[string]string {
	metadata := map[string]string{
		"tool":           "ffuf",
		"fuzz_type":      fuzzType,
		"status_code":    strconv.Itoa(result.StatusCode),
		"content_length": strconv.Itoa(result.ContentLength),
		"words":          strconv.Itoa(result.Words),
		"lines":          strconv.Itoa(result.Lines),
		"duration":       strconv.Itoa(result.Duration),
		"position":       strconv.Itoa(result.Position),
	}

	if result.ContentType != "" {
		metadata["content_type"] = result.ContentType
	}

	if result.RedirectLocation != "" {
		metadata["redirect_location"] = result.RedirectLocation
	}

	if result.Host != "" {
		metadata["host"] = result.Host
	}

	if result.Input.FUZZ != "" {
		metadata["fuzzed_value"] = result.Input.FUZZ
	}

	return metadata
}

// determineSeverity determines the severity based on the result
func (ff *FfufFuzzer) determineSeverity(result FfufResult) string {
	url := strings.ToLower(result.URL)

	// High severity for sensitive areas
	if strings.Contains(url, "admin") || strings.Contains(url, ".env") ||
		strings.Contains(url, "config") || strings.Contains(url, "backup") {
		return "high"
	}

	// Medium severity for interesting status codes
	if result.StatusCode == 200 || result.StatusCode == 403 {
		return "medium"
	}

	// Low severity for redirects and other codes
	if result.StatusCode >= 300 && result.StatusCode < 400 {
		return "low"
	}

	return "info"
}

// isInterestingFinding checks if a finding is particularly interesting
func (ff *FfufFuzzer) isInterestingFinding(result FfufResult) bool {
	url := strings.ToLower(result.URL)

	// Check for interesting keywords
	interestingKeywords := []string{
		"admin", "administrator", "dashboard", "control",
		"api", "v1", "v2", "graphql",
		"backup", ".bak", ".old", ".orig",
		"config", ".env", "settings",
		"upload", "file", "media",
		"login", "auth", "oauth",
	}

	for _, keyword := range interestingKeywords {
		if strings.Contains(url, keyword) {
			return true
		}
	}

	// Check for interesting status codes
	if result.StatusCode == 200 || result.StatusCode == 403 || result.StatusCode == 401 {
		return true
	}

	// Check for large content
	if result.ContentLength > 10000 {
		return true
	}

	return false
}

// FuzzWithCustomWordlist performs fuzzing with a custom wordlist
func (ff *FfufFuzzer) FuzzWithCustomWordlist(ctx context.Context, urls []string, wordlist string, fuzzType string) ([]output.Finding, error) {
	options := FfufOptions{
		Wordlist: wordlist,
		Arcs:     0, // No limit
	}

	if fuzzType == "directories" {
		return ff.FuzzDirectories(ctx, urls, options)
	} else {
		return ff.FuzzFiles(ctx, urls, options)
	}
}

// GenerateWordlistFromURLs generates a custom wordlist based on discovered URLs
func (ff *FfufFuzzer) GenerateWordlistFromURLs(urls []string) []string {
	wordSet := make(map[string]bool)

	for _, urlStr := range urls {
		parsed, err := url.Parse(urlStr)
		if err != nil {
			continue
		}

		// Extract path components
		pathParts := strings.Split(strings.Trim(parsed.Path, "/"), "/")
		for _, part := range pathParts {
			if part != "" && len(part) > 2 {
				wordSet[part] = true
			}
		}

		// Extract query parameters
		for key := range parsed.Query() {
			if key != "" && len(key) > 2 {
				wordSet[key] = true
			}
		}
	}

	var wordlist []string
	for word := range wordSet {
		wordlist = append(wordlist, word)
	}

	return wordlist
}

// GetAvailableTools returns a list of available fuzzing tools
func (ff *FfufFuzzer) GetAvailableTools() []string {
	var tools []string

	if ff.executor.CheckTool("ffuf") {
		tools = append(tools, "ffuf")
	}

	return tools
}

// GetFuzzingStatistics returns statistics about fuzzing results
func (ff *FfufFuzzer) GetFuzzingStatistics(findings []output.Finding) map[string]int {
	stats := make(map[string]int)

	for _, finding := range findings {
		// Count by type
		stats[finding.Type]++

		// Count by severity
		severity := finding.Severity
		if severity == "" {
			severity = "info"
		}
		stats["severity_"+severity]++

		// Count by status code
		if statusCode, exists := finding.Metadata["status_code"]; exists {
			stats["status_"+statusCode]++
		}
	}

	stats["total"] = len(findings)
	return stats
}
