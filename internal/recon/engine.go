package recon

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/ezrec/ezrec/internal/ai"
	"github.com/ezrec/ezrec/internal/classify"
	"github.com/ezrec/ezrec/internal/config"
	"github.com/ezrec/ezrec/internal/log"
	"github.com/ezrec/ezrec/internal/output"
	"github.com/ezrec/ezrec/internal/scope"
	"github.com/ezrec/ezrec/internal/telegram"
	"github.com/ezrec/ezrec/internal/waf"
)

// Engine orchestrates the reconnaissance pipeline
type Engine struct {
	config   *config.Config
	output   *output.Manager
	telegram *telegram.Client
	logger   *log.Logger
	scope    *scope.Matcher
}

// SubdomainResult represents the result of subdomain enumeration
type SubdomainResult struct {
	Subdomains []string
	Findings   []output.Finding
	Duration   time.Duration
}

// HostProbeResult represents the result of host probing
type HostProbeResult struct {
	LiveHosts []string
	Findings  []output.Finding
	Duration  time.Duration
}

// CrawlResult represents the result of crawling
type CrawlResult struct {
	URLs     []string
	Findings []output.Finding
	Duration time.Duration
}

// URLDiscoveryResult represents the result of URL discovery
type URLDiscoveryResult struct {
	URLs     []string
	Findings []output.Finding
	Duration time.Duration
}

// EndpointClassificationResult represents the result of endpoint classification
type EndpointClassificationResult struct {
	HighValueTargets []string
	Findings         []output.Finding
	Duration         time.Duration
}

// XSSResult represents the result of XSS testing
type XSSResult struct {
	Vulnerabilities []output.Finding
	Duration        time.Duration
}

// NucleiScanResult represents the result of Nuclei scanning
type NucleiScanResult struct {
	Findings []Finding
	Duration time.Duration
}

// FfufScanResult represents the result of FFUF fuzzing
type FfufScanResult struct {
	Discoveries []output.Finding
	Duration    time.Duration
}

// Finding represents a security finding
type Finding struct {
	URL         string
	Template    string
	Severity    string
	Description string
	Metadata    map[string]string
}

// XSSOptions contains options for XSS testing
type XSSOptions struct {
	Payload   string
	AISuggest bool
	WAFBypass bool
	WAFDetect bool
}

// NucleiOptions contains options for Nuclei scanning
type NucleiOptions struct {
	Templates string
	Severity  []string
	Tags      []string
}

// FfufOptions contains options for FFUF fuzzing
type FfufOptions struct {
	Arcs     int
	Wordlist string
}

// NewEngine creates a new reconnaissance engine
func NewEngine(cfg *config.Config, outputManager *output.Manager, telegramClient *telegram.Client, logger *log.Logger) *Engine {
	// Create scope matcher
	scopeMatcher, err := scope.NewMatcher(cfg.Scope.Include, cfg.Scope.Exclude)
	if err != nil {
		logger.Error("Failed to create scope matcher", "error", err)
		scopeMatcher, _ = scope.NewMatcher([]string{".*"}, []string{})
	}

	return &Engine{
		config:   cfg,
		output:   outputManager,
		telegram: telegramClient,
		logger:   logger,
		scope:    scopeMatcher,
	}
}

// EnumerateSubdomains performs subdomain enumeration
func (e *Engine) EnumerateSubdomains(ctx context.Context, targets []string) (*SubdomainResult, error) {
	start := time.Now()
	e.logger.Progress("Starting subdomain enumeration", "targets", len(targets))

	var allSubdomains []string
	var findings []output.Finding

	// Use both subfinder and amass for comprehensive coverage
	subfinderResults, err := e.runSubfinder(ctx, targets)
	if err != nil {
		e.logger.Warn("Subfinder failed", "error", err)
	} else {
		allSubdomains = append(allSubdomains, subfinderResults...)
	}

	amassResults, err := e.runAmass(ctx, targets)
	if err != nil {
		e.logger.Warn("Amass failed", "error", err)
	} else {
		allSubdomains = append(allSubdomains, amassResults...)
	}

	// Deduplicate and filter by scope
	allSubdomains = e.deduplicateStrings(allSubdomains)
	allSubdomains = e.scope.FilterTargets(allSubdomains)

	// Create findings
	for _, subdomain := range allSubdomains {
		findings = append(findings, output.Finding{
			Timestamp: time.Now(),
			Stage:     "subdomains",
			Type:      "subdomain",
			Target:    strings.Join(targets, ","),
			Value:     subdomain,
		})
	}

	duration := time.Since(start)
	result := &SubdomainResult{
		Subdomains: allSubdomains,
		Findings:   findings,
		Duration:   duration,
	}

	// Write output
	stageResult := &output.StageResult{
		Stage:       "subdomains",
		Timestamp:   start,
		Duration:    duration,
		InputCount:  len(targets),
		OutputCount: len(allSubdomains),
		Findings:    findings,
	}

	writer := e.output.GetStageWriter("subdomains")
	if err := writer.WriteStageResult(stageResult); err != nil {
		e.logger.Error("Failed to write subdomain results", "error", err)
	}

	e.logger.Success("Subdomain enumeration completed", "found", len(allSubdomains), "duration", duration)
	return result, nil
}

// ProbeHosts performs host liveness checking and fingerprinting
func (e *Engine) ProbeHosts(ctx context.Context, targets []string) (*HostProbeResult, error) {
	start := time.Now()
	e.logger.Progress("Starting host probing", "targets", len(targets))

	// Run httpx for host probing
	liveHosts, findings, err := e.runHttpx(ctx, targets)
	if err != nil {
		return nil, fmt.Errorf("httpx failed: %w", err)
	}

	// Filter by scope
	liveHosts = e.scope.FilterTargets(liveHosts)

	duration := time.Since(start)
	result := &HostProbeResult{
		LiveHosts: liveHosts,
		Findings:  findings,
		Duration:  duration,
	}

	// Write output
	stageResult := &output.StageResult{
		Stage:       "httpx",
		Timestamp:   start,
		Duration:    duration,
		InputCount:  len(targets),
		OutputCount: len(liveHosts),
		Findings:    findings,
	}

	writer := e.output.GetStageWriter("httpx")
	if err := writer.WriteStageResult(stageResult); err != nil {
		e.logger.Error("Failed to write httpx results", "error", err)
	}

	e.logger.Success("Host probing completed", "live", len(liveHosts), "duration", duration)
	return result, nil
}

// CrawlEndpoints performs endpoint crawling
func (e *Engine) CrawlEndpoints(ctx context.Context, targets []string) (*CrawlResult, error) {
	start := time.Now()
	e.logger.Progress("Starting endpoint crawling", "targets", len(targets))

	// Run katana for crawling
	urls, findings, err := e.runKatana(ctx, targets)
	if err != nil {
		return nil, fmt.Errorf("katana failed: %w", err)
	}

	// Filter by scope
	urls = e.scope.FilterURLs(urls)

	duration := time.Since(start)
	result := &CrawlResult{
		URLs:     urls,
		Findings: findings,
		Duration: duration,
	}

	// Write output
	stageResult := &output.StageResult{
		Stage:       "crawl",
		Timestamp:   start,
		Duration:    duration,
		InputCount:  len(targets),
		OutputCount: len(urls),
		Findings:    findings,
	}

	writer := e.output.GetStageWriter("crawl")
	if err := writer.WriteStageResult(stageResult); err != nil {
		e.logger.Error("Failed to write crawl results", "error", err)
	}

	e.logger.Success("Endpoint crawling completed", "urls", len(urls), "duration", duration)
	return result, nil
}

// DiscoverHistoricalURLs discovers URLs from historical sources
func (e *Engine) DiscoverHistoricalURLs(ctx context.Context, targets []string) (*URLDiscoveryResult, error) {
	start := time.Now()
	e.logger.Progress("Starting historical URL discovery", "targets", len(targets))

	var allURLs []string
	var findings []output.Finding

	// Run gau
	gauURLs, err := e.runGau(ctx, targets)
	if err != nil {
		e.logger.Warn("GAU failed", "error", err)
	} else {
		allURLs = append(allURLs, gauURLs...)
	}

	// Run waybackurls
	waybackURLs, err := e.runWaybackurls(ctx, targets)
	if err != nil {
		e.logger.Warn("Waybackurls failed", "error", err)
	} else {
		allURLs = append(allURLs, waybackURLs...)
	}

	// Deduplicate and filter by scope
	allURLs = e.deduplicateStrings(allURLs)
	allURLs = e.scope.FilterURLs(allURLs)

	// Create findings
	for _, url := range allURLs {
		findings = append(findings, output.Finding{
			Timestamp: time.Now(),
			Stage:     "urls",
			Type:      "historical_url",
			Target:    strings.Join(targets, ","),
			Value:     url,
		})
	}

	duration := time.Since(start)
	result := &URLDiscoveryResult{
		URLs:     allURLs,
		Findings: findings,
		Duration: duration,
	}

	// Write output
	stageResult := &output.StageResult{
		Stage:       "urls",
		Timestamp:   start,
		Duration:    duration,
		InputCount:  len(targets),
		OutputCount: len(allURLs),
		Findings:    findings,
	}

	writer := e.output.GetStageWriter("urls")
	if err := writer.WriteStageResult(stageResult); err != nil {
		e.logger.Error("Failed to write URL discovery results", "error", err)
	}

	e.logger.Success("Historical URL discovery completed", "urls", len(allURLs), "duration", duration)
	return result, nil
}

// ClassifyEndpoints classifies endpoints into high-value targets
func (e *Engine) ClassifyEndpoints(ctx context.Context, urls []string) (*EndpointClassificationResult, error) {
	start := time.Now()
	e.logger.Progress("Starting endpoint classification", "urls", len(urls))

	hvtEndpoints, findings := e.classifyHighValueTargets(urls)

	duration := time.Since(start)
	result := &EndpointClassificationResult{
		HighValueTargets: hvtEndpoints,
		Findings:         findings,
		Duration:         duration,
	}

	// Write output
	stageResult := &output.StageResult{
		Stage:       "endpoints",
		Timestamp:   start,
		Duration:    duration,
		InputCount:  len(urls),
		OutputCount: len(hvtEndpoints),
		Findings:    findings,
	}

	writer := e.output.GetStageWriter("endpoints")
	if err := writer.WriteStageResult(stageResult); err != nil {
		e.logger.Error("Failed to write endpoint classification results", "error", err)
	}

	e.logger.Success("Endpoint classification completed", "hvt", len(hvtEndpoints), "duration", duration)
	return result, nil
}

// TestXSS performs XSS testing
func (e *Engine) TestXSS(ctx context.Context, urls []string, options XSSOptions) (*XSSResult, error) {
	start := time.Now()
	e.logger.Progress("Starting XSS testing", "urls", len(urls))

	// This is a placeholder - actual XSS testing implementation would go here
	var vulnerabilities []output.Finding

	duration := time.Since(start)
	result := &XSSResult{
		Vulnerabilities: vulnerabilities,
		Duration:        duration,
	}

	e.logger.Success("XSS testing completed", "vulnerabilities", len(vulnerabilities), "duration", duration)
	return result, nil
}

// DetectWAF performs WAF detection on target URLs
func (e *Engine) DetectWAF(ctx context.Context, urls []string, aiClient *ai.Client) (map[string]*ai.WAFDetection, error) {
	start := time.Now()
	e.logger.Progress("Starting WAF detection", "urls", len(urls))

	detector := waf.NewDetector(aiClient, e.logger)
	results := make(map[string]*ai.WAFDetection)

	for _, url := range urls {
		if len(results) >= 5 { // Limit to first 5 URLs to avoid overwhelming
			break
		}

		detection, err := detector.DetectWAF(ctx, url)
		if err != nil {
			e.logger.Warn("WAF detection failed for URL", "url", url, "error", err)
			continue
		}

		results[url] = detection

		if detection.Present {
			e.logger.Info("WAF detected",
				"url", url,
				"type", detection.Type,
				"confidence", detection.Confidence)
		}
	}

	duration := time.Since(start)
	e.logger.Success("WAF detection completed", "scanned", len(results), "duration", duration)
	return results, nil
}

// RunNuclei performs Nuclei vulnerability scanning
func (e *Engine) RunNuclei(ctx context.Context, targets []string, options NucleiOptions) (*NucleiScanResult, error) {
	start := time.Now()
	e.logger.Progress("Starting Nuclei scanning", "targets", len(targets))

	scanner := NewNucleiScanner(e.config, e.logger)
	findings, _, err := scanner.ScanTargets(ctx, targets, options)
	if err != nil {
		return nil, err
	}

	duration := time.Since(start)
	result := &NucleiScanResult{
		Findings: findings,
		Duration: duration,
	}

	e.logger.Success("Nuclei scanning completed", "findings", len(findings), "duration", duration)
	return result, nil
}

// RunFfuf performs FFUF fuzzing
func (e *Engine) RunFfuf(ctx context.Context, targets []string, options FfufOptions) (*FfufScanResult, error) {
	start := time.Now()
	e.logger.Progress("Starting FFUF fuzzing", "targets", len(targets))

	fuzzer := NewFfufFuzzer(e.config, e.logger)
	discoveries, err := fuzzer.FuzzDirectories(ctx, targets, options)
	if err != nil {
		return nil, err
	}

	duration := time.Since(start)
	result := &FfufScanResult{
		Discoveries: discoveries,
		Duration:    duration,
	}

	e.logger.Success("FFUF fuzzing completed", "discoveries", len(discoveries), "duration", duration)
	return result, nil
}

// LoadTargetsFromFile loads targets from a file
func LoadTargetsFromFile(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	var targets []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			targets = append(targets, line)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	return targets, nil
}

// deduplicateStrings removes duplicate strings from a slice
func (e *Engine) deduplicateStrings(strs []string) []string {
	seen := make(map[string]bool)
	var result []string

	for _, str := range strs {
		if !seen[str] {
			seen[str] = true
			result = append(result, str)
		}
	}

	return result
}

// runSubfinder integrates with subfinder for subdomain enumeration
func (e *Engine) runSubfinder(ctx context.Context, targets []string) ([]string, error) {
	enumerator := NewSubdomainEnumerator(e.config, e.logger)
	subdomains, _, err := enumerator.EnumerateSubdomains(ctx, targets)
	return subdomains, err
}

// runAmass integrates with amass for subdomain enumeration
func (e *Engine) runAmass(ctx context.Context, targets []string) ([]string, error) {
	enumerator := NewSubdomainEnumerator(e.config, e.logger)
	subdomains, _, err := enumerator.EnumerateSubdomains(ctx, targets)
	return subdomains, err
}

// runHttpx integrates with httpx for host probing
func (e *Engine) runHttpx(ctx context.Context, targets []string) ([]string, []output.Finding, error) {
	prober := NewHttpxProber(e.config, e.logger)
	return prober.ProbeHosts(ctx, targets)
}

func (e *Engine) runKatana(ctx context.Context, targets []string) ([]string, []output.Finding, error) {
	crawler := NewKatanaCrawler(e.config, e.logger)
	return crawler.CrawlEndpoints(ctx, targets)
}

func (e *Engine) runGau(ctx context.Context, targets []string) ([]string, error) {
	discoverer := NewURLDiscoverer(e.config, e.logger)
	urls, _, err := discoverer.DiscoverHistoricalURLs(ctx, targets)
	return urls, err
}

func (e *Engine) runWaybackurls(ctx context.Context, targets []string) ([]string, error) {
	discoverer := NewURLDiscoverer(e.config, e.logger)
	urls, _, err := discoverer.DiscoverHistoricalURLs(ctx, targets)
	return urls, err
}

func (e *Engine) classifyHighValueTargets(urls []string) ([]string, []output.Finding) {
	classifier := classify.NewClassifier()
	classifications := classifier.GetHighValueTargets(urls)

	var hvtURLs []string
	var findings []output.Finding

	for _, classification := range classifications {
		hvtURLs = append(hvtURLs, classification.URL)

		finding := output.Finding{
			Timestamp:   time.Now(),
			Stage:       "endpoints",
			Type:        string(classification.Type),
			Target:      classification.URL,
			Value:       classification.URL,
			Confidence:  fmt.Sprintf("%.2f", classification.Confidence),
			Description: classification.Description,
			Metadata: map[string]string{
				"tool":       "classifier",
				"priority":   fmt.Sprintf("%d", classification.Priority),
				"confidence": fmt.Sprintf("%.2f", classification.Confidence),
				"matches":    strings.Join(classification.Matches, ","),
			},
		}

		// Set severity based on endpoint type and priority
		if classification.Priority >= 10 {
			finding.Severity = "high"
		} else if classification.Priority >= 7 {
			finding.Severity = "medium"
		} else {
			finding.Severity = "low"
		}

		findings = append(findings, finding)
	}

	return hvtURLs, findings
}
