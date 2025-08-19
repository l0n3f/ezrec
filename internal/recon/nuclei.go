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

// NucleiScanner handles vulnerability scanning using Nuclei
type NucleiScanner struct {
	config   *config.Config
	executor *runner.Executor
	logger   *log.Logger
}

// NucleiResult represents the JSON output from Nuclei
type NucleiResult struct {
	TemplateID       string                 `json:"template-id"`
	TemplatePath     string                 `json:"template-path"`
	Info             NucleiInfo             `json:"info"`
	Type             string                 `json:"type"`
	Host             string                 `json:"host"`
	MatchedAt        string                 `json:"matched-at"`
	ExtractedResults []string               `json:"extracted-results"`
	Request          string                 `json:"request"`
	Response         string                 `json:"response"`
	IP               string                 `json:"ip"`
	Timestamp        time.Time              `json:"timestamp"`
	CURLCommand      string                 `json:"curl-command"`
	Matcher          map[string]interface{} `json:"matcher"`
	Metadata         map[string]interface{} `json:"metadata"`
}

// NucleiInfo represents template information
type NucleiInfo struct {
	Name           string            `json:"name"`
	Author         []string          `json:"author"`
	Tags           []string          `json:"tags"`
	Description    string            `json:"description"`
	Reference      []string          `json:"reference"`
	Severity       string            `json:"severity"`
	Metadata       map[string]string `json:"metadata"`
	Classification struct {
		CVSSMetrics string  `json:"cvss-metrics"`
		CVSSScore   float64 `json:"cvss-score"`
		CWEId       []int   `json:"cwe-id"`
	} `json:"classification"`
}

// NewNucleiScanner creates a new Nuclei scanner
func NewNucleiScanner(cfg *config.Config, logger *log.Logger) *NucleiScanner {
	return &NucleiScanner{
		config:   cfg,
		executor: runner.NewExecutor(logger),
		logger:   logger,
	}
}

// ScanTargets performs vulnerability scanning on a list of targets
func (ns *NucleiScanner) ScanTargets(ctx context.Context, targets []string, options NucleiOptions) ([]Finding, []output.Finding, error) {
	if !ns.executor.CheckTool("nuclei") {
		return nil, nil, fmt.Errorf("nuclei not found in PATH")
	}

	ns.logger.Progress("Starting Nuclei vulnerability scanning", "targets", len(targets))

	// Create temporary files
	tempDir := filepath.Join(os.TempDir(), "ezrec-nuclei-"+util.GenerateTimestamp())
	if err := os.MkdirAll(tempDir, 0755); err != nil {
		return nil, nil, fmt.Errorf("failed to create temp directory: %w", err)
	}
	defer os.RemoveAll(tempDir)

	inputFile := filepath.Join(tempDir, "targets.txt")
	outputFile := filepath.Join(tempDir, "nuclei-output.json")

	// Write targets to input file
	input := strings.Join(targets, "\n")
	if err := os.WriteFile(inputFile, []byte(input), 0644); err != nil {
		return nil, nil, fmt.Errorf("failed to write input file: %w", err)
	}

	// Build nuclei command
	args := ns.buildNucleiArgs(inputFile, outputFile, options)

	// Execute nuclei
	result, err := ns.executor.Execute(ctx, "nuclei", args...)
	if err != nil {
		return nil, nil, fmt.Errorf("nuclei execution failed: %w", err)
	}

	if !result.Successful {
		ns.logger.Warn("Nuclei completed with errors", "error", result.Error)
	}

	// Parse results
	findings, outputFindings, err := ns.parseNucleiResults(outputFile)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse nuclei results: %w", err)
	}

	ns.logger.Success("Nuclei scanning completed", "findings", len(findings), "critical", ns.countCriticalFindings(findings))
	return findings, outputFindings, nil
}

// buildNucleiArgs constructs the command line arguments for Nuclei
func (ns *NucleiScanner) buildNucleiArgs(inputFile, outputFile string, options NucleiOptions) []string {
	args := []string{
		"-list", inputFile,
		"-json",
		"-output", outputFile,
		"-silent",
		"-no-color",
		"-no-update-templates",
	}

	// Add templates
	if options.Templates != "" {
		args = append(args, "-templates", options.Templates)
	} else if len(ns.config.Tools.Nuclei.Templates) > 0 {
		args = append(args, "-templates", strings.Join(ns.config.Tools.Nuclei.Templates, ","))
	}

	// Add severity filter
	severities := options.Severity
	if len(severities) == 0 {
		severities = ns.config.Tools.Nuclei.Severity
	}
	if len(severities) > 0 {
		args = append(args, "-severity", strings.Join(severities, ","))
	}

	// Add tags
	tags := options.Tags
	if len(tags) == 0 {
		tags = ns.config.Tools.Nuclei.Tags
	}
	if len(tags) > 0 {
		args = append(args, "-tags", strings.Join(tags, ","))
	}

	// Add exclude tags
	if len(ns.config.Tools.Nuclei.ExcludeTags) > 0 {
		args = append(args, "-exclude-tags", strings.Join(ns.config.Tools.Nuclei.ExcludeTags, ","))
	}

	// Add rate limiting
	if ns.config.Tools.Nuclei.RateLimit > 0 {
		args = append(args, "-rate-limit", strconv.Itoa(ns.config.Tools.Nuclei.RateLimit))
	}

	// Add bulk size
	if ns.config.Tools.Nuclei.BulkSize > 0 {
		args = append(args, "-bulk-size", strconv.Itoa(ns.config.Tools.Nuclei.BulkSize))
	}

	// Add timeout
	if ns.config.Tools.Nuclei.Timeout > 0 {
		args = append(args, "-timeout", strconv.Itoa(ns.config.Tools.Nuclei.Timeout))
	}

	// Add max host errors
	if ns.config.Tools.Nuclei.MaxHostError > 0 {
		args = append(args, "-max-host-error", strconv.Itoa(ns.config.Tools.Nuclei.MaxHostError))
	}

	// Add custom headers
	if len(ns.config.Headers) > 0 {
		for key, value := range ns.config.Headers {
			args = append(args, "-header", fmt.Sprintf("%s: %s", key, value))
		}
	}

	// Additional useful flags
	args = append(args,
		"-include-rr",         // Include request/response in output
		"-stats",              // Display stats
		"-metrics",            // Display metrics
		"-disable-redirects",  // Disable redirects
		"-follow-redirects",   // Follow redirects when needed
		"-max-redirects", "3", // Max redirects
	)

	return args
}

// parseNucleiResults parses the JSON output from Nuclei
func (ns *NucleiScanner) parseNucleiResults(outputFile string) ([]Finding, []output.Finding, error) {
	// Check if output file exists
	if _, err := os.Stat(outputFile); os.IsNotExist(err) {
		ns.logger.Warn("Nuclei output file not found, no vulnerabilities detected")
		return []Finding{}, []output.Finding{}, nil
	}

	content, err := os.ReadFile(outputFile)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read nuclei output: %w", err)
	}

	var findings []Finding
	var outputFindings []output.Finding

	// Parse each line as JSON
	lines := strings.Split(string(content), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		var result NucleiResult
		if err := json.Unmarshal([]byte(line), &result); err != nil {
			ns.logger.Debug("Failed to parse nuclei result line", "line", line, "error", err)
			continue
		}

		// Create Finding
		finding := Finding{
			URL:         result.MatchedAt,
			Template:    result.TemplateID,
			Severity:    result.Info.Severity,
			Description: result.Info.Description,
			Metadata: map[string]string{
				"tool":        "nuclei",
				"template_id": result.TemplateID,
				"type":        result.Type,
				"host":        result.Host,
				"ip":          result.IP,
			},
		}

		// Add additional metadata
		if len(result.Info.Tags) > 0 {
			finding.Metadata["tags"] = strings.Join(result.Info.Tags, ",")
		}
		if len(result.Info.Author) > 0 {
			finding.Metadata["author"] = strings.Join(result.Info.Author, ",")
		}
		if result.Info.Classification.CVSSScore > 0 {
			finding.Metadata["cvss_score"] = fmt.Sprintf("%.1f", result.Info.Classification.CVSSScore)
		}

		findings = append(findings, finding)

		// Create output Finding
		outputFinding := output.Finding{
			Timestamp:   result.Timestamp,
			Stage:       "nuclei",
			Type:        "vulnerability",
			Target:      result.Host,
			Value:       result.MatchedAt,
			Severity:    result.Info.Severity,
			Description: ns.buildDescription(result),
			Metadata:    ns.buildMetadata(result),
		}

		outputFindings = append(outputFindings, outputFinding)

		// Log critical findings
		if strings.ToLower(result.Info.Severity) == "critical" {
			ns.logger.Critical("Critical vulnerability found",
				"template", result.TemplateID,
				"target", result.MatchedAt,
				"description", result.Info.Description)
		}
	}

	return findings, outputFindings, nil
}

// buildDescription creates a human-readable description
func (ns *NucleiScanner) buildDescription(result NucleiResult) string {
	parts := []string{
		fmt.Sprintf("Template: %s", result.TemplateID),
		fmt.Sprintf("Severity: %s", result.Info.Severity),
	}

	if result.Info.Description != "" {
		parts = append(parts, fmt.Sprintf("Description: %s", result.Info.Description))
	}

	if len(result.Info.Tags) > 0 {
		parts = append(parts, fmt.Sprintf("Tags: %s", strings.Join(result.Info.Tags, ", ")))
	}

	return strings.Join(parts, " | ")
}

// buildMetadata creates metadata map for the finding
func (ns *NucleiScanner) buildMetadata(result NucleiResult) map[string]string {
	metadata := map[string]string{
		"tool":          "nuclei",
		"template_id":   result.TemplateID,
		"template_path": result.TemplatePath,
		"type":          result.Type,
		"host":          result.Host,
		"matched_at":    result.MatchedAt,
	}

	if result.IP != "" {
		metadata["ip"] = result.IP
	}

	if result.Info.Name != "" {
		metadata["template_name"] = result.Info.Name
	}

	if len(result.Info.Tags) > 0 {
		metadata["tags"] = strings.Join(result.Info.Tags, ",")
	}

	if len(result.Info.Author) > 0 {
		metadata["author"] = strings.Join(result.Info.Author, ",")
	}

	if result.Info.Classification.CVSSScore > 0 {
		metadata["cvss_score"] = fmt.Sprintf("%.1f", result.Info.Classification.CVSSScore)
		metadata["cvss_metrics"] = result.Info.Classification.CVSSMetrics
	}

	if len(result.Info.Reference) > 0 {
		metadata["references"] = strings.Join(result.Info.Reference, ",")
	}

	return metadata
}

// countCriticalFindings counts the number of critical findings
func (ns *NucleiScanner) countCriticalFindings(findings []Finding) int {
	count := 0
	for _, finding := range findings {
		if strings.ToLower(finding.Severity) == "critical" {
			count++
		}
	}
	return count
}

// ScanWithCustomTemplates scans with custom template directories
func (ns *NucleiScanner) ScanWithCustomTemplates(ctx context.Context, targets []string, templateDirs []string) ([]Finding, []output.Finding, error) {
	options := NucleiOptions{
		Templates: strings.Join(templateDirs, ","),
		Severity:  ns.config.Tools.Nuclei.Severity,
		Tags:      ns.config.Tools.Nuclei.Tags,
	}

	return ns.ScanTargets(ctx, targets, options)
}

// ScanForSpecificVulnerabilities scans for specific vulnerability types
func (ns *NucleiScanner) ScanForSpecificVulnerabilities(ctx context.Context, targets []string, vulnTypes []string) ([]Finding, []output.Finding, error) {
	options := NucleiOptions{
		Templates: ns.config.Tools.Nuclei.Templates[0], // Use first template directory
		Tags:      vulnTypes,
		Severity:  []string{"critical", "high", "medium"},
	}

	return ns.ScanTargets(ctx, targets, options)
}

// UpdateTemplates updates Nuclei templates
func (ns *NucleiScanner) UpdateTemplates(ctx context.Context) error {
	if !ns.executor.CheckTool("nuclei") {
		return fmt.Errorf("nuclei not found in PATH")
	}

	ns.logger.Progress("Updating Nuclei templates")

	args := []string{"-update-templates", "-silent"}
	result, err := ns.executor.Execute(ctx, "nuclei", args...)
	if err != nil {
		return fmt.Errorf("template update failed: %w", err)
	}

	if !result.Successful {
		return fmt.Errorf("template update failed: %s", result.Error)
	}

	ns.logger.Success("Nuclei templates updated successfully")
	return nil
}

// GetTemplateStats returns statistics about available templates
func (ns *NucleiScanner) GetTemplateStats(ctx context.Context) (map[string]int, error) {
	if !ns.executor.CheckTool("nuclei") {
		return nil, fmt.Errorf("nuclei not found in PATH")
	}

	args := []string{"-templates", ".", "-list", "-silent"}
	result, err := ns.executor.Execute(ctx, "nuclei", args...)
	if err != nil {
		return nil, fmt.Errorf("failed to get template stats: %w", err)
	}

	stats := make(map[string]int)
	stats["total"] = len(result.Output)

	// Count by severity (this is a simplified approach)
	for _, line := range result.Output {
		if strings.Contains(strings.ToLower(line), "critical") {
			stats["critical"]++
		} else if strings.Contains(strings.ToLower(line), "high") {
			stats["high"]++
		} else if strings.Contains(strings.ToLower(line), "medium") {
			stats["medium"]++
		} else if strings.Contains(strings.ToLower(line), "low") {
			stats["low"]++
		}
	}

	return stats, nil
}

// ValidateTemplates validates that template directories exist and are accessible
func (ns *NucleiScanner) ValidateTemplates() error {
	for _, templateDir := range ns.config.Tools.Nuclei.Templates {
		if _, err := os.Stat(templateDir); os.IsNotExist(err) {
			return fmt.Errorf("template directory does not exist: %s", templateDir)
		}
	}
	return nil
}

// GetAvailableTools returns a list of available vulnerability scanning tools
func (ns *NucleiScanner) GetAvailableTools() []string {
	var tools []string

	if ns.executor.CheckTool("nuclei") {
		tools = append(tools, "nuclei")
	}

	return tools
}

// GetSeverityStats returns statistics about findings by severity
func (ns *NucleiScanner) GetSeverityStats(findings []Finding) map[string]int {
	stats := make(map[string]int)

	for _, finding := range findings {
		severity := strings.ToLower(finding.Severity)
		stats[severity]++
	}

	stats["total"] = len(findings)
	return stats
}
