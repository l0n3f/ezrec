package output

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Manager handles output operations for different formats
type Manager struct {
	baseDir string
	formats []string
	writers map[string]*StageWriter
}

// StageWriter handles writing for a specific stage
type StageWriter struct {
	stageName string
	baseDir   string
	formats   []string
}

// Finding represents a generic finding/result
type Finding struct {
	Timestamp   time.Time         `json:"timestamp"`
	Stage       string            `json:"stage"`
	Type        string            `json:"type"`
	Target      string            `json:"target"`
	Value       string            `json:"value"`
	Severity    string            `json:"severity,omitempty"`
	Confidence  string            `json:"confidence,omitempty"`
	Description string            `json:"description,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty"`
}

// StageResult represents the result of a reconnaissance stage
type StageResult struct {
	Stage       string                 `json:"stage"`
	Timestamp   time.Time              `json:"timestamp"`
	Duration    time.Duration          `json:"duration"`
	InputCount  int                    `json:"input_count"`
	OutputCount int                    `json:"output_count"`
	Findings    []Finding              `json:"findings"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// NewManager creates a new output manager
func NewManager(baseDir string, formats []string) (*Manager, error) {
	if err := os.MkdirAll(baseDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create output directory: %w", err)
	}

	return &Manager{
		baseDir: baseDir,
		formats: formats,
		writers: make(map[string]*StageWriter),
	}, nil
}

// GetStageWriter returns a writer for a specific stage
func (m *Manager) GetStageWriter(stageName string) *StageWriter {
	if writer, exists := m.writers[stageName]; exists {
		return writer
	}

	writer := &StageWriter{
		stageName: stageName,
		baseDir:   m.baseDir,
		formats:   m.formats,
	}
	m.writers[stageName] = writer
	return writer
}

// WriteStageResult writes a complete stage result
func (sw *StageWriter) WriteStageResult(result *StageResult) error {
	for _, format := range sw.formats {
		switch format {
		case "markdown":
			if err := sw.writeMarkdown(result); err != nil {
				return fmt.Errorf("failed to write markdown: %w", err)
			}
		case "csv":
			if err := sw.writeCSV(result); err != nil {
				return fmt.Errorf("failed to write CSV: %w", err)
			}
		case "ndjson":
			if err := sw.writeNDJSON(result); err != nil {
				return fmt.Errorf("failed to write NDJSON: %w", err)
			}
		}
	}
	return nil
}

// writeMarkdown writes results in Markdown format
func (sw *StageWriter) writeMarkdown(result *StageResult) error {
	filename := fmt.Sprintf("%s.md", result.Stage)
	filepath := filepath.Join(sw.baseDir, filename)

	file, err := os.Create(filepath)
	if err != nil {
		return err
	}
	defer file.Close()

	// Write header
	fmt.Fprintf(file, "# %s Results\n\n", strings.Title(result.Stage))
	fmt.Fprintf(file, "**Timestamp:** %s\n", result.Timestamp.Format("2006-01-02 15:04:05"))
	fmt.Fprintf(file, "**Duration:** %s\n", result.Duration.String())
	fmt.Fprintf(file, "**Input Count:** %d\n", result.InputCount)
	fmt.Fprintf(file, "**Output Count:** %d\n\n", result.OutputCount)

	if len(result.Findings) == 0 {
		fmt.Fprintf(file, "*No results found.*\n")
		return nil
	}

	// Group findings by type
	findingsByType := make(map[string][]Finding)
	for _, finding := range result.Findings {
		findingsByType[finding.Type] = append(findingsByType[finding.Type], finding)
	}

	// Write findings by type
	for findingType, findings := range findingsByType {
		fmt.Fprintf(file, "## %s\n\n", strings.Title(findingType))

		switch result.Stage {
		case "subdomains":
			sw.writeSubdomainMarkdown(file, findings)
		case "httpx":
			sw.writeHttpxMarkdown(file, findings)
		case "crawl", "urls":
			sw.writeURLMarkdown(file, findings)
		case "endpoints":
			sw.writeEndpointMarkdown(file, findings)
		case "xss":
			sw.writeXSSMarkdown(file, findings)
		case "nuclei":
			sw.writeNucleiMarkdown(file, findings)
		case "ffuf":
			sw.writeFfufMarkdown(file, findings)
		default:
			sw.writeGenericMarkdown(file, findings)
		}
		fmt.Fprintf(file, "\n")
	}

	return nil
}

// writeSubdomainMarkdown writes subdomain findings in markdown
func (sw *StageWriter) writeSubdomainMarkdown(file *os.File, findings []Finding) {
	for _, finding := range findings {
		fmt.Fprintf(file, "- %s\n", finding.Value)
		if finding.Description != "" {
			fmt.Fprintf(file, "  - %s\n", finding.Description)
		}
	}
}

// writeHttpxMarkdown writes httpx findings in markdown
func (sw *StageWriter) writeHttpxMarkdown(file *os.File, findings []Finding) {
	fmt.Fprintf(file, "| URL | Status | Title | Tech |\n")
	fmt.Fprintf(file, "|-----|--------|-------|------|\n")

	for _, finding := range findings {
		status := finding.Metadata["status_code"]
		title := finding.Metadata["title"]
		tech := finding.Metadata["tech"]

		fmt.Fprintf(file, "| %s | %s | %s | %s |\n",
			finding.Value, status, title, tech)
	}
}

// writeXSSMarkdown writes XSS findings in markdown
func (sw *StageWriter) writeXSSMarkdown(file *os.File, findings []Finding) {
	fmt.Fprintf(file, "| URL | Method | Parameter | Payload | Result |\n")
	fmt.Fprintf(file, "|-----|--------|-----------|---------|--------|\n")

	for _, finding := range findings {
		method := finding.Metadata["method"]
		param := finding.Metadata["parameter"]
		payload := finding.Metadata["payload"]
		result := "✅ REFLECTED"
		if finding.Severity == "low" {
			result = "⚠️ POSSIBLE"
		}

		fmt.Fprintf(file, "| %s | %s | %s | %s | %s |\n",
			finding.Value, method, param, payload, result)
	}
}

// writeNucleiMarkdown writes Nuclei findings in markdown
func (sw *StageWriter) writeNucleiMarkdown(file *os.File, findings []Finding) {
	fmt.Fprintf(file, "| URL | Template | Severity | Description |\n")
	fmt.Fprintf(file, "|-----|----------|----------|-------------|\n")

	for _, finding := range findings {
		template := finding.Metadata["template"]
		severity := finding.Severity

		// Add emoji based on severity
		severityIcon := ""
		switch strings.ToLower(severity) {
		case "critical":
			severityIcon = "🚨"
		case "high":
			severityIcon = "🔴"
		case "medium":
			severityIcon = "🟡"
		case "low":
			severityIcon = "🟢"
		}

		fmt.Fprintf(file, "| %s | %s | %s %s | %s |\n",
			finding.Value, template, severityIcon, severity, finding.Description)
	}
}

// writeFfufMarkdown writes FFUF findings in markdown
func (sw *StageWriter) writeFfufMarkdown(file *os.File, findings []Finding) {
	fmt.Fprintf(file, "| URL | Status | Size | Words | Lines |\n")
	fmt.Fprintf(file, "|-----|--------|------|-------|-------|\n")

	for _, finding := range findings {
		status := finding.Metadata["status_code"]
		size := finding.Metadata["content_length"]
		words := finding.Metadata["words"]
		lines := finding.Metadata["lines"]

		fmt.Fprintf(file, "| %s | %s | %s | %s | %s |\n",
			finding.Value, status, size, words, lines)
	}
}

// writeGenericMarkdown writes generic findings in markdown
func (sw *StageWriter) writeGenericMarkdown(file *os.File, findings []Finding) {
	for _, finding := range findings {
		fmt.Fprintf(file, "- **%s**", finding.Value)
		if finding.Description != "" {
			fmt.Fprintf(file, " - %s", finding.Description)
		}
		fmt.Fprintf(file, "\n")
	}
}

// writeURLMarkdown writes URL findings in markdown
func (sw *StageWriter) writeURLMarkdown(file *os.File, findings []Finding) {
	for _, finding := range findings {
		fmt.Fprintf(file, "- %s\n", finding.Value)
	}
}

// writeEndpointMarkdown writes endpoint findings in markdown
func (sw *StageWriter) writeEndpointMarkdown(file *os.File, findings []Finding) {
	fmt.Fprintf(file, "| URL | Type | Risk Level |\n")
	fmt.Fprintf(file, "|-----|------|------------|\n")

	for _, finding := range findings {
		endpointType := finding.Type
		risk := "Medium"
		if strings.Contains(strings.ToLower(finding.Value), "admin") ||
			strings.Contains(strings.ToLower(finding.Value), "login") {
			risk = "High"
		}

		fmt.Fprintf(file, "| %s | %s | %s |\n",
			finding.Value, endpointType, risk)
	}
}

// writeCSV writes results in CSV format
func (sw *StageWriter) writeCSV(result *StageResult) error {
	filename := fmt.Sprintf("%s.csv", result.Stage)
	filepath := filepath.Join(sw.baseDir, filename)

	file, err := os.Create(filepath)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	// Write header
	header := []string{"timestamp", "stage", "type", "target", "value", "severity", "confidence", "description"}
	if err := writer.Write(header); err != nil {
		return err
	}

	// Write findings
	for _, finding := range result.Findings {
		record := []string{
			finding.Timestamp.Format(time.RFC3339),
			finding.Stage,
			finding.Type,
			finding.Target,
			finding.Value,
			finding.Severity,
			finding.Confidence,
			finding.Description,
		}
		if err := writer.Write(record); err != nil {
			return err
		}
	}

	return nil
}

// writeNDJSON writes results in NDJSON format
func (sw *StageWriter) writeNDJSON(result *StageResult) error {
	filename := fmt.Sprintf("%s.ndjson", result.Stage)
	filepath := filepath.Join(sw.baseDir, filename)

	file, err := os.Create(filepath)
	if err != nil {
		return err
	}
	defer file.Close()

	encoder := json.NewEncoder(file)

	// Write stage metadata
	if err := encoder.Encode(result); err != nil {
		return err
	}

	// Write individual findings
	for _, finding := range result.Findings {
		if err := encoder.Encode(finding); err != nil {
			return err
		}
	}

	return nil
}

// GenerateFinalReport generates a comprehensive final report
func (m *Manager) GenerateFinalReport(outputPath string) error {
	file, err := os.Create(outputPath)
	if err != nil {
		return err
	}
	defer file.Close()

	// Write report header
	fmt.Fprintf(file, "# ezrec Reconnaissance Report\n\n")
	fmt.Fprintf(file, "**Generated:** %s\n\n", time.Now().Format("2006-01-02 15:04:05"))

	// TODO: Aggregate results from all stages and write summary
	fmt.Fprintf(file, "## Summary\n\n")
	fmt.Fprintf(file, "This report contains the results of the reconnaissance pipeline.\n\n")

	// List generated files
	fmt.Fprintf(file, "## Generated Files\n\n")
	files, err := filepath.Glob(filepath.Join(m.baseDir, "*"))
	if err != nil {
		return err
	}

	for _, filePath := range files {
		filename := filepath.Base(filePath)
		if filename != "README.md" {
			fmt.Fprintf(file, "- [%s](./%s)\n", filename, filename)
		}
	}

	return nil
}

// Note: Stage numbering removed for cleaner file names
