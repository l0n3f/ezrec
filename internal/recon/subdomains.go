package recon

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ezrec/ezrec/internal/config"
	"github.com/ezrec/ezrec/internal/log"
	"github.com/ezrec/ezrec/internal/output"
	"github.com/ezrec/ezrec/internal/runner"
	"github.com/ezrec/ezrec/internal/util"
)

// SubdomainEnumerator handles subdomain enumeration using multiple tools
type SubdomainEnumerator struct {
	config   *config.Config
	executor *runner.Executor
	logger   *log.Logger
}

// NewSubdomainEnumerator creates a new subdomain enumerator
func NewSubdomainEnumerator(cfg *config.Config, logger *log.Logger) *SubdomainEnumerator {
	return &SubdomainEnumerator{
		config:   cfg,
		executor: runner.NewExecutor(logger),
		logger:   logger,
	}
}

// EnumerateSubdomains performs comprehensive subdomain enumeration
func (se *SubdomainEnumerator) EnumerateSubdomains(ctx context.Context, domains []string) ([]string, []output.Finding, error) {
	se.logger.Progress("Starting subdomain enumeration", "domains", len(domains))

	var allSubdomains []string
	var findings []output.Finding

	// Run subfinder
	if se.executor.CheckTool("subfinder") {
		se.logger.Info("Running subfinder")
		subfinderResults, subfinderFindings, err := se.runSubfinder(ctx, domains)
		if err != nil {
			se.logger.Warn("Subfinder failed", "error", err)
		} else {
			allSubdomains = append(allSubdomains, subfinderResults...)
			findings = append(findings, subfinderFindings...)
			se.logger.Success("Subfinder completed", "subdomains", len(subfinderResults))
		}
	} else {
		se.logger.Warn("Subfinder not found in PATH, skipping")
	}

	// Run amass
	if se.executor.CheckTool("amass") {
		se.logger.Info("Running amass")
		amassResults, amassFindings, err := se.runAmass(ctx, domains)
		if err != nil {
			se.logger.Warn("Amass failed", "error", err)
		} else {
			allSubdomains = append(allSubdomains, amassResults...)
			findings = append(findings, amassFindings...)
			se.logger.Success("Amass completed", "subdomains", len(amassResults))
		}
	} else {
		se.logger.Warn("Amass not found in PATH, skipping")
	}

	// Deduplicate results
	allSubdomains = util.DeduplicateStrings(allSubdomains)

	se.logger.Success("Subdomain enumeration completed", "total_subdomains", len(allSubdomains))
	return allSubdomains, findings, nil
}

// runSubfinder executes subfinder for subdomain enumeration
func (se *SubdomainEnumerator) runSubfinder(ctx context.Context, domains []string) ([]string, []output.Finding, error) {
	args := []string{"-silent"}

	// Add configuration options
	if len(se.config.Tools.Subfinder.Sources) > 0 && se.config.Tools.Subfinder.Sources[0] != "all" {
		args = append(args, "-sources", strings.Join(se.config.Tools.Subfinder.Sources, ","))
	}

	if se.config.Tools.Subfinder.MaxDepth > 0 {
		args = append(args, "-max-time", fmt.Sprintf("%d", se.config.Tools.Subfinder.Timeout))
	}

	if se.config.Tools.Subfinder.Threads > 0 {
		args = append(args, "-t", fmt.Sprintf("%d", se.config.Tools.Subfinder.Threads))
	}

	var allSubdomains []string
	var findings []output.Finding

	for _, domain := range domains {
		se.logger.Debug("Running subfinder for domain", "domain", domain)

		domainArgs := append(args, "-d", domain)
		result, err := se.executor.Execute(ctx, "subfinder", domainArgs...)
		if err != nil {
			return nil, nil, fmt.Errorf("subfinder execution failed: %w", err)
		}

		if !result.Successful {
			se.logger.Warn("Subfinder failed for domain", "domain", domain, "error", result.Error)
			continue
		}

		// Process results
		for _, subdomain := range result.Output {
			subdomain = strings.TrimSpace(subdomain)
			if subdomain != "" && util.IsValidURL("https://"+subdomain) {
				allSubdomains = append(allSubdomains, subdomain)

				findings = append(findings, output.Finding{
					Timestamp: time.Now(),
					Stage:     "subdomains",
					Type:      "subdomain",
					Target:    domain,
					Value:     subdomain,
					Metadata: map[string]string{
						"tool":   "subfinder",
						"source": "passive",
					},
				})
			}
		}

		se.logger.Debug("Subfinder completed for domain", "domain", domain, "subdomains", len(result.Output))
	}

	return allSubdomains, findings, nil
}

// runAmass executes amass for subdomain enumeration
func (se *SubdomainEnumerator) runAmass(ctx context.Context, domains []string) ([]string, []output.Finding, error) {
	args := []string{"enum", "-passive", "-silent"}

	// Add configuration options
	if se.config.Tools.Amass.MaxDNSQueries > 0 {
		args = append(args, "-max-dns-queries", fmt.Sprintf("%d", se.config.Tools.Amass.MaxDNSQueries))
	}

	// Create output directory for amass
	tempDir := filepath.Join(os.TempDir(), "ezrec-amass-"+util.GenerateTimestamp())
	if err := os.MkdirAll(tempDir, 0755); err != nil {
		return nil, nil, fmt.Errorf("failed to create temp directory: %w", err)
	}
	defer os.RemoveAll(tempDir)

	outputFile := filepath.Join(tempDir, "amass-output.txt")
	args = append(args, "-o", outputFile)

	var allSubdomains []string
	var findings []output.Finding

	for _, domain := range domains {
		se.logger.Debug("Running amass for domain", "domain", domain)

		domainArgs := append(args, "-d", domain)
		result, err := se.executor.Execute(ctx, "amass", domainArgs...)
		if err != nil {
			return nil, nil, fmt.Errorf("amass execution failed: %w", err)
		}

		if !result.Successful {
			se.logger.Warn("Amass failed for domain", "domain", domain, "error", result.Error)
			continue
		}

		// Read output file
		if _, err := os.Stat(outputFile); err == nil {
			content, err := os.ReadFile(outputFile)
			if err != nil {
				se.logger.Warn("Failed to read amass output", "error", err)
				continue
			}

			lines := strings.Split(string(content), "\n")
			for _, line := range lines {
				subdomain := strings.TrimSpace(line)
				if subdomain != "" && util.IsValidURL("https://"+subdomain) {
					allSubdomains = append(allSubdomains, subdomain)

					findings = append(findings, output.Finding{
						Timestamp: time.Now(),
						Stage:     "subdomains",
						Type:      "subdomain",
						Target:    domain,
						Value:     subdomain,
						Metadata: map[string]string{
							"tool":   "amass",
							"source": "passive",
						},
					})
				}
			}

			// Clean up output file for next domain
			os.Remove(outputFile)
		}

		se.logger.Debug("Amass completed for domain", "domain", domain)
	}

	return allSubdomains, findings, nil
}

// EnumerateWithDNSBruteforce performs DNS bruteforce enumeration
func (se *SubdomainEnumerator) EnumerateWithDNSBruteforce(ctx context.Context, domains []string, wordlist string) ([]string, []output.Finding, error) {
	if !se.executor.CheckTool("subfinder") {
		return nil, nil, fmt.Errorf("subfinder not available for DNS bruteforce")
	}

	se.logger.Progress("Starting DNS bruteforce enumeration", "domains", len(domains))

	args := []string{"-silent", "-brute"}

	if wordlist != "" {
		args = append(args, "-w", wordlist)
	}

	var allSubdomains []string
	var findings []output.Finding

	for _, domain := range domains {
		se.logger.Debug("Running DNS bruteforce for domain", "domain", domain)

		domainArgs := append(args, "-d", domain)
		result, err := se.executor.Execute(ctx, "subfinder", domainArgs...)
		if err != nil {
			return nil, nil, fmt.Errorf("DNS bruteforce failed: %w", err)
		}

		if !result.Successful {
			se.logger.Warn("DNS bruteforce failed for domain", "domain", domain, "error", result.Error)
			continue
		}

		// Process results
		for _, subdomain := range result.Output {
			subdomain = strings.TrimSpace(subdomain)
			if subdomain != "" && util.IsValidURL("https://"+subdomain) {
				allSubdomains = append(allSubdomains, subdomain)

				findings = append(findings, output.Finding{
					Timestamp: time.Now(),
					Stage:     "subdomains",
					Type:      "subdomain",
					Target:    domain,
					Value:     subdomain,
					Metadata: map[string]string{
						"tool":   "subfinder",
						"source": "bruteforce",
					},
				})
			}
		}
	}

	allSubdomains = util.DeduplicateStrings(allSubdomains)
	se.logger.Success("DNS bruteforce completed", "subdomains", len(allSubdomains))

	return allSubdomains, findings, nil
}

// EnumerateFromCertificates performs certificate transparency enumeration
func (se *SubdomainEnumerator) EnumerateFromCertificates(ctx context.Context, domains []string) ([]string, []output.Finding, error) {
	if !se.executor.CheckTool("subfinder") {
		return nil, nil, fmt.Errorf("subfinder not available for certificate enumeration")
	}

	se.logger.Progress("Starting certificate transparency enumeration", "domains", len(domains))

	args := []string{"-silent", "-sources", "certspotter,crtsh,censys"}

	var allSubdomains []string
	var findings []output.Finding

	for _, domain := range domains {
		se.logger.Debug("Running certificate enumeration for domain", "domain", domain)

		domainArgs := append(args, "-d", domain)
		result, err := se.executor.Execute(ctx, "subfinder", domainArgs...)
		if err != nil {
			return nil, nil, fmt.Errorf("certificate enumeration failed: %w", err)
		}

		if !result.Successful {
			se.logger.Warn("Certificate enumeration failed for domain", "domain", domain, "error", result.Error)
			continue
		}

		// Process results
		for _, subdomain := range result.Output {
			subdomain = strings.TrimSpace(subdomain)
			if subdomain != "" && util.IsValidURL("https://"+subdomain) {
				allSubdomains = append(allSubdomains, subdomain)

				findings = append(findings, output.Finding{
					Timestamp: time.Now(),
					Stage:     "subdomains",
					Type:      "subdomain",
					Target:    domain,
					Value:     subdomain,
					Metadata: map[string]string{
						"tool":   "subfinder",
						"source": "certificates",
					},
				})
			}
		}
	}

	allSubdomains = util.DeduplicateStrings(allSubdomains)
	se.logger.Success("Certificate enumeration completed", "subdomains", len(allSubdomains))

	return allSubdomains, findings, nil
}

// GetAvailableTools returns a list of available subdomain enumeration tools
func (se *SubdomainEnumerator) GetAvailableTools() []string {
	var tools []string

	if se.executor.CheckTool("subfinder") {
		tools = append(tools, "subfinder")
	}

	if se.executor.CheckTool("amass") {
		tools = append(tools, "amass")
	}

	return tools
}

// ValidateSubdomains validates that subdomains are properly formatted
func (se *SubdomainEnumerator) ValidateSubdomains(subdomains []string) []string {
	var valid []string

	for _, subdomain := range subdomains {
		subdomain = strings.TrimSpace(subdomain)

		// Basic validation
		if subdomain == "" {
			continue
		}

		// Remove protocol if present
		if strings.HasPrefix(subdomain, "http://") {
			subdomain = strings.TrimPrefix(subdomain, "http://")
		} else if strings.HasPrefix(subdomain, "https://") {
			subdomain = strings.TrimPrefix(subdomain, "https://")
		}

		// Remove trailing slash
		subdomain = strings.TrimSuffix(subdomain, "/")

		// Check if it looks like a valid domain
		if strings.Contains(subdomain, ".") && !strings.Contains(subdomain, " ") {
			valid = append(valid, subdomain)
		}
	}

	return util.DeduplicateStrings(valid)
}
