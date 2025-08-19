package scope

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

// Matcher provides scope-based filtering using regex patterns
type Matcher struct {
	includePatterns []*regexp.Regexp
	excludePatterns []*regexp.Regexp
}

// NewMatcher creates a new scope matcher
func NewMatcher(includeRules, excludeRules []string) (*Matcher, error) {
	var includePatterns []*regexp.Regexp
	var excludePatterns []*regexp.Regexp

	// Compile include patterns
	for _, rule := range includeRules {
		if rule == "" {
			continue
		}
		pattern, err := regexp.Compile(rule)
		if err != nil {
			return nil, fmt.Errorf("invalid include pattern '%s': %w", rule, err)
		}
		includePatterns = append(includePatterns, pattern)
	}

	// Compile exclude patterns
	for _, rule := range excludeRules {
		if rule == "" {
			continue
		}
		pattern, err := regexp.Compile(rule)
		if err != nil {
			return nil, fmt.Errorf("invalid exclude pattern '%s': %w", rule, err)
		}
		excludePatterns = append(excludePatterns, pattern)
	}

	// If no include patterns, add catch-all
	if len(includePatterns) == 0 {
		catchAll, _ := regexp.Compile(".*")
		includePatterns = append(includePatterns, catchAll)
	}

	return &Matcher{
		includePatterns: includePatterns,
		excludePatterns: excludePatterns,
	}, nil
}

// IsInScope checks if a target is within scope
func (m *Matcher) IsInScope(target string) bool {
	// Normalize target
	normalized := m.normalizeTarget(target)

	// Check exclude patterns first
	for _, pattern := range m.excludePatterns {
		if pattern.MatchString(normalized) {
			return false
		}
	}

	// Check include patterns
	for _, pattern := range m.includePatterns {
		if pattern.MatchString(normalized) {
			return true
		}
	}

	return false
}

// FilterTargets filters a list of targets based on scope rules
func (m *Matcher) FilterTargets(targets []string) []string {
	var filtered []string
	for _, target := range targets {
		if m.IsInScope(target) {
			filtered = append(filtered, target)
		}
	}
	return filtered
}

// FilterURLs filters a list of URLs based on scope rules
func (m *Matcher) FilterURLs(urls []string) []string {
	var filtered []string
	for _, urlStr := range urls {
		if m.IsURLInScope(urlStr) {
			filtered = append(filtered, urlStr)
		}
	}
	return filtered
}

// IsURLInScope checks if a URL is within scope
func (m *Matcher) IsURLInScope(urlStr string) bool {
	// Parse URL to extract host
	parsed, err := url.Parse(urlStr)
	if err != nil {
		// If URL parsing fails, check the raw string
		return m.IsInScope(urlStr)
	}

	// Check both the full URL and just the host
	return m.IsInScope(urlStr) || m.IsInScope(parsed.Host)
}

// normalizeTarget normalizes a target for consistent matching
func (m *Matcher) normalizeTarget(target string) string {
	// Remove protocol if present
	if strings.HasPrefix(target, "http://") {
		target = strings.TrimPrefix(target, "http://")
	} else if strings.HasPrefix(target, "https://") {
		target = strings.TrimPrefix(target, "https://")
	}

	// Remove trailing slash
	target = strings.TrimSuffix(target, "/")

	// Convert to lowercase for case-insensitive matching
	return strings.ToLower(target)
}

// Stats returns statistics about the scope matcher
func (m *Matcher) Stats() map[string]interface{} {
	return map[string]interface{}{
		"include_patterns": len(m.includePatterns),
		"exclude_patterns": len(m.excludePatterns),
	}
}

// GetIncludePatterns returns the include patterns as strings
func (m *Matcher) GetIncludePatterns() []string {
	var patterns []string
	for _, pattern := range m.includePatterns {
		patterns = append(patterns, pattern.String())
	}
	return patterns
}

// GetExcludePatterns returns the exclude patterns as strings
func (m *Matcher) GetExcludePatterns() []string {
	var patterns []string
	for _, pattern := range m.excludePatterns {
		patterns = append(patterns, pattern.String())
	}
	return patterns
}

// DomainMatcher provides domain-specific matching utilities
type DomainMatcher struct {
	*Matcher
	rootDomains []string
}

// NewDomainMatcher creates a domain-specific matcher
func NewDomainMatcher(rootDomains []string, includeRules, excludeRules []string) (*DomainMatcher, error) {
	matcher, err := NewMatcher(includeRules, excludeRules)
	if err != nil {
		return nil, err
	}

	return &DomainMatcher{
		Matcher:     matcher,
		rootDomains: rootDomains,
	}, nil
}

// IsSubdomain checks if a domain is a subdomain of any root domain
func (dm *DomainMatcher) IsSubdomain(domain string) bool {
	domain = strings.ToLower(domain)

	for _, root := range dm.rootDomains {
		root = strings.ToLower(root)

		// Exact match
		if domain == root {
			return true
		}

		// Subdomain match
		if strings.HasSuffix(domain, "."+root) {
			return true
		}
	}

	return false
}

// FilterSubdomains filters domains to only include subdomains of root domains
func (dm *DomainMatcher) FilterSubdomains(domains []string) []string {
	var filtered []string
	for _, domain := range domains {
		if dm.IsSubdomain(domain) && dm.IsInScope(domain) {
			filtered = append(filtered, domain)
		}
	}
	return filtered
}
