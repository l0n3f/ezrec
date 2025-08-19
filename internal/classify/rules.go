package classify

import (
	"net/url"
	"regexp"
	"strings"
)

// EndpointType represents the type of endpoint
type EndpointType string

const (
	EndpointLogin   EndpointType = "login"
	EndpointAdmin   EndpointType = "admin"
	EndpointAPI     EndpointType = "api"
	EndpointPayment EndpointType = "payment"
	EndpointUpload  EndpointType = "upload"
	EndpointAuth    EndpointType = "auth"
	EndpointConfig  EndpointType = "config"
	EndpointDebug   EndpointType = "debug"
	EndpointBackup  EndpointType = "backup"
	EndpointTest    EndpointType = "test"
	EndpointDev     EndpointType = "dev"
	EndpointStaging EndpointType = "staging"
	EndpointGeneric EndpointType = "generic"
)

// ClassificationRule defines a rule for classifying endpoints
type ClassificationRule struct {
	Type        EndpointType
	Patterns    []*regexp.Regexp
	Keywords    []string
	Priority    int
	Description string
}

// Classifier classifies endpoints into high-value targets
type Classifier struct {
	rules []ClassificationRule
}

// Classification represents the result of endpoint classification
type Classification struct {
	URL         string
	Type        EndpointType
	Priority    int
	Confidence  float64
	Description string
	Matches     []string
}

// NewClassifier creates a new endpoint classifier
func NewClassifier() *Classifier {
	return &Classifier{
		rules: getDefaultRules(),
	}
}

// ClassifyURL classifies a single URL
func (c *Classifier) ClassifyURL(urlStr string) *Classification {
	parsed, err := url.Parse(urlStr)
	if err != nil {
		return &Classification{
			URL:  urlStr,
			Type: EndpointGeneric,
		}
	}

	path := strings.ToLower(parsed.Path)
	query := strings.ToLower(parsed.RawQuery)
	host := strings.ToLower(parsed.Host)
	fullURL := strings.ToLower(urlStr)

	var bestMatch *Classification
	highestScore := 0.0

	for _, rule := range c.rules {
		score, matches := c.scoreRule(rule, fullURL, host, path, query)
		if score > highestScore {
			highestScore = score
			bestMatch = &Classification{
				URL:         urlStr,
				Type:        rule.Type,
				Priority:    rule.Priority,
				Confidence:  score,
				Description: rule.Description,
				Matches:     matches,
			}
		}
	}

	if bestMatch == nil {
		return &Classification{
			URL:  urlStr,
			Type: EndpointGeneric,
		}
	}

	return bestMatch
}

// ClassifyURLs classifies multiple URLs and returns high-value targets
func (c *Classifier) ClassifyURLs(urls []string) []*Classification {
	var classifications []*Classification

	for _, urlStr := range urls {
		classification := c.ClassifyURL(urlStr)
		if classification.Priority > 0 || classification.Confidence > 0.5 {
			classifications = append(classifications, classification)
		}
	}

	return classifications
}

// GetHighValueTargets returns only high-priority classifications
func (c *Classifier) GetHighValueTargets(urls []string) []*Classification {
	classifications := c.ClassifyURLs(urls)
	var hvt []*Classification

	for _, classification := range classifications {
		if classification.Priority >= 8 || classification.Type == EndpointLogin ||
			classification.Type == EndpointAdmin || classification.Type == EndpointAPI ||
			classification.Type == EndpointPayment {
			hvt = append(hvt, classification)
		}
	}

	return hvt
}

// scoreRule calculates the score for a rule against a URL
func (c *Classifier) scoreRule(rule ClassificationRule, fullURL, host, path, query string) (float64, []string) {
	var score float64
	var matches []string

	// Check regex patterns
	for _, pattern := range rule.Patterns {
		if pattern.MatchString(fullURL) {
			score += 0.8
			matches = append(matches, "pattern:"+pattern.String())
		}
		if pattern.MatchString(path) {
			score += 0.7
			matches = append(matches, "path:"+pattern.String())
		}
		if pattern.MatchString(host) {
			score += 0.6
			matches = append(matches, "host:"+pattern.String())
		}
	}

	// Check keywords
	for _, keyword := range rule.Keywords {
		keyword = strings.ToLower(keyword)
		if strings.Contains(fullURL, keyword) {
			score += 0.5
			matches = append(matches, "keyword:"+keyword)
		}
		if strings.Contains(path, keyword) {
			score += 0.4
			matches = append(matches, "path-keyword:"+keyword)
		}
		if strings.Contains(query, keyword) {
			score += 0.3
			matches = append(matches, "query-keyword:"+keyword)
		}
	}

	return score, matches
}

// getDefaultRules returns the default classification rules
func getDefaultRules() []ClassificationRule {
	return []ClassificationRule{
		{
			Type:        EndpointLogin,
			Priority:    10,
			Description: "Authentication and login endpoints",
			Patterns: []*regexp.Regexp{
				regexp.MustCompile(`(?i)/login`),
				regexp.MustCompile(`(?i)/signin`),
				regexp.MustCompile(`(?i)/auth/login`),
				regexp.MustCompile(`(?i)/authenticate`),
				regexp.MustCompile(`(?i)/user/login`),
				regexp.MustCompile(`(?i)/account/login`),
			},
			Keywords: []string{
				"login", "signin", "authenticate", "auth", "logon",
				"password", "username", "credential",
			},
		},
		{
			Type:        EndpointAdmin,
			Priority:    10,
			Description: "Administrative interfaces and panels",
			Patterns: []*regexp.Regexp{
				regexp.MustCompile(`(?i)/admin`),
				regexp.MustCompile(`(?i)/administrator`),
				regexp.MustCompile(`(?i)/wp-admin`),
				regexp.MustCompile(`(?i)/cpanel`),
				regexp.MustCompile(`(?i)/control`),
				regexp.MustCompile(`(?i)/dashboard`),
				regexp.MustCompile(`(?i)/manage`),
			},
			Keywords: []string{
				"admin", "administrator", "dashboard", "control", "manage",
				"panel", "backend", "console",
			},
		},
		{
			Type:        EndpointAPI,
			Priority:    9,
			Description: "API endpoints and web services",
			Patterns: []*regexp.Regexp{
				regexp.MustCompile(`(?i)/api/`),
				regexp.MustCompile(`(?i)/v\d+/`),
				regexp.MustCompile(`(?i)/rest/`),
				regexp.MustCompile(`(?i)/graphql`),
				regexp.MustCompile(`(?i)/ws/`),
				regexp.MustCompile(`(?i)/service/`),
			},
			Keywords: []string{
				"api", "rest", "graphql", "json", "xml", "soap",
				"webservice", "endpoint", "v1", "v2", "v3",
			},
		},
		{
			Type:        EndpointPayment,
			Priority:    10,
			Description: "Payment and financial endpoints",
			Patterns: []*regexp.Regexp{
				regexp.MustCompile(`(?i)/payment`),
				regexp.MustCompile(`(?i)/checkout`),
				regexp.MustCompile(`(?i)/billing`),
				regexp.MustCompile(`(?i)/invoice`),
				regexp.MustCompile(`(?i)/cart`),
				regexp.MustCompile(`(?i)/order`),
			},
			Keywords: []string{
				"payment", "checkout", "billing", "invoice", "cart",
				"order", "purchase", "transaction", "paypal", "stripe",
			},
		},
		{
			Type:        EndpointUpload,
			Priority:    8,
			Description: "File upload endpoints",
			Patterns: []*regexp.Regexp{
				regexp.MustCompile(`(?i)/upload`),
				regexp.MustCompile(`(?i)/file`),
				regexp.MustCompile(`(?i)/attach`),
				regexp.MustCompile(`(?i)/media`),
			},
			Keywords: []string{
				"upload", "file", "attach", "media", "document",
				"image", "photo", "avatar",
			},
		},
		{
			Type:        EndpointAuth,
			Priority:    9,
			Description: "Authentication and authorization endpoints",
			Patterns: []*regexp.Regexp{
				regexp.MustCompile(`(?i)/oauth`),
				regexp.MustCompile(`(?i)/sso`),
				regexp.MustCompile(`(?i)/saml`),
				regexp.MustCompile(`(?i)/jwt`),
				regexp.MustCompile(`(?i)/token`),
				regexp.MustCompile(`(?i)/refresh`),
			},
			Keywords: []string{
				"oauth", "sso", "saml", "jwt", "token", "refresh",
				"authorize", "callback", "redirect",
			},
		},
		{
			Type:        EndpointConfig,
			Priority:    7,
			Description: "Configuration and settings endpoints",
			Patterns: []*regexp.Regexp{
				regexp.MustCompile(`(?i)/config`),
				regexp.MustCompile(`(?i)/settings`),
				regexp.MustCompile(`(?i)/preferences`),
				regexp.MustCompile(`(?i)\.env`),
				regexp.MustCompile(`(?i)\.config`),
			},
			Keywords: []string{
				"config", "configuration", "settings", "preferences",
				"env", "environment", "properties",
			},
		},
		{
			Type:        EndpointDebug,
			Priority:    8,
			Description: "Debug and development endpoints",
			Patterns: []*regexp.Regexp{
				regexp.MustCompile(`(?i)/debug`),
				regexp.MustCompile(`(?i)/trace`),
				regexp.MustCompile(`(?i)/phpinfo`),
				regexp.MustCompile(`(?i)/info`),
				regexp.MustCompile(`(?i)/status`),
				regexp.MustCompile(`(?i)/health`),
			},
			Keywords: []string{
				"debug", "trace", "phpinfo", "info", "status",
				"health", "monitor", "metrics",
			},
		},
		{
			Type:        EndpointBackup,
			Priority:    7,
			Description: "Backup and archive files",
			Patterns: []*regexp.Regexp{
				regexp.MustCompile(`(?i)\.bak$`),
				regexp.MustCompile(`(?i)\.backup$`),
				regexp.MustCompile(`(?i)\.old$`),
				regexp.MustCompile(`(?i)\.orig$`),
				regexp.MustCompile(`(?i)\.zip$`),
				regexp.MustCompile(`(?i)\.tar`),
			},
			Keywords: []string{
				"backup", "bak", "old", "orig", "archive",
				"dump", "export", "snapshot",
			},
		},
		{
			Type:        EndpointTest,
			Priority:    5,
			Description: "Test and development endpoints",
			Patterns: []*regexp.Regexp{
				regexp.MustCompile(`(?i)/test`),
				regexp.MustCompile(`(?i)/demo`),
				regexp.MustCompile(`(?i)/example`),
				regexp.MustCompile(`(?i)/sample`),
			},
			Keywords: []string{
				"test", "testing", "demo", "example", "sample",
				"prototype", "poc",
			},
		},
		{
			Type:        EndpointDev,
			Priority:    6,
			Description: "Development environment endpoints",
			Patterns: []*regexp.Regexp{
				regexp.MustCompile(`(?i)dev\.`),
				regexp.MustCompile(`(?i)/dev`),
				regexp.MustCompile(`(?i)development`),
			},
			Keywords: []string{
				"dev", "development", "developer",
			},
		},
		{
			Type:        EndpointStaging,
			Priority:    4,
			Description: "Staging environment endpoints",
			Patterns: []*regexp.Regexp{
				regexp.MustCompile(`(?i)staging\.`),
				regexp.MustCompile(`(?i)stage\.`),
				regexp.MustCompile(`(?i)/staging`),
			},
			Keywords: []string{
				"staging", "stage", "pre-prod", "preprod",
			},
		},
	}
}

// AddCustomRule adds a custom classification rule
func (c *Classifier) AddCustomRule(rule ClassificationRule) {
	c.rules = append(c.rules, rule)
}

// GetRulesByType returns all rules of a specific type
func (c *Classifier) GetRulesByType(endpointType EndpointType) []ClassificationRule {
	var rules []ClassificationRule
	for _, rule := range c.rules {
		if rule.Type == endpointType {
			rules = append(rules, rule)
		}
	}
	return rules
}

// GetStats returns classification statistics
func (c *Classifier) GetStats(classifications []*Classification) map[EndpointType]int {
	stats := make(map[EndpointType]int)
	for _, classification := range classifications {
		stats[classification.Type]++
	}
	return stats
}
