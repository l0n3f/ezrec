package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Provider represents an AI provider
type Provider interface {
	GeneratePayloads(ctx context.Context, target string, context string) ([]string, error)
	AnalyzeVulnerability(ctx context.Context, finding string) (*Analysis, error)
	GenerateWordlist(ctx context.Context, target string, size int) ([]string, error)
}

// Analysis represents AI analysis of a vulnerability
type Analysis struct {
	Severity    string   `json:"severity"`
	Impact      string   `json:"impact"`
	Remediation string   `json:"remediation"`
	References  []string `json:"references"`
}

// Client provides AI-powered suggestions and analysis
type Client struct {
	provider Provider
	enabled  bool
}

// NewClient creates a new AI client
func NewClient(providerType, apiKey, model string) (*Client, error) {
	if apiKey == "" {
		return &Client{enabled: false}, nil
	}

	var provider Provider
	var err error

	switch strings.ToLower(providerType) {
	case "openai":
		provider, err = NewOpenAIProvider(apiKey, model)
	case "anthropic":
		provider, err = NewAnthropicProvider(apiKey, model)
	case "ollama":
		provider, err = NewOllamaProvider(model)
	default:
		return nil, fmt.Errorf("unsupported AI provider: %s", providerType)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to create AI provider: %w", err)
	}

	return &Client{
		provider: provider,
		enabled:  true,
	}, nil
}

// IsEnabled returns whether AI features are enabled
func (c *Client) IsEnabled() bool {
	return c.enabled
}

// GenerateXSSPayloads generates XSS payloads for a target
func (c *Client) GenerateXSSPayloads(ctx context.Context, target, context string) ([]string, error) {
	if !c.enabled {
		return []string{}, nil
	}

	return c.provider.GeneratePayloads(ctx, target, context)
}

// AnalyzeVulnerability analyzes a vulnerability finding
func (c *Client) AnalyzeVulnerability(ctx context.Context, finding string) (*Analysis, error) {
	if !c.enabled {
		return nil, fmt.Errorf("AI not enabled")
	}

	return c.provider.AnalyzeVulnerability(ctx, finding)
}

// GenerateWordlist generates a custom wordlist for fuzzing
func (c *Client) GenerateWordlist(ctx context.Context, target string, size int) ([]string, error) {
	if !c.enabled {
		return []string{}, nil
	}

	return c.provider.GenerateWordlist(ctx, target, size)
}

// OpenAIProvider implements the Provider interface for OpenAI
type OpenAIProvider struct {
	apiKey string
	model  string
	client *http.Client
}

// OpenAIRequest represents an OpenAI API request
type OpenAIRequest struct {
	Model       string    `json:"model"`
	Messages    []Message `json:"messages"`
	MaxTokens   int       `json:"max_tokens"`
	Temperature float64   `json:"temperature"`
}

// Message represents a chat message
type Message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// OpenAIResponse represents an OpenAI API response
type OpenAIResponse struct {
	Choices []Choice `json:"choices"`
	Error   *Error   `json:"error,omitempty"`
}

// Choice represents a response choice
type Choice struct {
	Message Message `json:"message"`
}

// Error represents an API error
type Error struct {
	Message string `json:"message"`
	Type    string `json:"type"`
}

// NewOpenAIProvider creates a new OpenAI provider
func NewOpenAIProvider(apiKey, model string) (*OpenAIProvider, error) {
	if model == "" {
		model = "gpt-4"
	}

	return &OpenAIProvider{
		apiKey: apiKey,
		model:  model,
		client: &http.Client{
			Timeout: 60 * time.Second,
		},
	}, nil
}

// GeneratePayloads generates XSS payloads using OpenAI
func (p *OpenAIProvider) GeneratePayloads(ctx context.Context, target, context string) ([]string, error) {
	prompt := fmt.Sprintf(`Generate 10 diverse XSS payloads for testing the target: %s

Context: %s

Requirements:
- Include different payload types (script tags, event handlers, DOM-based, etc.)
- Consider potential filters and WAF bypasses
- Focus on practical payloads that might work in real scenarios
- Return only the payloads, one per line, without explanations

Payloads:`, target, context)

	response, err := p.callAPI(ctx, prompt)
	if err != nil {
		return nil, err
	}

	// Parse payloads from response
	payloads := strings.Split(strings.TrimSpace(response), "\n")
	var cleanPayloads []string
	for _, payload := range payloads {
		payload = strings.TrimSpace(payload)
		if payload != "" && !strings.HasPrefix(payload, "#") {
			cleanPayloads = append(cleanPayloads, payload)
		}
	}

	return cleanPayloads, nil
}

// AnalyzeVulnerability analyzes a vulnerability using OpenAI
func (p *OpenAIProvider) AnalyzeVulnerability(ctx context.Context, finding string) (*Analysis, error) {
	prompt := fmt.Sprintf(`Analyze this security finding and provide a structured assessment:

Finding: %s

Please provide:
1. Severity level (Critical/High/Medium/Low)
2. Impact description
3. Remediation steps
4. Relevant references or standards

Format your response as JSON with keys: severity, impact, remediation, references`, finding)

	response, err := p.callAPI(ctx, prompt)
	if err != nil {
		return nil, err
	}

	var analysis Analysis
	if err := json.Unmarshal([]byte(response), &analysis); err != nil {
		// If JSON parsing fails, create a basic analysis
		return &Analysis{
			Severity:    "Medium",
			Impact:      "Potential security vulnerability detected",
			Remediation: "Review and validate the finding manually",
			References:  []string{},
		}, nil
	}

	return &analysis, nil
}

// GenerateWordlist generates a custom wordlist using OpenAI
func (p *OpenAIProvider) GenerateWordlist(ctx context.Context, target string, size int) ([]string, error) {
	prompt := fmt.Sprintf(`Generate %d directory and file names for fuzzing the target: %s

Consider:
- Common web application paths
- Technology-specific paths
- Administrative interfaces
- API endpoints
- Configuration files
- Backup files

Return only the paths/filenames, one per line, without explanations.

Paths:`, size, target)

	response, err := p.callAPI(ctx, prompt)
	if err != nil {
		return nil, err
	}

	// Parse wordlist from response
	words := strings.Split(strings.TrimSpace(response), "\n")
	var cleanWords []string
	for _, word := range words {
		word = strings.TrimSpace(word)
		if word != "" && !strings.HasPrefix(word, "#") {
			cleanWords = append(cleanWords, word)
		}
	}

	return cleanWords, nil
}

// callAPI makes a request to the OpenAI API
func (p *OpenAIProvider) callAPI(ctx context.Context, prompt string) (string, error) {
	request := OpenAIRequest{
		Model: p.model,
		Messages: []Message{
			{
				Role:    "system",
				Content: "You are a cybersecurity expert helping with ethical bug bounty research.",
			},
			{
				Role:    "user",
				Content: prompt,
			},
		},
		MaxTokens:   1000,
		Temperature: 0.7,
	}

	jsonData, err := json.Marshal(request)
	if err != nil {
		return "", fmt.Errorf("failed to marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", "https://api.openai.com/v1/chat/completions", bytes.NewBuffer(jsonData))
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+p.apiKey)

	resp, err := p.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to make request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response: %w", err)
	}

	var response OpenAIResponse
	if err := json.Unmarshal(body, &response); err != nil {
		return "", fmt.Errorf("failed to parse response: %w", err)
	}

	if response.Error != nil {
		return "", fmt.Errorf("API error: %s", response.Error.Message)
	}

	if len(response.Choices) == 0 {
		return "", fmt.Errorf("no response choices returned")
	}

	return response.Choices[0].Message.Content, nil
}

// Placeholder implementations for other providers
type AnthropicProvider struct {
	apiKey string
	model  string
}

func NewAnthropicProvider(apiKey, model string) (*AnthropicProvider, error) {
	return &AnthropicProvider{apiKey: apiKey, model: model}, nil
}

func (p *AnthropicProvider) GeneratePayloads(ctx context.Context, target, context string) ([]string, error) {
	// TODO: Implement Anthropic integration
	return []string{}, nil
}

func (p *AnthropicProvider) AnalyzeVulnerability(ctx context.Context, finding string) (*Analysis, error) {
	// TODO: Implement Anthropic integration
	return nil, nil
}

func (p *AnthropicProvider) GenerateWordlist(ctx context.Context, target string, size int) ([]string, error) {
	// TODO: Implement Anthropic integration
	return []string{}, nil
}

type OllamaProvider struct {
	model string
}

func NewOllamaProvider(model string) (*OllamaProvider, error) {
	return &OllamaProvider{model: model}, nil
}

func (p *OllamaProvider) GeneratePayloads(ctx context.Context, target, context string) ([]string, error) {
	// TODO: Implement Ollama integration
	return []string{}, nil
}

func (p *OllamaProvider) AnalyzeVulnerability(ctx context.Context, finding string) (*Analysis, error) {
	// TODO: Implement Ollama integration
	return nil, nil
}

func (p *OllamaProvider) GenerateWordlist(ctx context.Context, target string, size int) ([]string, error) {
	// TODO: Implement Ollama integration
	return []string{}, nil
}
