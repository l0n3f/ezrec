package config

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"gopkg.in/yaml.v3"
)

// Config represents the main configuration structure
type Config struct {
	Program     string            `yaml:"program"`
	Rate        int               `yaml:"rate"`        // requests per second
	Concurrency int               `yaml:"concurrency"` // concurrent workers
	Timeout     time.Duration     `yaml:"timeout"`
	Headers     map[string]string `yaml:"headers"` // custom headers for requests
	UserAgent   string            `yaml:"user_agent"`
	Scope       ScopeConfig       `yaml:"scope"`
	Tools       ToolsConfig       `yaml:"tools"`
	Output      OutputConfig      `yaml:"output"`
	Telegram    TelegramConfig    `yaml:"telegram"`
	AI          AIConfig          `yaml:"ai"`
}

// ScopeConfig defines inclusion/exclusion rules
type ScopeConfig struct {
	Include []string `yaml:"include"` // regex patterns to include
	Exclude []string `yaml:"exclude"` // regex patterns to exclude
}

// ToolsConfig contains tool-specific configurations
type ToolsConfig struct {
	Subfinder   SubfinderConfig   `yaml:"subfinder"`
	Amass       AmassConfig       `yaml:"amass"`
	Httpx       HttpxConfig       `yaml:"httpx"`
	Katana      KatanaConfig      `yaml:"katana"`
	Gau         GauConfig         `yaml:"gau"`
	Waybackurls WaybackurlsConfig `yaml:"waybackurls"`
	Nuclei      NucleiConfig      `yaml:"nuclei"`
	Ffuf        FfufConfig        `yaml:"ffuf"`
}

// SubfinderConfig for subdomain enumeration
type SubfinderConfig struct {
	Sources  []string `yaml:"sources"`
	MaxDepth int      `yaml:"max_depth"`
	Timeout  int      `yaml:"timeout"`
	Threads  int      `yaml:"threads"`
}

// AmassConfig for subdomain enumeration
type AmassConfig struct {
	MaxDNSQueries int      `yaml:"max_dns_queries"`
	Sources       []string `yaml:"sources"`
	Wordlists     []string `yaml:"wordlists"`
}

// HttpxConfig for host probing
type HttpxConfig struct {
	Threads      int      `yaml:"threads"`
	Timeout      int      `yaml:"timeout"`
	MaxRedirects int      `yaml:"max_redirects"`
	StatusCodes  []int    `yaml:"status_codes"`
	TechDetect   bool     `yaml:"tech_detect"`
	Screenshot   bool     `yaml:"screenshot"`
	Ports        []string `yaml:"ports"`
}

// KatanaConfig for crawling
type KatanaConfig struct {
	MaxDepth    int      `yaml:"max_depth"`
	MaxPages    int      `yaml:"max_pages"`
	Concurrency int      `yaml:"concurrency"`
	Delay       int      `yaml:"delay"`
	Extensions  []string `yaml:"extensions"`
	FilterRegex []string `yaml:"filter_regex"`
}

// GauConfig for historical URLs
type GauConfig struct {
	Providers []string `yaml:"providers"`
	MaxPages  int      `yaml:"max_pages"`
	Threads   int      `yaml:"threads"`
}

// WaybackurlsConfig for historical URLs
type WaybackurlsConfig struct {
	GetVersions bool `yaml:"get_versions"`
	NoSubs      bool `yaml:"no_subs"`
}

// NucleiConfig for vulnerability scanning
type NucleiConfig struct {
	Templates    []string `yaml:"templates"`
	Severity     []string `yaml:"severity"`
	Tags         []string `yaml:"tags"`
	ExcludeTags  []string `yaml:"exclude_tags"`
	RateLimit    int      `yaml:"rate_limit"`
	BulkSize     int      `yaml:"bulk_size"`
	Timeout      int      `yaml:"timeout"`
	MaxHostError int      `yaml:"max_host_error"`
}

// FfufConfig for fuzzing
type FfufConfig struct {
	Wordlists      []string `yaml:"wordlists"`
	Extensions     []string `yaml:"extensions"`
	Threads        int      `yaml:"threads"`
	Delay          string   `yaml:"delay"`
	MatchCodes     []int    `yaml:"match_codes"`
	FilterSize     []int    `yaml:"filter_size"`
	FilterWords    []int    `yaml:"filter_words"`
	FilterLines    []int    `yaml:"filter_lines"`
	Recursion      bool     `yaml:"recursion"`
	RecursionDepth int      `yaml:"recursion_depth"`
}

// OutputConfig for output formatting
type OutputConfig struct {
	Directory string   `yaml:"directory"`
	Formats   []string `yaml:"formats"` // markdown, csv, ndjson
	Timestamp bool     `yaml:"timestamp"`
}

// TelegramConfig for notifications
type TelegramConfig struct {
	Token  string `yaml:"token"`
	ChatID string `yaml:"chat_id"`
	Alerts struct {
		StageComplete bool     `yaml:"stage_complete"`
		Critical      bool     `yaml:"critical"`
		Keywords      []string `yaml:"keywords"`
	} `yaml:"alerts"`
}

// AIConfig for AI integration
type AIConfig struct {
	Provider string `yaml:"provider"` // openai, anthropic, ollama
	APIKey   string `yaml:"api_key"`
	Model    string `yaml:"model"`
	Enabled  bool   `yaml:"enabled"`
}

// DefaultConfig returns a configuration with sensible defaults
func DefaultConfig() *Config {
	return &Config{
		Rate:        5,
		Concurrency: 50,
		Timeout:     30 * time.Second,
		Headers: map[string]string{
			"User-Agent": "ezrec/1.0 (Bug Bounty Research Tool)",
		},
		Scope: ScopeConfig{
			Include: []string{".*"},
			Exclude: []string{},
		},
		Tools: ToolsConfig{
			Subfinder: SubfinderConfig{
				Sources:  []string{"all"},
				MaxDepth: 3,
				Timeout:  30,
				Threads:  10,
			},
			Amass: AmassConfig{
				MaxDNSQueries: 1000,
				Sources:       []string{"all"},
			},
			Httpx: HttpxConfig{
				Threads:      50,
				Timeout:      10,
				MaxRedirects: 3,
				StatusCodes:  []int{200, 201, 202, 204, 301, 302, 307, 308, 401, 403, 500},
				TechDetect:   true,
				Screenshot:   false,
				Ports:        []string{"80", "443", "8080", "8443"},
			},
			Katana: KatanaConfig{
				MaxDepth:    3,
				MaxPages:    1000,
				Concurrency: 10,
				Delay:       1,
				Extensions:  []string{"js", "php", "asp", "aspx", "jsp"},
			},
			Gau: GauConfig{
				Providers: []string{"wayback", "commoncrawl", "otx", "urlscan"},
				MaxPages:  10,
				Threads:   5,
			},
			Waybackurls: WaybackurlsConfig{
				GetVersions: false,
				NoSubs:      false,
			},
			Nuclei: NucleiConfig{
				Templates:    []string{"./templates/"},
				Severity:     []string{"critical", "high", "medium"},
				RateLimit:    150,
				BulkSize:     25,
				Timeout:      10,
				MaxHostError: 30,
			},
			Ffuf: FfufConfig{
				Wordlists:      []string{"./wordlists/common.txt"},
				Extensions:     []string{"php", "asp", "aspx", "jsp", "html", "js", "txt", "bak"},
				Threads:        40,
				Delay:          "0.1-2.0",
				MatchCodes:     []int{200, 204, 301, 302, 307, 401, 403},
				Recursion:      true,
				RecursionDepth: 2,
			},
		},
		Output: OutputConfig{
			Directory: "./out",
			Formats:   []string{"markdown", "csv", "ndjson"},
			Timestamp: true,
		},
		AI: AIConfig{
			Provider: "openai",
			Model:    "gpt-4",
			Enabled:  false,
		},
	}
}

// LoadConfig loads configuration from a YAML file
func LoadConfig(path string) (*Config, error) {
	config := DefaultConfig()

	if path == "" {
		return config, nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return config, nil // Use defaults if file doesn't exist
		}
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	if err := yaml.Unmarshal(data, config); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	return config, nil
}

// LoadProfileConfig loads a program-specific configuration
func LoadProfileConfig(program string) (*Config, error) {
	profilePath := filepath.Join("profiles", program+".yml")
	return LoadConfig(profilePath)
}

// SaveConfig saves the configuration to a YAML file
func (c *Config) SaveConfig(path string) error {
	data, err := yaml.Marshal(c)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	return nil
}

// Validate validates the configuration
func (c *Config) Validate() error {
	if c.Rate <= 0 {
		return fmt.Errorf("rate must be positive")
	}
	if c.Concurrency <= 0 {
		return fmt.Errorf("concurrency must be positive")
	}
	if c.Timeout <= 0 {
		return fmt.Errorf("timeout must be positive")
	}
	return nil
}
