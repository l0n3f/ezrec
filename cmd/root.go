package cmd

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/ezrec/ezrec/internal/config"
	"github.com/ezrec/ezrec/internal/log"
)

// showBanner displays the l0n3 ASCII banner
func showBanner() {
	banner := `
██╗      ██████╗ ███╗   ██╗██████╗ 
██║     ██╔═████╗████╗  ██║╚════██╗
██║     ██║██╔██║██╔██╗ ██║ █████╔╝
██║     ████╔╝██║██║╚██╗██║ ╚═══██╗
███████╗╚██████╔╝██║ ╚████║██████╔╝
╚══════╝ ╚═════╝ ╚═╝  ╚═══╝╚═════╝ 
                                   
🔥 ezrec - Ultimate Bug Bounty Recon & Evasion Orchestrator
💀 Advanced WAF Bypass | AI-Powered Testing | Stealth Mode
📡 github.com/l0n3f/ezrec
`
	fmt.Print(banner)
}

var (
	cfgFile  string
	program  string
	domain   string
	seedFile string
	outDir   string
	verbose  bool
	quiet    bool

	// Global flags
	rate        int
	concurrency int
	timeout     time.Duration
	headers     map[string]string
	userAgent   string

	// Telegram flags
	telegramToken  string
	telegramChatID string

	// AI flags
	aiEnabled  bool
	aiProvider string
	aiAPIKey   string
	aiModel    string

	cfg    *config.Config
	ctx    context.Context
	cancel context.CancelFunc
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "ezrec",
	Short: "Bug Bounty Recon Orchestrator",
	Long: `ezrec is a comprehensive bug bounty reconnaissance tool that automates
the entire discovery pipeline from subdomain enumeration to vulnerability testing.

Features:
  • Modular and scalable recon pipeline
  • Subdomain enumeration (subfinder, amass)
  • Host liveness and fingerprinting (httpx)
  • Endpoint crawling (katana)
  • Historical URL discovery (gau, waybackurls)
  • Critical endpoint classification (login, admin, API, payments)
  • Interactive XSS testing with AI-powered payload suggestions
  • Nuclei integration with enhanced templates
  • Advanced fuzzing with ffuf
  • Structured outputs (Markdown, CSV, NDJSON)
  • Telegram notifications and alerts
  • Rate limiting and scope awareness
  • Program-specific configurations`,
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		return initConfig()
	},
}

// Execute adds all child commands to the root command and sets flags appropriately.
func Execute() error {
	// Show banner unless quiet mode is enabled or help is requested
	args := os.Args
	isHelp := false
	isQuiet := false
	
	for _, arg := range args {
		if arg == "--help" || arg == "-h" {
			isHelp = true
			break
		}
		if arg == "--quiet" || arg == "-q" {
			isQuiet = true
			break
		}
	}
	
	// Show banner for actual command execution (not help)
	if !isHelp && !isQuiet && len(args) > 1 {
		showBanner()
	}

	// Setup signal handling for graceful shutdown
	ctx, cancel = signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	return rootCmd.ExecuteContext(ctx)
}

func init() {
	// Note: initConfig is called in PersistentPreRunE instead

	// Global flags
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is ./profiles/$program.yml)")
	rootCmd.PersistentFlags().StringVar(&program, "program", "", "bug bounty program name (loads ./profiles/$program.yml)")
	rootCmd.PersistentFlags().StringVar(&domain, "domain", "", "single domain to start reconnaissance")
	rootCmd.PersistentFlags().StringVar(&seedFile, "seed-file", "", "file containing list of domains/subdomains")
	rootCmd.PersistentFlags().StringVar(&outDir, "outdir", "./results", "output directory for results")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "verbose output")
	rootCmd.PersistentFlags().BoolVarP(&quiet, "quiet", "q", false, "quiet output (errors only)")

	// Rate limiting and concurrency
	rootCmd.PersistentFlags().IntVar(&rate, "rate", 5, "requests per second rate limit")
	rootCmd.PersistentFlags().IntVar(&concurrency, "concurrency", 50, "number of concurrent workers")
	rootCmd.PersistentFlags().DurationVar(&timeout, "timeout", 30*time.Second, "request timeout")

	// Custom headers
	rootCmd.PersistentFlags().StringToStringVar(&headers, "headers", nil, "custom headers (key=value format)")
	rootCmd.PersistentFlags().StringVar(&userAgent, "user-agent", "", "custom User-Agent header")

	// Telegram notifications
	rootCmd.PersistentFlags().StringVar(&telegramToken, "telegram-token", "", "Telegram bot token for notifications")
	rootCmd.PersistentFlags().StringVar(&telegramChatID, "telegram-chat", "", "Telegram chat ID for notifications")

	// AI integration
	rootCmd.PersistentFlags().BoolVar(&aiEnabled, "ai", false, "enable AI-powered features")
	rootCmd.PersistentFlags().StringVar(&aiProvider, "ai-provider", "openai", "AI provider (openai, anthropic, ollama)")
	rootCmd.PersistentFlags().StringVar(&aiAPIKey, "ai-key", "", "AI API key")
	rootCmd.PersistentFlags().StringVar(&aiModel, "ai-model", "gpt-4", "AI model to use")

	// Bind flags to viper
	viper.BindPFlag("rate", rootCmd.PersistentFlags().Lookup("rate"))
	viper.BindPFlag("concurrency", rootCmd.PersistentFlags().Lookup("concurrency"))
	viper.BindPFlag("timeout", rootCmd.PersistentFlags().Lookup("timeout"))
}

// initConfig reads in config file and ENV variables if set.
func initConfig() error {
	logger := log.NewLogger(verbose, quiet)

	// Load configuration
	var err error
	if program != "" {
		cfg, err = config.LoadProfileConfig(program)
		if err != nil {
			return fmt.Errorf("failed to load program config: %w", err)
		}
		logger.Info("Loaded program configuration", "program", program)
	} else if cfgFile != "" {
		cfg, err = config.LoadConfig(cfgFile)
		if err != nil {
			return fmt.Errorf("failed to load config: %w", err)
		}
		logger.Info("Loaded configuration", "config", cfgFile)
	} else {
		cfg = config.DefaultConfig()
		logger.Info("Using default configuration")
	}

	// Override config with command line flags
	if rate > 0 {
		cfg.Rate = rate
	}
	if concurrency > 0 {
		cfg.Concurrency = concurrency
	}
	if timeout > 0 {
		cfg.Timeout = timeout
	}
	if userAgent != "" {
		cfg.UserAgent = userAgent
		cfg.Headers["User-Agent"] = userAgent
	}
	if len(headers) > 0 {
		for k, v := range headers {
			cfg.Headers[k] = v
		}
	}
	if outDir != "" {
		cfg.Output.Directory = outDir
	}

	// Telegram configuration
	if telegramToken != "" {
		cfg.Telegram.Token = telegramToken
	}
	if telegramChatID != "" {
		cfg.Telegram.ChatID = telegramChatID
	}

	// AI configuration
	if aiEnabled {
		cfg.AI.Enabled = true
	}
	if aiProvider != "" {
		cfg.AI.Provider = aiProvider
	}
	if aiAPIKey != "" {
		cfg.AI.APIKey = aiAPIKey
	}
	if aiModel != "" {
		cfg.AI.Model = aiModel
	}

	// Set program name if provided
	if program != "" {
		cfg.Program = program
	}

	// Validate configuration
	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("invalid configuration: %w", err)
	}

	// Create output directory
	if err := os.MkdirAll(cfg.Output.Directory, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	// Create program-specific output directory
	if cfg.Program != "" {
		programDir := filepath.Join(cfg.Output.Directory, cfg.Program)
		if err := os.MkdirAll(programDir, 0755); err != nil {
			return fmt.Errorf("failed to create program output directory: %w", err)
		}
	}

	logger.Info("Configuration initialized successfully")
	return nil
}

// GetConfig returns the current configuration
func GetConfig() *config.Config {
	return cfg
}

// GetContext returns the context for cancellation
func GetContext() context.Context {
	return ctx
}

// GetDomain returns the domain to scan
func GetDomain() string {
	return domain
}

// GetSeedFile returns the seed file path
func GetSeedFile() string {
	return seedFile
}
