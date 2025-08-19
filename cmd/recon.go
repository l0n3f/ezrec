package cmd

import (
	"fmt"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	"github.com/ezrec/ezrec/internal/log"
	"github.com/ezrec/ezrec/internal/output"
	"github.com/ezrec/ezrec/internal/recon"
	"github.com/ezrec/ezrec/internal/telegram"
)

var (
	// Stage flags
	enableSubdomains bool
	enableHttpx      bool
	enableCrawl      bool
	enableURLs       bool
	enableEndpoints  bool
	enableXSS        bool
	enableNuclei     bool
	enableFfuf       bool

	// XSS specific flags
	xssPayload string
	aiSuggest  bool

	// Nuclei specific flags
	nucleiTemplates string
	nucleiSeverity  []string
	nucleiTags      []string

	// FFUF specific flags
	arcs         int
	ffufWordlist string

	// Resume flag
	resume bool
)

// reconCmd represents the recon command
var reconCmd = &cobra.Command{
	Use:   "recon",
	Short: "Run the complete reconnaissance pipeline",
	Long: `Run the complete reconnaissance pipeline with configurable stages.

The pipeline executes the following stages in order:
1. Subdomain enumeration (--subdomains)
2. Host liveness and fingerprinting (--httpx)
3. Endpoint crawling (--crawl)
4. Historical URL discovery (--urls)
5. Endpoint classification (--endpoints)
6. XSS testing (--xss)
7. Nuclei vulnerability scanning (--nuclei)
8. Directory/file fuzzing (--ffuf)

Each stage generates structured output in multiple formats and can be
enabled/disabled individually using the corresponding flags.`,
	Example: `  # Full pipeline on a single domain
  ezrec recon --domain example.com --subdomains --httpx --crawl --endpoints --xss --nuclei --ffuf

  # Target specific program with custom configuration
  ezrec recon --program hackerone --seed-file domains.txt --subdomains --httpx --crawl

  # XSS testing with AI-powered payload suggestions
  ezrec recon --domain example.com --httpx --crawl --xss --ai-suggest --payload "<script>alert(1)</script>"

  # Advanced fuzzing with custom wordlist and arc count
  ezrec recon --domain example.com --httpx --ffuf --arcs 10000 --ffuf-wordlist custom.txt

  # Full pipeline with Telegram notifications
  ezrec recon --program example --subdomains --httpx --crawl --xss --nuclei --ffuf \
    --telegram-token "123456:ABCDEF" --telegram-chat "987654321"`,
	RunE: runRecon,
}

func init() {
	rootCmd.AddCommand(reconCmd)

	// Stage control flags
	reconCmd.Flags().BoolVar(&enableSubdomains, "subdomains", false, "enable subdomain enumeration")
	reconCmd.Flags().BoolVar(&enableHttpx, "httpx", false, "enable host liveness and fingerprinting")
	reconCmd.Flags().BoolVar(&enableCrawl, "crawl", false, "enable endpoint crawling")
	reconCmd.Flags().BoolVar(&enableURLs, "urls", false, "enable historical URL discovery")
	reconCmd.Flags().BoolVar(&enableEndpoints, "endpoints", false, "enable endpoint classification")
	reconCmd.Flags().BoolVar(&enableXSS, "xss", false, "enable XSS testing")
	reconCmd.Flags().BoolVar(&enableNuclei, "nuclei", false, "enable Nuclei vulnerability scanning")
	reconCmd.Flags().BoolVar(&enableFfuf, "ffuf", false, "enable directory/file fuzzing")

	// XSS flags
	reconCmd.Flags().StringVar(&xssPayload, "payload", "<script>alert(1)</script>", "XSS payload to test")
	reconCmd.Flags().BoolVar(&aiSuggest, "ai-suggest", false, "enable AI-powered payload suggestions")

	// Nuclei flags
	reconCmd.Flags().StringVar(&nucleiTemplates, "nuclei-templates", "", "path to Nuclei templates directory")
	reconCmd.Flags().StringSliceVar(&nucleiSeverity, "nuclei-severity", []string{"critical", "high", "medium"}, "Nuclei severity levels to include")
	reconCmd.Flags().StringSliceVar(&nucleiTags, "nuclei-tags", nil, "Nuclei tags to include")

	// FFUF flags
	reconCmd.Flags().IntVar(&arcs, "arcs", 1000, "number of potential directories/files to fuzz")
	reconCmd.Flags().StringVar(&ffufWordlist, "ffuf-wordlist", "", "custom wordlist for FFUF")

	// Resume flag
	reconCmd.Flags().BoolVar(&resume, "resume", false, "resume from previous incomplete run")
}

func runRecon(cmd *cobra.Command, args []string) error {
	cfg := GetConfig()
	ctx := GetContext()
	logger := log.NewLogger(verbose, quiet)

	// Validate input
	if domain == "" && seedFile == "" {
		return fmt.Errorf("either --domain or --seed-file must be specified")
	}

	// Check if any stage is enabled
	if !enableSubdomains && !enableHttpx && !enableCrawl && !enableURLs &&
		!enableEndpoints && !enableXSS && !enableNuclei && !enableFfuf {
		return fmt.Errorf("at least one stage must be enabled")
	}

	// Create run directory with timestamp
	timestamp := time.Now().Format("20060102-150405")
	runDir := filepath.Join(cfg.Output.Directory, cfg.Program, fmt.Sprintf("run-%s", timestamp))

	// Initialize output manager
	outputManager, err := output.NewManager(runDir, cfg.Output.Formats)
	if err != nil {
		return fmt.Errorf("failed to initialize output manager: %w", err)
	}

	// Initialize Telegram notifications if configured
	var telegramClient *telegram.Client
	if cfg.Telegram.Token != "" && cfg.Telegram.ChatID != "" {
		telegramClient = telegram.NewClient(cfg.Telegram.Token, cfg.Telegram.ChatID)
		logger.Info("Telegram notifications enabled")
	}

	// Initialize reconnaissance engine
	reconEngine := recon.NewEngine(cfg, outputManager, telegramClient, logger)

	// Load initial targets
	var targets []string
	if domain != "" {
		targets = []string{domain}
	} else if seedFile != "" {
		targets, err = recon.LoadTargetsFromFile(seedFile)
		if err != nil {
			return fmt.Errorf("failed to load targets from file: %w", err)
		}
	}

	logger.Info("Starting reconnaissance pipeline",
		"targets", len(targets),
		"program", cfg.Program,
		"output", runDir)

	// Send start notification
	if telegramClient != nil {
		msg := fmt.Sprintf("🔍 *ezrec* reconnaissance started\n\n"+
			"*Program:* %s\n"+
			"*Targets:* %d\n"+
			"*Output:* %s\n"+
			"*Stages:* %s",
			cfg.Program,
			len(targets),
			runDir,
			getEnabledStages())
		telegramClient.SendMessage(msg)
	}

	// Execute pipeline stages
	currentTargets := targets

	// Stage 1: Subdomain Enumeration
	if enableSubdomains {
		logger.Info("Starting subdomain enumeration")
		result, err := reconEngine.EnumerateSubdomains(ctx, currentTargets)
		if err != nil {
			logger.Error("Subdomain enumeration failed", "error", err)
			if telegramClient != nil {
				telegramClient.SendMessage(fmt.Sprintf("❌ Subdomain enumeration failed: %v", err))
			}
		} else {
			currentTargets = result.Subdomains
			logger.Info("Subdomain enumeration completed", "found", len(currentTargets))
			if telegramClient != nil {
				telegramClient.SendMessage(fmt.Sprintf("✅ Subdomain enumeration complete: %d subdomains found", len(currentTargets)))
			}
		}
	}

	// Stage 2: Host Liveness and Fingerprinting
	if enableHttpx {
		logger.Info("Starting host liveness check")
		result, err := reconEngine.ProbeHosts(ctx, currentTargets)
		if err != nil {
			logger.Error("Host probing failed", "error", err)
			if telegramClient != nil {
				telegramClient.SendMessage(fmt.Sprintf("❌ Host probing failed: %v", err))
			}
		} else {
			currentTargets = result.LiveHosts
			logger.Info("Host probing completed", "live", len(currentTargets))
			if telegramClient != nil {
				telegramClient.SendMessage(fmt.Sprintf("✅ Host probing complete: %d live hosts found", len(currentTargets)))
			}
		}
	}

	// Stage 3: Endpoint Crawling
	var crawledURLs []string
	if enableCrawl {
		logger.Info("Starting endpoint crawling")
		result, err := reconEngine.CrawlEndpoints(ctx, currentTargets)
		if err != nil {
			logger.Error("Endpoint crawling failed", "error", err)
			if telegramClient != nil {
				telegramClient.SendMessage(fmt.Sprintf("❌ Endpoint crawling failed: %v", err))
			}
		} else {
			crawledURLs = result.URLs
			logger.Info("Endpoint crawling completed", "urls", len(crawledURLs))
			if telegramClient != nil {
				telegramClient.SendMessage(fmt.Sprintf("✅ Endpoint crawling complete: %d URLs found", len(crawledURLs)))
			}
		}
	}

	// Stage 4: Historical URL Discovery
	if enableURLs {
		logger.Info("Starting historical URL discovery")
		result, err := reconEngine.DiscoverHistoricalURLs(ctx, currentTargets)
		if err != nil {
			logger.Error("Historical URL discovery failed", "error", err)
			if telegramClient != nil {
				telegramClient.SendMessage(fmt.Sprintf("❌ Historical URL discovery failed: %v", err))
			}
		} else {
			// Merge with crawled URLs
			crawledURLs = append(crawledURLs, result.URLs...)
			logger.Info("Historical URL discovery completed", "urls", len(result.URLs))
			if telegramClient != nil {
				telegramClient.SendMessage(fmt.Sprintf("✅ Historical URL discovery complete: %d URLs found", len(result.URLs)))
			}
		}
	}

	// Stage 5: Endpoint Classification
	var classifiedEndpoints []string
	if enableEndpoints && len(crawledURLs) > 0 {
		logger.Info("Starting endpoint classification")
		result, err := reconEngine.ClassifyEndpoints(ctx, crawledURLs)
		if err != nil {
			logger.Error("Endpoint classification failed", "error", err)
			if telegramClient != nil {
				telegramClient.SendMessage(fmt.Sprintf("❌ Endpoint classification failed: %v", err))
			}
		} else {
			classifiedEndpoints = result.HighValueTargets
			logger.Info("Endpoint classification completed", "hvt", len(classifiedEndpoints))
			if telegramClient != nil {
				telegramClient.SendMessage(fmt.Sprintf("✅ Endpoint classification complete: %d high-value targets found", len(classifiedEndpoints)))
			}
		}
	}

	// Stage 6: XSS Testing
	if enableXSS && len(crawledURLs) > 0 {
		logger.Info("Starting XSS testing")

		// Configure XSS options
		xssOptions := recon.XSSOptions{
			Payload:   xssPayload,
			AISuggest: aiSuggest,
		}

		result, err := reconEngine.TestXSS(ctx, crawledURLs, xssOptions)
		if err != nil {
			logger.Error("XSS testing failed", "error", err)
			if telegramClient != nil {
				telegramClient.SendMessage(fmt.Sprintf("❌ XSS testing failed: %v", err))
			}
		} else {
			logger.Info("XSS testing completed", "vulnerabilities", len(result.Vulnerabilities))
			if telegramClient != nil {
				if len(result.Vulnerabilities) > 0 {
					telegramClient.SendMessage(fmt.Sprintf("🚨 XSS testing complete: %d vulnerabilities found!", len(result.Vulnerabilities)))
				} else {
					telegramClient.SendMessage("✅ XSS testing complete: no vulnerabilities found")
				}
			}
		}
	}

	// Stage 7: Nuclei Vulnerability Scanning
	if enableNuclei && len(currentTargets) > 0 {
		logger.Info("Starting Nuclei vulnerability scanning")

		nucleiOptions := recon.NucleiOptions{
			Templates: nucleiTemplates,
			Severity:  nucleiSeverity,
			Tags:      nucleiTags,
		}

		result, err := reconEngine.RunNuclei(ctx, currentTargets, nucleiOptions)
		if err != nil {
			logger.Error("Nuclei scanning failed", "error", err)
			if telegramClient != nil {
				telegramClient.SendMessage(fmt.Sprintf("❌ Nuclei scanning failed: %v", err))
			}
		} else {
			logger.Info("Nuclei scanning completed", "findings", len(result.Findings))
			if telegramClient != nil {
				criticalCount := countCriticalFindings(result.Findings)
				if criticalCount > 0 {
					telegramClient.SendMessage(fmt.Sprintf("🚨 Nuclei scanning complete: %d findings (%d critical)!", len(result.Findings), criticalCount))
				} else {
					telegramClient.SendMessage(fmt.Sprintf("✅ Nuclei scanning complete: %d findings", len(result.Findings)))
				}
			}
		}
	}

	// Stage 8: Directory/File Fuzzing
	if enableFfuf && len(currentTargets) > 0 {
		logger.Info("Starting FFUF fuzzing")

		ffufOptions := recon.FfufOptions{
			Arcs:     arcs,
			Wordlist: ffufWordlist,
		}

		result, err := reconEngine.RunFfuf(ctx, currentTargets, ffufOptions)
		if err != nil {
			logger.Error("FFUF fuzzing failed", "error", err)
			if telegramClient != nil {
				telegramClient.SendMessage(fmt.Sprintf("❌ FFUF fuzzing failed: %v", err))
			}
		} else {
			logger.Info("FFUF fuzzing completed", "discoveries", len(result.Discoveries))
			if telegramClient != nil {
				telegramClient.SendMessage(fmt.Sprintf("✅ FFUF fuzzing complete: %d discoveries", len(result.Discoveries)))
			}
		}
	}

	// Generate final report
	logger.Info("Generating final report")
	reportPath := filepath.Join(runDir, "README.md")
	if err := outputManager.GenerateFinalReport(reportPath); err != nil {
		logger.Error("Failed to generate final report", "error", err)
	} else {
		logger.Info("Final report generated", "path", reportPath)
	}

	// Send completion notification
	if telegramClient != nil {
		msg := fmt.Sprintf("🎉 *ezrec* reconnaissance completed!\n\n"+
			"*Program:* %s\n"+
			"*Duration:* %s\n"+
			"*Report:* %s",
			cfg.Program,
			time.Since(time.Now()).String(), // This would need proper timing
			reportPath)
		telegramClient.SendMessage(msg)
	}

	logger.Info("Reconnaissance pipeline completed successfully")
	return nil
}

func getEnabledStages() string {
	var stages []string
	if enableSubdomains {
		stages = append(stages, "subdomains")
	}
	if enableHttpx {
		stages = append(stages, "httpx")
	}
	if enableCrawl {
		stages = append(stages, "crawl")
	}
	if enableURLs {
		stages = append(stages, "urls")
	}
	if enableEndpoints {
		stages = append(stages, "endpoints")
	}
	if enableXSS {
		stages = append(stages, "xss")
	}
	if enableNuclei {
		stages = append(stages, "nuclei")
	}
	if enableFfuf {
		stages = append(stages, "ffuf")
	}

	if len(stages) == 0 {
		return "none"
	}

	result := ""
	for i, stage := range stages {
		if i > 0 {
			result += ", "
		}
		result += stage
	}
	return result
}

func countCriticalFindings(findings []recon.Finding) int {
	count := 0
	for _, finding := range findings {
		if finding.Severity == "critical" {
			count++
		}
	}
	return count
}
