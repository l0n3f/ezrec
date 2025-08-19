package telegram

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

// Client represents a Telegram bot client
type Client struct {
	token  string
	chatID string
	client *http.Client
}

// Message represents a Telegram message
type Message struct {
	ChatID    string `json:"chat_id"`
	Text      string `json:"text"`
	ParseMode string `json:"parse_mode,omitempty"`
}

// Response represents a Telegram API response
type Response struct {
	OK          bool   `json:"ok"`
	Description string `json:"description,omitempty"`
	ErrorCode   int    `json:"error_code,omitempty"`
}

// NewClient creates a new Telegram client
func NewClient(token, chatID string) *Client {
	return &Client{
		token:  token,
		chatID: chatID,
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// SendMessage sends a message to the configured chat
func (c *Client) SendMessage(text string) error {
	return c.SendMessageWithOptions(text, "Markdown", false)
}

// SendMessageWithOptions sends a message with specific options
func (c *Client) SendMessageWithOptions(text, parseMode string, disablePreview bool) error {
	url := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", c.token)

	message := Message{
		ChatID:    c.chatID,
		Text:      text,
		ParseMode: parseMode,
	}

	jsonData, err := json.Marshal(message)
	if err != nil {
		return fmt.Errorf("failed to marshal message: %w", err)
	}

	resp, err := c.client.Post(url, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response: %w", err)
	}

	var response Response
	if err := json.Unmarshal(body, &response); err != nil {
		return fmt.Errorf("failed to parse response: %w", err)
	}

	if !response.OK {
		return fmt.Errorf("telegram API error %d: %s", response.ErrorCode, response.Description)
	}

	return nil
}

// SendStageComplete sends a stage completion notification
func (c *Client) SendStageComplete(stage string, results map[string]interface{}) error {
	emoji := getStageEmoji(stage)

	message := fmt.Sprintf("%s *Stage Complete: %s*\n\n", emoji, strings.Title(stage))

	for key, value := range results {
		message += fmt.Sprintf("*%s:* %v\n", strings.Title(key), value)
	}

	return c.SendMessage(message)
}

// SendCriticalAlert sends a critical finding alert
func (c *Client) SendCriticalAlert(finding string, details map[string]string) error {
	message := fmt.Sprintf("🚨 *CRITICAL FINDING*\n\n*Finding:* %s\n\n", finding)

	for key, value := range details {
		message += fmt.Sprintf("*%s:* %s\n", strings.Title(key), value)
	}

	return c.SendMessage(message)
}

// SendStartNotification sends a pipeline start notification
func (c *Client) SendStartNotification(program string, targets int, stages []string) error {
	stageList := strings.Join(stages, ", ")

	message := fmt.Sprintf("🔍 *ezrec Reconnaissance Started*\n\n"+
		"*Program:* %s\n"+
		"*Targets:* %d\n"+
		"*Stages:* %s\n"+
		"*Started:* %s",
		program, targets, stageList, time.Now().Format("15:04:05"))

	return c.SendMessage(message)
}

// SendCompletionNotification sends a pipeline completion notification
func (c *Client) SendCompletionNotification(program string, duration time.Duration, summary map[string]int) error {
	message := fmt.Sprintf("🎉 *ezrec Reconnaissance Complete*\n\n"+
		"*Program:* %s\n"+
		"*Duration:* %s\n"+
		"*Completed:* %s\n\n",
		program, duration.String(), time.Now().Format("15:04:05"))

	if len(summary) > 0 {
		message += "*Summary:*\n"
		for stage, count := range summary {
			emoji := getStageEmoji(stage)
			message += fmt.Sprintf("%s %s: %d\n", emoji, strings.Title(stage), count)
		}
	}

	return c.SendMessage(message)
}

// SendErrorNotification sends an error notification
func (c *Client) SendErrorNotification(stage, error string) error {
	message := fmt.Sprintf("❌ *Stage Failed: %s*\n\n*Error:* %s", strings.Title(stage), error)
	return c.SendMessage(message)
}

// TestConnection tests the Telegram connection
func (c *Client) TestConnection() error {
	url := fmt.Sprintf("https://api.telegram.org/bot%s/getMe", c.token)

	resp, err := c.client.Get(url)
	if err != nil {
		return fmt.Errorf("failed to connect to Telegram: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response: %w", err)
	}

	var response Response
	if err := json.Unmarshal(body, &response); err != nil {
		return fmt.Errorf("failed to parse response: %w", err)
	}

	if !response.OK {
		return fmt.Errorf("telegram API error %d: %s", response.ErrorCode, response.Description)
	}

	return nil
}

// SendWithContext sends a message with context for cancellation
func (c *Client) SendWithContext(ctx context.Context, text string) error {
	url := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", c.token)

	message := Message{
		ChatID:    c.chatID,
		Text:      text,
		ParseMode: "Markdown",
	}

	jsonData, err := json.Marshal(message)
	if err != nil {
		return fmt.Errorf("failed to marshal message: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response: %w", err)
	}

	var response Response
	if err := json.Unmarshal(body, &response); err != nil {
		return fmt.Errorf("failed to parse response: %w", err)
	}

	if !response.OK {
		return fmt.Errorf("telegram API error %d: %s", response.ErrorCode, response.Description)
	}

	return nil
}

// getStageEmoji returns an emoji for a given stage
func getStageEmoji(stage string) string {
	emojis := map[string]string{
		"subdomains": "🌐",
		"httpx":      "🔍",
		"crawl":      "🕷️",
		"urls":       "📜",
		"endpoints":  "🎯",
		"xss":        "⚡",
		"nuclei":     "🔬",
		"ffuf":       "🔨",
	}

	if emoji, exists := emojis[stage]; exists {
		return emoji
	}
	return "📊"
}

// Notifier provides high-level notification functionality
type Notifier struct {
	client  *Client
	enabled bool
}

// NewNotifier creates a new notifier
func NewNotifier(token, chatID string) *Notifier {
	if token == "" || chatID == "" {
		return &Notifier{enabled: false}
	}

	client := NewClient(token, chatID)
	return &Notifier{
		client:  client,
		enabled: true,
	}
}

// IsEnabled returns whether notifications are enabled
func (n *Notifier) IsEnabled() bool {
	return n.enabled
}

// Notify sends a notification if enabled
func (n *Notifier) Notify(message string) error {
	if !n.enabled {
		return nil
	}
	return n.client.SendMessage(message)
}

// NotifyStage sends a stage notification
func (n *Notifier) NotifyStage(stage string, results map[string]interface{}) error {
	if !n.enabled {
		return nil
	}
	return n.client.SendStageComplete(stage, results)
}

// NotifyCritical sends a critical alert
func (n *Notifier) NotifyCritical(finding string, details map[string]string) error {
	if !n.enabled {
		return nil
	}
	return n.client.SendCriticalAlert(finding, details)
}

// NotifyError sends an error notification
func (n *Notifier) NotifyError(stage, error string) error {
	if !n.enabled {
		return nil
	}
	return n.client.SendErrorNotification(stage, error)
}
