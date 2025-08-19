package util

import (
	"crypto/md5"
	"fmt"
	"math/rand"
	"net/url"
	"strings"
	"time"
)

// DeduplicateStrings removes duplicate strings from a slice while preserving order
func DeduplicateStrings(strs []string) []string {
	seen := make(map[string]bool)
	var result []string

	for _, str := range strs {
		if !seen[str] {
			seen[str] = true
			result = append(result, str)
		}
	}

	return result
}

// HashString returns MD5 hash of a string
func HashString(s string) string {
	return fmt.Sprintf("%x", md5.Sum([]byte(s)))
}

// RandomJitter returns a random duration between min and max
func RandomJitter(min, max time.Duration) time.Duration {
	if min >= max {
		return min
	}

	diff := max - min
	jitter := time.Duration(rand.Int63n(int64(diff)))
	return min + jitter
}

// ExtractDomain extracts the domain from a URL
func ExtractDomain(urlStr string) string {
	parsed, err := url.Parse(urlStr)
	if err != nil {
		return urlStr
	}
	return parsed.Host
}

// CleanURL removes query parameters and fragments from a URL
func CleanURL(urlStr string) string {
	parsed, err := url.Parse(urlStr)
	if err != nil {
		return urlStr
	}

	parsed.RawQuery = ""
	parsed.Fragment = ""
	return parsed.String()
}

// IsValidURL checks if a string is a valid URL
func IsValidURL(urlStr string) bool {
	_, err := url.ParseRequestURI(urlStr)
	return err == nil
}

// NormalizeURL normalizes a URL for consistent comparison
func NormalizeURL(urlStr string) string {
	parsed, err := url.Parse(urlStr)
	if err != nil {
		return urlStr
	}

	// Convert to lowercase
	parsed.Scheme = strings.ToLower(parsed.Scheme)
	parsed.Host = strings.ToLower(parsed.Host)

	// Remove default ports
	if (parsed.Scheme == "http" && parsed.Port() == "80") ||
		(parsed.Scheme == "https" && parsed.Port() == "443") {
		parsed.Host = parsed.Hostname()
	}

	// Remove trailing slash from path
	if parsed.Path == "/" {
		parsed.Path = ""
	}

	return parsed.String()
}

// FilterEmptyStrings removes empty strings from a slice
func FilterEmptyStrings(strs []string) []string {
	var result []string
	for _, str := range strs {
		if strings.TrimSpace(str) != "" {
			result = append(result, str)
		}
	}
	return result
}

// ChunkStrings splits a slice of strings into chunks of specified size
func ChunkStrings(strs []string, chunkSize int) [][]string {
	if chunkSize <= 0 {
		return [][]string{strs}
	}

	var chunks [][]string
	for i := 0; i < len(strs); i += chunkSize {
		end := i + chunkSize
		if end > len(strs) {
			end = len(strs)
		}
		chunks = append(chunks, strs[i:end])
	}
	return chunks
}

// ContainsString checks if a string exists in a slice
func ContainsString(strs []string, target string) bool {
	for _, str := range strs {
		if str == target {
			return true
		}
	}
	return false
}

// ContainsStringIgnoreCase checks if a string exists in a slice (case-insensitive)
func ContainsStringIgnoreCase(strs []string, target string) bool {
	target = strings.ToLower(target)
	for _, str := range strs {
		if strings.ToLower(str) == target {
			return true
		}
	}
	return false
}

// TruncateString truncates a string to a maximum length
func TruncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

// FormatDuration formats a duration in a human-readable way
func FormatDuration(d time.Duration) string {
	if d < time.Second {
		return fmt.Sprintf("%dms", d.Milliseconds())
	} else if d < time.Minute {
		return fmt.Sprintf("%.1fs", d.Seconds())
	} else if d < time.Hour {
		return fmt.Sprintf("%.1fm", d.Minutes())
	} else {
		return fmt.Sprintf("%.1fh", d.Hours())
	}
}

// GenerateTimestamp generates a timestamp string for filenames
func GenerateTimestamp() string {
	return time.Now().Format("20060102-150405")
}

// SanitizeFilename removes invalid characters from a filename
func SanitizeFilename(filename string) string {
	// Replace invalid characters with underscores
	invalid := []string{"<", ">", ":", "\"", "/", "\\", "|", "?", "*"}
	for _, char := range invalid {
		filename = strings.ReplaceAll(filename, char, "_")
	}
	return filename
}

// ParseHostPort parses a host:port string and returns host and port separately
func ParseHostPort(hostport string) (host, port string) {
	if strings.Contains(hostport, ":") {
		parts := strings.Split(hostport, ":")
		if len(parts) == 2 {
			return parts[0], parts[1]
		}
	}
	return hostport, ""
}

// MergeStringSlices merges multiple string slices and removes duplicates
func MergeStringSlices(slices ...[]string) []string {
	var merged []string
	for _, slice := range slices {
		merged = append(merged, slice...)
	}
	return DeduplicateStrings(merged)
}

// RetryWithBackoff executes a function with exponential backoff
func RetryWithBackoff(fn func() error, maxRetries int, baseDelay time.Duration) error {
	var err error
	for i := 0; i < maxRetries; i++ {
		err = fn()
		if err == nil {
			return nil
		}

		if i < maxRetries-1 {
			delay := time.Duration(1<<uint(i)) * baseDelay
			jitter := RandomJitter(0, delay/10)
			time.Sleep(delay + jitter)
		}
	}
	return err
}

// init initializes the random seed
func init() {
	rand.Seed(time.Now().UnixNano())
}
