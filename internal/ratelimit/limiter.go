package ratelimit

import (
	"context"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// Limiter provides rate limiting capabilities with per-host and global limits
type Limiter struct {
	globalLimiter *rate.Limiter
	hostLimiters  map[string]*rate.Limiter
	mutex         sync.RWMutex
	hostRate      rate.Limit
	hostBurst     int
}

// NewLimiter creates a new rate limiter
func NewLimiter(globalRate int, hostRate int) *Limiter {
	return &Limiter{
		globalLimiter: rate.NewLimiter(rate.Limit(globalRate), globalRate),
		hostLimiters:  make(map[string]*rate.Limiter),
		hostRate:      rate.Limit(hostRate),
		hostBurst:     hostRate,
	}
}

// Wait waits for permission to proceed with a request to the specified host
func (l *Limiter) Wait(ctx context.Context, host string) error {
	// Wait for global rate limit
	if err := l.globalLimiter.Wait(ctx); err != nil {
		return err
	}

	// Wait for host-specific rate limit
	hostLimiter := l.getHostLimiter(host)
	return hostLimiter.Wait(ctx)
}

// Allow checks if a request to the specified host is allowed immediately
func (l *Limiter) Allow(host string) bool {
	if !l.globalLimiter.Allow() {
		return false
	}

	hostLimiter := l.getHostLimiter(host)
	return hostLimiter.Allow()
}

// getHostLimiter returns the rate limiter for a specific host
func (l *Limiter) getHostLimiter(host string) *rate.Limiter {
	l.mutex.RLock()
	limiter, exists := l.hostLimiters[host]
	l.mutex.RUnlock()

	if exists {
		return limiter
	}

	l.mutex.Lock()
	defer l.mutex.Unlock()

	// Double-check in case another goroutine created it
	if limiter, exists := l.hostLimiters[host]; exists {
		return limiter
	}

	// Create new host limiter
	limiter = rate.NewLimiter(l.hostRate, l.hostBurst)
	l.hostLimiters[host] = limiter
	return limiter
}

// UpdateGlobalRate updates the global rate limit
func (l *Limiter) UpdateGlobalRate(newRate int) {
	l.globalLimiter.SetLimit(rate.Limit(newRate))
	l.globalLimiter.SetBurst(newRate)
}

// UpdateHostRate updates the host-specific rate limit for new hosts
func (l *Limiter) UpdateHostRate(newRate int) {
	l.mutex.Lock()
	defer l.mutex.Unlock()

	l.hostRate = rate.Limit(newRate)
	l.hostBurst = newRate

	// Update existing host limiters
	for _, limiter := range l.hostLimiters {
		limiter.SetLimit(l.hostRate)
		limiter.SetBurst(l.hostBurst)
	}
}

// Stats returns statistics about the rate limiter
func (l *Limiter) Stats() map[string]interface{} {
	l.mutex.RLock()
	defer l.mutex.RUnlock()

	return map[string]interface{}{
		"global_rate":   float64(l.globalLimiter.Limit()),
		"global_burst":  l.globalLimiter.Burst(),
		"host_rate":     float64(l.hostRate),
		"host_burst":    l.hostBurst,
		"tracked_hosts": len(l.hostLimiters),
	}
}

// BackoffLimiter provides exponential backoff with jitter
type BackoffLimiter struct {
	baseDelay     time.Duration
	maxDelay      time.Duration
	backoffFactor float64
	jitterFactor  float64
	attempts      map[string]int
	mutex         sync.RWMutex
}

// NewBackoffLimiter creates a new backoff limiter
func NewBackoffLimiter(baseDelay, maxDelay time.Duration) *BackoffLimiter {
	return &BackoffLimiter{
		baseDelay:     baseDelay,
		maxDelay:      maxDelay,
		backoffFactor: 2.0,
		jitterFactor:  0.1,
		attempts:      make(map[string]int),
	}
}

// Wait waits with exponential backoff for the specified host
func (bl *BackoffLimiter) Wait(ctx context.Context, host string) error {
	delay := bl.calculateDelay(host)

	select {
	case <-time.After(delay):
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// RecordFailure records a failure for the specified host
func (bl *BackoffLimiter) RecordFailure(host string) {
	bl.mutex.Lock()
	defer bl.mutex.Unlock()
	bl.attempts[host]++
}

// RecordSuccess records a success for the specified host (resets backoff)
func (bl *BackoffLimiter) RecordSuccess(host string) {
	bl.mutex.Lock()
	defer bl.mutex.Unlock()
	delete(bl.attempts, host)
}

// calculateDelay calculates the delay for a host based on failure count
func (bl *BackoffLimiter) calculateDelay(host string) time.Duration {
	bl.mutex.RLock()
	attempts := bl.attempts[host]
	bl.mutex.RUnlock()

	if attempts == 0 {
		return 0
	}

	// Calculate exponential backoff
	delay := float64(bl.baseDelay)
	for i := 0; i < attempts-1; i++ {
		delay *= bl.backoffFactor
	}

	// Cap at max delay
	if delay > float64(bl.maxDelay) {
		delay = float64(bl.maxDelay)
	}

	// Add jitter
	jitter := delay * bl.jitterFactor * (2.0*randomFloat() - 1.0)
	delay += jitter

	// Ensure positive delay
	if delay < 0 {
		delay = float64(bl.baseDelay)
	}

	return time.Duration(delay)
}

// randomFloat returns a random float between 0 and 1
func randomFloat() float64 {
	return float64(time.Now().UnixNano()%1000) / 1000.0
}
