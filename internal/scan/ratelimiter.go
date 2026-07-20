package scan

import (
	"context"
	"sync"
	"time"
)

type RateLimiter struct {
	mu         sync.Mutex
	tokens     float64
	max        float64
	ratePerSec float64
	last       time.Time
	now        func() time.Time
}

func NewRateLimiter(ratePerSec float64, burst int) *RateLimiter {
	if ratePerSec <= 0 {
		ratePerSec = 1
	}
	if burst <= 0 {
		burst = 1
	}
	return &RateLimiter{
		tokens:     float64(burst),
		max:        float64(burst),
		ratePerSec: ratePerSec,
		last:       time.Now(),
		now:        time.Now,
	}
}

func (r *RateLimiter) Wait(ctx context.Context) error {
	for {
		r.mu.Lock()
		now := r.now()
		elapsed := now.Sub(r.last).Seconds()
		if elapsed > 0 {
			r.tokens += elapsed * r.ratePerSec
			if r.tokens > r.max {
				r.tokens = r.max
			}
			r.last = now
		}
		if r.tokens >= 1 {
			r.tokens--
			r.mu.Unlock()
			return nil
		}
		wait := time.Duration((1 - r.tokens) / r.ratePerSec * float64(time.Second))
		r.mu.Unlock()

		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}
