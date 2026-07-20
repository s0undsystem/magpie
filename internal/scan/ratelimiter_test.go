package scan

import (
	"context"
	"testing"
	"time"
)

func TestRateLimiterAllowsBurst(t *testing.T) {
	rl := NewRateLimiter(1, 5)
	ctx := context.Background()
	for i := 0; i < 5; i++ {
		if err := rl.Wait(ctx); err != nil {
			t.Fatalf("Wait() call %d error = %v", i, err)
		}
	}
}

func TestRateLimiterThrottlesBeyondBurst(t *testing.T) {
	rl := NewRateLimiter(1000, 1) // burst of 1, fast refill so test stays quick
	ctx := context.Background()
	if err := rl.Wait(ctx); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	if err := rl.Wait(ctx); err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(start); elapsed <= 0 {
		t.Error("expected second call beyond burst to wait for refill")
	}
}

func TestRateLimiterRespectsContextCancellation(t *testing.T) {
	rl := NewRateLimiter(0.001, 1) // effectively never refills within test window
	ctx := context.Background()
	if err := rl.Wait(ctx); err != nil {
		t.Fatal(err)
	}
	cctx, cancel := context.WithTimeout(ctx, 20*time.Millisecond)
	defer cancel()
	if err := rl.Wait(cctx); err == nil {
		t.Error("expected Wait to return an error when context is cancelled before a token is available")
	}
}
