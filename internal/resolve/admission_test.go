package resolve

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"dwebproxy/internal/content"
)

func TestSharedWorkKeepsAdmissionAfterWaitersCancel(t *testing.T) {
	entered := make(chan struct{}, 2)
	release := make(chan struct{})
	var calls atomic.Int32
	r := resolverFunc(func(ctx context.Context, _ string) (content.Target, error) {
		calls.Add(1)
		entered <- struct{}{}
		select {
		case <-release:
			return content.Target{Kind: content.IPFS, ID: "root"}, nil
		case <-ctx.Done():
			return content.Target{}, ctx.Err()
		}
	})
	c := NewCached(r, 10, time.Minute, time.Second, time.Second, 2)
	t.Cleanup(c.Close)
	for _, name := range []string{"one.eth", "two.eth"} {
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() { _, err := c.Resolve(ctx, name); done <- err }()
		<-entered
		cancel()
		if err := <-done; !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	}
	for range 20 {
		if _, err := c.Resolve(context.Background(), "other.eth"); !errors.Is(err, ErrBusy) {
			t.Fatalf("overload: %v", err)
		}
	}
	// Existing shared work remains joinable even when all work slots are full.
	done := make(chan error, 1)
	go func() { _, err := c.Resolve(context.Background(), "one.eth"); done <- err }()
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 2 {
		t.Fatalf("started %d resolutions with limit 2", calls.Load())
	}
}

func TestCacheCloseCancelsDetachedWork(t *testing.T) {
	entered, stopped := make(chan struct{}), make(chan struct{})
	c := NewCached(resolverFunc(func(ctx context.Context, _ string) (content.Target, error) {
		close(entered)
		<-ctx.Done()
		close(stopped)
		return content.Target{}, ctx.Err()
	}), 2, time.Minute, time.Second, time.Minute, 1)
	t.Cleanup(c.Close)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { _, err := c.Resolve(ctx, "one.eth"); done <- err }()
	<-entered
	cancel()
	<-done
	c.Close()
	select {
	case <-stopped:
	case <-time.After(time.Second):
		t.Fatal("shutdown did not cancel shared work")
	}
	if _, err := c.Resolve(context.Background(), "two.eth"); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}
