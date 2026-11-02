package resolve

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"dwebproxy/internal/content"
)

type resolverFunc func(context.Context, string) (content.Target, error)

func (f resolverFunc) Resolve(ctx context.Context, n string) (content.Target, error) {
	return f(ctx, n)
}

func TestCacheDeduplicatesAndSeparatesCancellation(t *testing.T) {
	var calls atomic.Int32
	entered, release := make(chan struct{}), make(chan struct{})
	r := resolverFunc(func(ctx context.Context, _ string) (content.Target, error) {
		calls.Add(1)
		close(entered)
		select {
		case <-release:
			return content.Target{Kind: content.IPFS, ID: "root"}, nil
		case <-ctx.Done():
			return content.Target{}, ctx.Err()
		}
	})
	c := NewCached(r, 10, time.Minute, time.Second, time.Second)
	ctx, cancel := context.WithCancel(context.Background())
	first := make(chan error, 1)
	go func() { _, err := c.Resolve(ctx, "EXAMPLE.eth"); first <- err }()
	<-entered
	var wg sync.WaitGroup
	for range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := c.Resolve(context.Background(), "example.eth")
			if err != nil {
				t.Error(err)
			}
		}()
	}
	cancel()
	if !errors.Is(<-first, context.Canceled) {
		t.Fatal("first waiter did not cancel")
	}
	close(release)
	wg.Wait()
	if calls.Load() != 1 {
		t.Fatalf("upstream calls=%d", calls.Load())
	}
}

func TestOnlyMissingRecordsAreNegativeCached(t *testing.T) {
	for _, tc := range []struct {
		err  error
		want int
	}{{ErrNotFound, 1}, {errors.New("RPC failed"), 2}, {ErrStale, 2}} {
		calls := 0
		r := resolverFunc(func(context.Context, string) (content.Target, error) { calls++; return content.Target{}, tc.err })
		c := NewCached(r, 2, time.Second, time.Second, time.Second)
		for range 2 {
			_, _ = c.Resolve(context.Background(), "example.sns")
		}
		if calls != tc.want {
			t.Fatalf("%v cached incorrectly: %d", tc.err, calls)
		}
	}
}

func TestNormalizeScope(t *testing.T) {
	for _, s := range []string{"alice.sol", "alice.sns.evil", "a.b.c.sns", "a..sns", "a_.ton", "xn--invalid-.sns"} {
		if _, err := Normalize(s); err == nil {
			t.Errorf("accepted %s", s)
		}
	}
	for _, s := range []string{"Alice.ETH.", "sub.alice.sns", "alice.ton"} {
		if _, err := Normalize(s); err != nil {
			t.Errorf("%s: %v", s, err)
		}
	}
}

func TestCacheExpiresAndEvicts(t *testing.T) {
	var calls atomic.Int32
	r := resolverFunc(func(context.Context, string) (content.Target, error) {
		calls.Add(1)
		return content.Target{Kind: content.IPFS, ID: "root"}, nil
	})
	c := NewCached(r, 1, 20*time.Millisecond, time.Second, time.Second)
	for _, n := range []string{"alice.eth", "alice.eth", "bob.eth", "alice.eth"} {
		if _, err := c.Resolve(context.Background(), n); err != nil {
			t.Fatal(err)
		}
	}
	if calls.Load() != 3 {
		t.Fatalf("LRU calls=%d", calls.Load())
	}
	time.Sleep(30 * time.Millisecond)
	if _, err := c.Resolve(context.Background(), "alice.eth"); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 4 {
		t.Fatalf("expired result was served: %d", calls.Load())
	}
}
