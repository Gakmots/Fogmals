package resolve

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"dwebproxy/internal/content"
	"dwebproxy/internal/netutil"
	ens "github.com/ensdomains/go-ens/v4"
	"github.com/hashicorp/golang-lru/v2/expirable"
	"golang.org/x/sync/singleflight"
)

var (
	ErrNotFound    = errors.New("name or content record not found")
	ErrInvalid     = errors.New("invalid domain name")
	ErrUnavailable = errors.New("resolver not configured")
	ErrStale       = errors.New("SNS V2 record is stale or unverified")
	ErrBusy        = errors.New("too many concurrent resolutions")
)

type Resolver interface {
	Resolve(context.Context, string) (content.Target, error)
}

// Normalize is chain-specific. Browser IDNA decoding is intentionally not
// applied globally: ENSIP-15 is not IDNA and does not decode punycode.
func Normalize(name string) (string, error) {
	name = strings.TrimSuffix(strings.ToLower(name), ".")
	if strings.HasSuffix(name, ".eth") {
		n, err := ens.Normalize(name)
		if err != nil {
			return "", fmt.Errorf("%w: %v", ErrInvalid, err)
		}
		return n, nil
	}
	if strings.HasSuffix(name, ".sns") || strings.HasSuffix(name, ".ton") {
		if !netutil.ValidASCIIHostname(name) {
			return "", ErrInvalid
		}
		if strings.HasSuffix(name, ".sns") && strings.Count(name, ".") > 2 {
			return "", fmt.Errorf("%w: SNS supports one subdomain level", ErrInvalid)
		}
		return name, nil
	}
	return "", ErrInvalid
}

type result struct {
	target content.Target
	err    error
}

type Cached struct {
	resolver Resolver
	positive *expirable.LRU[string, result]
	negative *expirable.LRU[string, result]
	timeout  time.Duration
	group    singleflight.Group
	root     context.Context
	cancel   context.CancelFunc
	slots    chan struct{}
}

func NewCached(r Resolver, size int, ttl, negativeTTL, timeout time.Duration, maxConcurrent int) *Cached {
	root, cancel := context.WithCancel(context.Background())
	return &Cached{resolver: r, positive: expirable.NewLRU[string, result](size, nil, ttl), negative: expirable.NewLRU[string, result](size, nil, negativeTTL), timeout: timeout, root: root, cancel: cancel, slots: make(chan struct{}, maxConcurrent)}
}

// Close cancels shared work, including work whose original caller has left.
func (c *Cached) Close() { c.cancel() }

func (c *Cached) lookup(name string) (result, bool) {
	if v, ok := c.positive.Get(name); ok {
		return v, true
	}
	return c.negative.Get(name)
}

func (c *Cached) Resolve(ctx context.Context, name string) (content.Target, error) {
	if err := ctx.Err(); err != nil {
		return content.Target{}, err
	}
	if err := c.root.Err(); err != nil {
		return content.Target{}, err
	}
	n, err := Normalize(name)
	if err != nil {
		return content.Target{}, err
	}
	if v, ok := c.lookup(n); ok {
		return v.target, v.err
	}
	ch := c.group.DoChan(n, func() (any, error) {
		if v, ok := c.lookup(n); ok {
			return v, nil
		}
		// Admission belongs to the work, not to any browser waiter. Reject
		// overload instead of accumulating a queue of detached goroutines.
		select {
		case c.slots <- struct{}{}:
			defer func() { <-c.slots }()
		default:
			return nil, ErrBusy
		}
		// Shared work survives an individual waiter but not process shutdown.
		work, cancel := context.WithTimeout(c.root, c.timeout)
		defer cancel()
		if err := work.Err(); err != nil {
			return nil, err
		}
		t, err := c.resolver.Resolve(work, n)
		v := result{t, err}
		if err == nil {
			c.positive.Add(n, v)
		} else if errors.Is(err, ErrNotFound) {
			c.negative.Add(n, v)
		}
		return v, nil
	})
	select {
	case <-ctx.Done():
		return content.Target{}, ctx.Err()
	case <-c.root.Done():
		return content.Target{}, c.root.Err()
	case answer := <-ch:
		if answer.Err != nil {
			return content.Target{}, answer.Err
		}
		v := answer.Val.(result)
		return v.target, v.err
	}
}

type BySuffix struct{ ENS, SNS Resolver }

func (r BySuffix) Resolve(ctx context.Context, name string) (content.Target, error) {
	var next Resolver
	switch {
	case strings.HasSuffix(name, ".eth"):
		next = r.ENS
	case strings.HasSuffix(name, ".sns"):
		next = r.SNS
	}
	if next == nil {
		return content.Target{}, ErrUnavailable
	}
	return next.Resolve(ctx, name)
}
