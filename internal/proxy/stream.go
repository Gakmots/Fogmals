package proxy

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptrace"
	"sync"
	"time"
)

var errStreamIdle = fmt.Errorf("stream idle timeout: %w", context.DeadlineExceeded)

// A request owns its watchdog. Neither context cancellation nor HTTP/2 stream
// deadlines close a connection shared by other requests. Header waiting keeps
// the Transport's separate ResponseHeaderTimeout.
func streamRequest(w http.ResponseWriter, r *http.Request, idle time.Duration) (http.ResponseWriter, *http.Request, func()) {
	ctx, cancel := context.WithCancelCause(r.Context())
	controller := http.NewResponseController(w)
	g := &streamGuard{idle: idle, cancel: cancel, controller: controller, uploading: r.Body != nil && r.Body != http.NoBody && r.ContentLength != 0}
	ctx = httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{WroteRequest: func(info httptrace.WroteRequestInfo) {
		if info.Err == nil {
			g.mu.Lock()
			defer g.mu.Unlock()
			if g.closed {
				return
			}
			controller.SetReadDeadline(time.Time{})
			g.uploading = false
			if !g.responding && g.timer != nil {
				g.timer.Stop()
			}
		}
	}})
	r = r.Clone(ctx)
	if g.uploading {
		// Let the progress watchdog own upload timing instead of racing the
		// server's read deadline (which cancels the parent context first).
		controller.SetReadDeadline(time.Time{})
		r.Body = &streamBody{ReadCloser: r.Body, guard: g}
		g.touch()
	}
	writer := &streamWriter{ResponseWriter: w, guard: g, controller: controller}
	return writer, r, func() {
		g.mu.Lock()
		expired := g.closed
		g.closed = true
		if g.timer != nil {
			g.timer.Stop()
		}
		g.mu.Unlock()
		cancel(nil)
		// Clear normal-session deadlines. Keep an aborted body read expired so
		// it cannot resume blocking during HTTP server cleanup.
		if !expired {
			controller.SetReadDeadline(time.Time{})
		}
		controller.SetWriteDeadline(time.Time{})
	}
}

type streamGuard struct {
	mu                    sync.Mutex
	idle                  time.Duration
	cancel                context.CancelCauseFunc
	controller            *http.ResponseController
	timer                 *time.Timer
	last                  time.Time
	uploading, responding bool
	closed                bool
}

func (g *streamGuard) touch() {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closed || (!g.uploading && !g.responding) {
		return
	}
	g.last = time.Now()
	if g.timer == nil {
		g.timer = time.AfterFunc(g.idle, g.expire)
	} else {
		g.timer.Reset(g.idle)
	}
}

func (g *streamGuard) expire() {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closed || (!g.uploading && !g.responding) {
		return
	}
	// Reset may race a callback which has already started. Always check the
	// most recent activity before expiring a stream.
	if remaining := g.idle - time.Since(g.last); remaining > 0 {
		g.timer.Reset(remaining)
		return
	}
	g.closed = true
	g.cancel(errStreamIdle)
	if g.uploading {
		// Record the timeout before unblocking a request-body Read. net/http
		// may cancel the incoming parent context when that Read times out.
		g.controller.SetReadDeadline(time.Now())
	}
}

type streamBody struct {
	io.ReadCloser
	guard *streamGuard
}

func (b *streamBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	if n > 0 {
		b.guard.touch()
	}
	return n, err
}

type streamWriter struct {
	http.ResponseWriter
	guard      *streamGuard
	controller *http.ResponseController
}

func (w *streamWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func (w *streamWriter) WriteHeader(status int) {
	if status >= 200 {
		w.guard.mu.Lock()
		w.guard.responding = true
		w.guard.mu.Unlock()
		w.guard.touch()
	}
	w.controller.SetWriteDeadline(time.Now().Add(w.guard.idle))
	w.ResponseWriter.WriteHeader(status)
	w.controller.SetWriteDeadline(time.Time{})
}

func (w *streamWriter) Write(p []byte) (int, error) {
	w.controller.SetWriteDeadline(time.Now().Add(w.guard.idle))
	n, err := w.ResponseWriter.Write(p)
	if n > 0 {
		w.guard.touch()
	}
	w.controller.SetWriteDeadline(time.Time{})
	return n, err
}

func (w *streamWriter) Flush() { _ = w.FlushError() }

func (w *streamWriter) FlushError() error {
	w.controller.SetWriteDeadline(time.Now().Add(w.guard.idle))
	err := w.controller.Flush()
	if err == nil {
		w.guard.touch()
	}
	w.controller.SetWriteDeadline(time.Time{})
	return err
}
