package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"dwebproxy/internal/certstore"
	"dwebproxy/internal/config"
	"dwebproxy/internal/netutil"
	"dwebproxy/internal/proxy"
	"dwebproxy/internal/resolve"
)

func main() {
	if err := run(); err != nil {
		slog.Error("dwebproxy stopped", "error", err)
		os.Exit(1)
	}
}

func run() error {
	path := flag.String("config", "", "JSON config file (omit to use defaults)")
	printConfig := flag.Bool("print-config", false, "print the effective JSON configuration and exit")
	check := flag.Bool("check", false, "validate configuration and exit without contacting upstreams")
	initCA := flag.Bool("init-ca", false, "create a private local Web3 CA and exit; never installs it")
	flag.Parse()
	c, err := config.Load(*path)
	if err != nil {
		return err
	}
	if *initCA {
		if err := certstore.Init(c.HTTPS.CACert, c.HTTPS.CAKey); err != nil {
			return err
		}
		fmt.Printf("CA created. Import only this certificate into your browser or OS trust store:\n%s\nKeep the CA private key private. No trust store was modified.\n", c.HTTPS.CACert)
		return nil
	}
	if *printConfig {
		b, err := json.MarshalIndent(c, "", "  ")
		if err != nil {
			return err
		}
		fmt.Println(string(b))
		return nil
	}
	if *check {
		if c.HTTPS.Enabled {
			if _, err := certstore.Load(c.HTTPS.CACert, c.HTTPS.CAKey, c.CacheSize); err != nil {
				return err
			}
		}
		fmt.Println("configuration valid")
		return nil
	}
	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	timeout := time.Duration(c.ResolveTimeout)
	rpcClient := netutil.Client(timeout)
	defer rpcClient.CloseIdleConnections()
	ccipClient := netutil.CCIPClient(c.CCIPRead, timeout)
	defer ccipClient.CloseIdleConnections()
	ens, err := resolve.NewENS(c.EthereumRPC, rpcClient, ccipClient)
	if err != nil {
		return err
	}
	defer ens.Close()
	sns := resolve.NewSNS(c.SolanaRPC, rpcClient)
	resolver := resolve.NewCached(resolve.BySuffix{ENS: ens, SNS: sns}, c.CacheSize, time.Duration(c.CacheTTL), time.Duration(c.NegativeCacheTTL), timeout)
	h, err := proxy.New(c, resolver, logger)
	if err != nil {
		return err
	}
	defer h.Close()
	server := &http.Server{Addr: c.Listen, Handler: h, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 64 << 10}
	server.Protocols = new(http.Protocols)
	server.Protocols.SetHTTP1(true)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	done := make(chan error, 1)
	go func() { done <- server.ListenAndServe() }()
	logger.Info("HTTP proxy listening", "address", c.Listen, "ton_enabled", c.TONProxy != "", "fallback_enabled", c.FallbackProxy != "", "https_enabled", c.HTTPS.Enabled)
	select {
	case err := <-done:
		if err == http.ErrServerClosed {
			return nil
		}
		return err
	case <-ctx.Done():
		h.Close() // net/http Shutdown does not own hijacked CONNECT sessions
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdown); err != nil {
			server.Close()
			return err
		}
		return nil
	}
}
