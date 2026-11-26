package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
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
	programProxy, err := c.ProgramProxy.Endpoint()
	if err != nil {
		return err
	}
	dial, err := netutil.NewDialer(programProxy)
	if err != nil {
		return err
	}
	rpcClient := netutil.Client(timeout, dial)
	defer rpcClient.CloseIdleConnections()
	ccipClient := netutil.CCIPClient(c.CCIPRead, timeout, dial)
	defer ccipClient.CloseIdleConnections()
	ens, err := resolve.NewENS(c.EthereumRPC, rpcClient, ccipClient, c.RecordPriority.ENS)
	if err != nil {
		return err
	}
	defer ens.Close()
	sns, err := resolve.NewSNS(c.SolanaRPC, rpcClient, c.RecordPriority.SNS)
	if err != nil {
		return err
	}
	resolver := resolve.NewCached(resolve.BySuffix{ENS: ens, SNS: sns}, c.CacheSize, time.Duration(c.CacheTTL), time.Duration(c.NegativeCacheTTL), timeout, c.MaxConcurrent)
	defer resolver.Close()
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
	listener, err := net.Listen("tcp", c.Listen)
	if err != nil {
		return err
	}
	defer listener.Close()
	done := make(chan error, 1)
	go func() {
		if c.ListenProtocol == "socks5" {
			done <- h.ServeSOCKS5(listener)
		} else {
			done <- server.Serve(listener)
		}
	}()
	logger.Info("proxy listening", "protocol", c.ListenProtocol, "address", c.Listen, "ton_enabled", c.TONProxy != "", "fallback_enabled", c.FallbackProxy != "", "web3_https_enabled", c.HTTPS.Enabled, "program_proxy_enabled", c.ProgramProxy.Enabled)
	select {
	case err := <-done:
		if errors.Is(err, http.ErrServerClosed) || errors.Is(err, net.ErrClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		listener.Close()
		resolver.Close()
		h.Close() // net/http Shutdown does not own hijacked CONNECT sessions
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdown); err != nil {
			server.Close()
			return err
		}
		if c.ListenProtocol == "socks5" {
			select {
			case err := <-done:
				if !errors.Is(err, net.ErrClosed) {
					return err
				}
			case <-shutdown.Done():
				return shutdown.Err()
			}
		}
		return nil
	}
}
