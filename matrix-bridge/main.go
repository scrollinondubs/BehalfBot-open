// matrix-bridge: Jill's end-to-end encrypted Matrix chat bridge.
//
//	matrix-bridge run     sync, decrypt, accept or drop, hand accepted
//	                      messages to the Python worker, encrypt replies
//	matrix-bridge setup   interactive, once: login, cross-signing, emoji
//	                      verification of the principal, pin
//	matrix-bridge setup --no-sas
//	                      fallback: pin after a typed fingerprint check
//	matrix-bridge status  pin, login and identity lock, for the host
//	matrix-bridge isolation-check
//	                      proves the worker uid cannot read the bridge state
//
// The homeserver is run by someone else, so nothing here trusts it: every
// accepted message must decrypt, come from the principal, and come from a
// device cross-signed by the master key pinned at setup. See
// bridge/WIRING.md.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func nowUnix() int64 { return time.Now().Unix() }

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: matrix-bridge run|setup|status|isolation-check")
		os.Exit(64)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	cfg, problems := LoadConfig()
	if len(problems) > 0 {
		for _, p := range problems {
			logf("ERROR: %s", p)
		}
		os.Exit(78)
	}
	switch os.Args[1] {
	case "setup":
		cfg.NoSAS = len(os.Args) > 2 && os.Args[2] == "--no-sas"
		tty, err := openTTY()
		if err != nil {
			logf("ERROR: %v", err)
			os.Exit(1)
		}
		if err := Setup(ctx, cfg, tty); err != nil {
			tty.Say("SETUP FAILED: " + err.Error())
			os.Exit(1)
		}
	case "run":
		if err := Run(ctx, cfg); err != nil && ctx.Err() == nil {
			logf("ERROR: %v", err)
			// Stay up and unhealthy rather than restart-loop against the
			// homeserver.
			<-ctx.Done()
			os.Exit(1)
		}
	case "status":
		if err := Status(cfg); err != nil {
			os.Exit(2)
		}
	case "isolation-check":
		if err := IsolationCheck(ctx, cfg); err != nil {
			logf("ISOLATION CHECK FAILED: %v", err)
			os.Exit(1)
		}
		logf("isolation check passed: the worker cannot read the bridge state")
	default:
		fmt.Fprintln(os.Stderr, "usage: matrix-bridge run|setup|status|isolation-check")
		os.Exit(64)
	}
}
