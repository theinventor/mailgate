package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"golang.org/x/net/netutil"
	"mailgate/internal/gateway"
)

var version = "dev"

const usage = `mailgate: private Gmail access for agents

Usage: mailgate [--config /etc/mailgate/config.json] COMMAND [flags]

  init           Create a new configuration file (does not overwrite)
  serve          Run the API and durable alert workers
  check          Check configuration, credentials, database, and GOG version
  tokens create  Issue a token with explicit permissions; printed only once
  tokens list    List token metadata (never plaintext tokens)
  tokens revoke  Revoke a token immediately
  audit          Show recent audit events
  alerts         Show pending alerts; 'alerts test' queues an owner test
  sends          Show pending/uncertain sends needing owner review
  backup         Create a consistent private SQLite backup
  maintain       Apply explicitly chosen audit retention and prune stale counters
  version        Print version and supported GOG version

Open /admin/ on the configured HTTPS origin to initialize the owner's password
on first visit and manage tokens. No SSH password setup is required.
`

func main() {
	syscall.Umask(0077)
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "mailgate:", err)
		os.Exit(1)
	}
}

func output(w io.Writer, v any) error {
	e := json.NewEncoder(w)
	e.SetIndent("", "  ")
	return e.Encode(v)
}
func flags(name string, w io.Writer) *flag.FlagSet {
	f := flag.NewFlagSet(name, flag.ContinueOnError)
	f.SetOutput(w)
	return f
}

func run(args []string, out, errOut io.Writer) error {
	global := flags("mailgate", errOut)
	configPath := global.String("config", "/etc/mailgate/config.json", "configuration file")
	global.Usage = func() { fmt.Fprint(errOut, usage) }
	if err := global.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	args = global.Args()
	if len(args) == 0 {
		fmt.Fprint(out, usage)
		return nil
	}
	command, args := args[0], args[1:]
	if command == "version" {
		return output(out, map[string]string{"version": version, "tested_gog": gateway.TestedGOGVersion, "required_gog_build": gateway.RequiredGOGBuild})
	}
	if command == "init" {
		return initConfig(*configPath, args, out, errOut)
	}
	c, err := gateway.LoadConfig(*configPath)
	if err != nil {
		return err
	}
	s, err := gateway.OpenStore(c.StateDir)
	if err != nil {
		return err
	}
	defer s.Close()
	ctx := context.Background()
	switch command {
	case "serve", "check":
		if len(args) != 0 {
			return errors.New("unexpected arguments")
		}
		secrets, err := c.LoadSecrets()
		if err != nil {
			return err
		}
		gog := gateway.NewGOG(c, secrets)
		if err := gog.Verify(ctx); err != nil {
			return err
		}
		if command == "check" {
			return output(out, map[string]any{"configuration": "ok", "gog_version": gateway.TestedGOGVersion, "google_authorization": "not contacted", "notifications": "not sent"})
		}
		return serve(c, s, gog, secrets, errOut)
	case "tokens":
		return tokens(ctx, s, args, out, errOut)
	case "audit":
		f := flags("audit", errOut)
		limit := f.Int("limit", 50, "number of recent events (1–1000)")
		if err := f.Parse(args); err != nil {
			return err
		}
		if f.NArg() != 0 {
			return errors.New("unexpected arguments")
		}
		events, err := s.Events(ctx, *limit)
		if err != nil {
			return err
		}
		return output(out, events)
	case "alerts":
		if len(args) == 1 && args[0] == "test" {
			secrets, err := c.LoadSecrets()
			if err != nil {
				return err
			}
			n := gateway.NewNotifier(secrets, nil)
			if len(n.Channels()) == 0 {
				return errors.New("no alert channels configured")
			}
			if err := s.Record(ctx, gateway.Event{Action: "owner.alert_test", TokenID: "owner", RequestID: "owner-test"}, n.Channels(), "owner_test"); err != nil {
				return err
			}
			return output(out, map[string]any{"queued": true, "channels": n.Channels(), "note": "the running service delivers these jobs"})
		}
		if len(args) != 0 {
			return errors.New("usage: alerts [test]")
		}
		jobs := []gateway.AlertJob{}
		for _, channel := range []string{"pushover", "brrr"} {
			j, err := s.DueAlerts(ctx, channel, 1<<62)
			if err != nil {
				return err
			}
			jobs = append(jobs, j...)
		}
		return output(out, jobs)
	case "sends":
		if len(args) != 0 {
			return errors.New("unexpected arguments")
		}
		pending, err := s.PendingSends(ctx)
		if err != nil {
			return err
		}
		return output(out, pending)
	case "backup":
		f := flags("backup", errOut)
		path := f.String("output", "", "new absolute destination path")
		if err := f.Parse(args); err != nil {
			return err
		}
		if f.NArg() != 0 || *path == "" {
			return errors.New("--output is required")
		}
		if err := s.Backup(ctx, *path); err != nil {
			return err
		}
		return output(out, map[string]string{"backup": *path})
	case "maintain":
		f := flags("maintain", errOut)
		days := f.Int("audit-days", 90, "delete audit events older than this many days (minimum 7)")
		if err := f.Parse(args); err != nil {
			return err
		}
		if f.NArg() != 0 {
			return errors.New("unexpected arguments")
		}
		if err := s.Maintain(ctx, *days); err != nil {
			return err
		}
		return output(out, map[string]any{"audit_retention_days": *days, "completed": true})
	default:
		return errors.New("unknown command; use --help")
	}
}

func initConfig(path string, args []string, out, errOut io.Writer) error {
	c := gateway.DefaultConfig()
	f := flags("init", errOut)
	account := f.String("account", "", "Google account authorized in GOG")
	owner := f.String("owner", "", "address to receive required copies (defaults to account)")
	state := f.String("state-dir", c.StateDir, "absolute state directory")
	secretDir := f.String("secret-dir", c.SecretDir, "absolute credential directory")
	gogPath := f.String("gog-path", c.GOGPath, "absolute GOG executable path")
	client := f.String("gog-client", c.GOGClient, "GOG OAuth client name")
	adminOrigin := f.String("admin-origin", "", "HTTPS origin for the owner admin interface")
	listen := f.String("listen", c.Listen, "loopback API listener")
	adminListen := f.String("admin-listen", c.AdminListen, "separate loopback admin listener")
	if err := f.Parse(args); err != nil {
		return err
	}
	if f.NArg() != 0 {
		return errors.New("unexpected arguments")
	}
	c.GOGAccount = *account
	c.OwnerEmail = *owner
	if c.OwnerEmail == "" {
		c.OwnerEmail = c.GOGAccount
	}
	c.StateDir = *state
	c.GOGHome = filepath.Join(*state, "gog")
	c.SecretDir = *secretDir
	c.GOGPath = *gogPath
	c.GOGClient = *client
	c.AdminOrigin = *adminOrigin
	c.Listen, c.AdminListen = *listen, *adminListen
	if err := c.Validate(); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0750); err != nil {
		return err
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	if err = output(file, c); err != nil {
		file.Close()
		return err
	}
	if err = file.Close(); err != nil {
		return err
	}
	return output(out, map[string]string{"config": path, "next": "install private credentials and authorize GOG on the dedicated host; see docs/deployment.md"})
}

func split(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}
	return parts
}

func tokens(ctx context.Context, s *gateway.Store, args []string, out, errOut io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: tokens create|list|revoke")
	}
	switch args[0] {
	case "list":
		if len(args) != 1 {
			return errors.New("unexpected arguments")
		}
		list, err := s.Tokens(ctx)
		if err != nil {
			return err
		}
		return output(out, list)
	case "revoke":
		f := flags("tokens revoke", errOut)
		id := f.String("id", "", "token ID, not its secret")
		if err := f.Parse(args[1:]); err != nil {
			return err
		}
		if *id == "" || f.NArg() != 0 {
			return errors.New("--id is required")
		}
		if err := s.Revoke(ctx, *id); err != nil {
			return err
		}
		return output(out, map[string]string{"revoked": *id})
	case "create":
		p := gateway.DefaultTokenPolicy()
		f := flags("tokens create", errOut)
		name := f.String("name", "", "human-readable agent name")
		scopes := f.String("scopes", "mail.search,mail.read", "comma-separated mail.search,mail.read,mail.send")
		expires := f.Duration("expires-in", 30*24*time.Hour, "token lifetime, e.g. 720h")
		f.IntVar(&p.RequestsPerMinute, "requests-per-minute", p.RequestsPerMinute, "request limit per minute")
		f.IntVar(&p.ReadsPerDay, "reads-per-day", p.ReadsPerDay, "messages inspected per UTC day, including search candidates")
		f.IntVar(&p.SendsPerDay, "sends-per-day", p.SendsPerDay, "send attempts per UTC day")
		f.StringVar(&p.CopyOwner, "copy-owner", p.CopyOwner, "cc, bcc, or none")
		labels := f.String("allow-label-ids", "", "optional comma-separated Gmail label IDs")
		senders := f.String("allow-senders", "", "optional comma-separated exact sender addresses")
		recipients := f.String("allow-recipients", "", "optional comma-separated exact recipient addresses")
		if err := f.Parse(args[1:]); err != nil {
			return err
		}
		if f.NArg() != 0 {
			return errors.New("unexpected arguments")
		}
		p.Scopes = split(*scopes)
		p.AllowedLabelIDs = split(*labels)
		p.AllowedSenders = split(*senders)
		p.AllowedRecipients = split(*recipients)
		t, raw, err := s.CreateToken(ctx, *name, p, time.Now().Add(*expires))
		if err != nil {
			return err
		}
		return output(out, map[string]any{"token": raw, "metadata": t, "notice": "Save this token now. It is not stored in recoverable form."})
	default:
		return errors.New("usage: tokens create|list|revoke")
	}
}

func serve(c gateway.Config, s *gateway.Store, b gateway.Backend, secrets gateway.Secrets, errOut io.Writer) error {
	lock, err := os.OpenFile(filepath.Join(c.StateDir, "server.lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return err
	}
	defer lock.Close()
	if err = syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return errors.New("another mailgate server is using this state directory")
	}
	defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
	logger := slog.New(slog.NewJSONHandler(errOut, nil))
	notifier := gateway.NewNotifier(secrets, logger)
	api := gateway.NewAPI(c, s, b, notifier.Channels(), logger)
	server := api.HTTPServer()
	listener, err := net.Listen("tcp", c.Listen)
	if err != nil {
		return err
	}
	defer listener.Close()
	var adminServer *http.Server
	var adminListener net.Listener
	if c.AdminOrigin != "" {
		adminServer = api.AdminHTTPServer()
		adminListener, err = net.Listen("tcp", c.AdminListen)
		if err != nil {
			return err
		}
		defer adminListener.Close()
	}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()
	workerDone := make(chan struct{})
	go func() { defer close(workerDone); notifier.Run(ctx, s) }()
	serverErr := make(chan error, 2)
	go func() { serverErr <- server.Serve(netutil.LimitListener(listener, 64)) }()
	if adminServer != nil {
		go func() { serverErr <- adminServer.Serve(netutil.LimitListener(adminListener, 16)) }()
	}
	logger.Info("mailgate listening", "address", c.Listen, "alert_channels", notifier.Channels(), "version", version)
	select {
	case <-ctx.Done():
	case err = <-serverErr:
		cancel()
	}
	shutdownCtx, stop := context.WithTimeout(context.Background(), time.Duration(c.RequestTimeoutSeconds+5)*time.Second)
	defer stop()
	if shutdownErr := server.Shutdown(shutdownCtx); shutdownErr != nil {
		_ = server.Close()
	}
	if adminServer != nil {
		if adminServer.Shutdown(shutdownCtx) != nil {
			_ = adminServer.Close()
		}
	}
	cancel()
	<-workerDone
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}
