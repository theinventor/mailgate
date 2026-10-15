package gateway

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

type Config struct {
	Listen                  string   `json:"listen"`
	AdminListen             string   `json:"admin_listen"`
	StateDir                string   `json:"state_dir"`
	GOGPath                 string   `json:"gog_path"`
	GOGHome                 string   `json:"gog_home"`
	GOGAccount              string   `json:"gog_account"`
	GOGClient               string   `json:"gog_client"`
	OwnerEmail              string   `json:"owner_email"`
	AdminOrigin             string   `json:"admin_origin"`
	SecretDir               string   `json:"secret_dir"`
	RequireAlerts           bool     `json:"require_alerts"`
	MaxConcurrentRequests   int      `json:"max_concurrent_requests"`
	MaxConcurrentGOG        int      `json:"max_concurrent_gog"`
	GlobalRequestsPerMinute int      `json:"global_requests_per_minute"`
	MaxSearchResults        int      `json:"max_search_results"`
	RequestTimeoutSeconds   int      `json:"request_timeout_seconds"`
	GOGTimeoutSeconds       int      `json:"gog_timeout_seconds"`
	MaxGOGOutputBytes       int      `json:"max_gog_output_bytes"`
	BlockedLabelIDs         []string `json:"blocked_label_ids"`
	SensitiveKeywords       []string `json:"sensitive_keywords"`
}

func DefaultConfig() Config {
	return Config{Listen: "127.0.0.1:8787", AdminListen: "127.0.0.1:8788", StateDir: "/var/lib/mailgate", GOGPath: "/usr/local/bin/gog", GOGHome: "/var/lib/mailgate/gog", GOGClient: "default", SecretDir: "/etc/mailgate/secrets", RequireAlerts: true, MaxConcurrentRequests: 8, MaxConcurrentGOG: 2, GlobalRequestsPerMinute: 120, MaxSearchResults: 20, RequestTimeoutSeconds: 90, GOGTimeoutSeconds: 20, MaxGOGOutputBytes: 2 << 20, BlockedLabelIDs: []string{}, SensitiveKeywords: []string{}}
}

func LoadConfig(path string) (Config, error) {
	c := DefaultConfig()
	f, err := os.Open(path)
	if err != nil {
		return c, err
	}
	defer f.Close()
	d := json.NewDecoder(io.LimitReader(f, 65537))
	d.DisallowUnknownFields()
	if err := d.Decode(&c); err != nil {
		return c, fmt.Errorf("config: %w", err)
	}
	if err := d.Decode(new(any)); err != io.EOF {
		return c, errors.New("config must contain exactly one JSON object")
	}
	return c, c.Validate()
}

func (c Config) Validate() error {
	if c.AdminOrigin != "" {
		u, err := url.Parse(c.AdminOrigin)
		if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" || u.String() != c.AdminOrigin {
			return errors.New("admin_origin must be an HTTPS origin without a path, such as https://mailgate.example.ts.net")
		}
	}
	for _, address := range []string{c.Listen, c.AdminListen} {
		host, port, err := net.SplitHostPort(address)
		if err != nil || (host != "127.0.0.1" && host != "::1") || port == "" || port == "0" {
			return errors.New("listeners must use a literal loopback IP and nonzero port; expose HTTPS through Tailscale Serve")
		}
	}
	if c.Listen == c.AdminListen {
		return errors.New("API and admin listeners must use separate ports")
	}
	for _, p := range []string{c.StateDir, c.GOGPath, c.GOGHome, c.SecretDir} {
		if !filepath.IsAbs(p) {
			return errors.New("state, GOG, and secret paths must be absolute")
		}
	}
	if _, err := CanonicalAddress(c.OwnerEmail); err != nil {
		return errors.New("owner_email must be a bare email address")
	}
	if _, err := CanonicalAddress(c.GOGAccount); err != nil {
		return errors.New("gog_account must be a bare email address")
	}
	if c.GOGClient == "" || len(c.GOGClient) > 100 || strings.ContainsAny(c.GOGClient, "\x00\r\n") {
		return errors.New("invalid gog_client")
	}
	if c.MaxConcurrentRequests < 1 || c.MaxConcurrentRequests > 64 || c.MaxConcurrentGOG < 1 || c.MaxConcurrentGOG > 8 || c.MaxConcurrentGOG > c.MaxConcurrentRequests {
		return errors.New("invalid concurrency limits")
	}
	if c.GlobalRequestsPerMinute < 1 || c.GlobalRequestsPerMinute > 10000 || c.MaxSearchResults < 1 || c.MaxSearchResults > 50 {
		return errors.New("invalid request limits")
	}
	if c.GOGTimeoutSeconds < 1 || c.GOGTimeoutSeconds > 60 || c.RequestTimeoutSeconds < c.GOGTimeoutSeconds || c.RequestTimeoutSeconds > 300 {
		return errors.New("invalid request timeouts")
	}
	if c.MaxGOGOutputBytes < 65536 || c.MaxGOGOutputBytes > 8<<20 {
		return errors.New("max_gog_output_bytes must be between 64 KiB and 8 MiB")
	}
	if len(c.SensitiveKeywords) > 100 || len(c.BlockedLabelIDs) > 100 {
		return errors.New("too many policy rules")
	}
	for _, word := range c.SensitiveKeywords {
		if strings.TrimSpace(word) == "" || len(word) > 256 {
			return errors.New("invalid sensitive keyword")
		}
	}
	return nil
}

type Secrets struct{ GOGPassword, PushoverToken, PushoverUser, BRRRKey string }

func (c Config) LoadSecrets() (Secrets, error) {
	dir := c.SecretDir
	managed := false
	if p := os.Getenv("CREDENTIALS_DIRECTORY"); p != "" {
		dir = p
		managed = true
	}
	read := func(name string) (string, error) {
		p := filepath.Join(dir, name)
		f, err := os.Open(p)
		if errors.Is(err, os.ErrNotExist) {
			return "", nil
		}
		if err != nil {
			return "", fmt.Errorf("cannot read credential %s", name)
		}
		defer f.Close()
		info, err := f.Stat()
		forbidden := os.FileMode(0077)
		if managed {
			// systemd may present credentials as 0440 inside a private mount with
			// a service-specific ACL. Its credential directory is the boundary.
			forbidden = 0037
		}
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&forbidden != 0 {
			return "", fmt.Errorf("credential %s has unsafe permissions or is not a regular file", name)
		}
		b, err := io.ReadAll(io.LimitReader(f, 4097))
		if err != nil || len(b) > 4096 {
			return "", fmt.Errorf("invalid credential %s", name)
		}
		v := strings.TrimSuffix(strings.TrimSuffix(string(b), "\n"), "\r")
		if strings.ContainsAny(v, "\r\n\x00") {
			return "", fmt.Errorf("invalid credential %s", name)
		}
		return v, nil
	}
	var s Secrets
	for name, target := range map[string]*string{"gog-keyring-password": &s.GOGPassword, "pushover-app-token": &s.PushoverToken, "pushover-user-key": &s.PushoverUser, "brrr-key": &s.BRRRKey} {
		v, err := read(name)
		if err != nil {
			return s, err
		}
		*target = v
	}
	if s.GOGPassword == "" {
		return s, errors.New("gog-keyring-password credential is required")
	}
	if (s.PushoverToken == "") != (s.PushoverUser == "") {
		return s, errors.New("both Pushover credentials are required together")
	}
	if c.RequireAlerts && (s.PushoverToken == "" || s.PushoverUser == "" || s.BRRRKey == "") {
		return s, errors.New("Pushover and brrr credentials are required; require_alerts=false is only for local development")
	}
	return s, nil
}
