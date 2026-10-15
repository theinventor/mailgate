package gateway

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPrivateAndSystemdCredentialModes(t *testing.T) {
	c := DefaultConfig()
	c.SecretDir = t.TempDir()
	c.RequireAlerts = false
	path := filepath.Join(c.SecretDir, "gog-keyring-password")
	if err := os.WriteFile(path, []byte("fixture-secret\n"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CREDENTIALS_DIRECTORY", "")
	if _, err := c.LoadSecrets(); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0640); err != nil {
		t.Fatal(err)
	}
	if _, err := c.LoadSecrets(); err == nil {
		t.Fatal("group-readable standalone secret accepted")
	}
	t.Setenv("CREDENTIALS_DIRECTORY", c.SecretDir)
	if err := os.Chmod(path, 0440); err != nil {
		t.Fatal(err)
	}
	if _, err := c.LoadSecrets(); err != nil {
		t.Fatal("systemd private credential mode rejected:", err)
	}
	if err := os.Chmod(path, 0444); err != nil {
		t.Fatal(err)
	}
	if _, err := c.LoadSecrets(); err == nil {
		t.Fatal("world-readable secret accepted")
	}
}

func TestConfigRejectsPublicListenersAndInsecureOrigins(t *testing.T) {
	c := DefaultConfig()
	c.OwnerEmail = "owner@example.test"
	c.GOGAccount = c.OwnerEmail
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, address := range []string{"0.0.0.0:8787", ":8787", "100.64.0.1:8787", "127.0.0.1:0"} {
		bad := c
		bad.Listen = address
		if bad.Validate() == nil {
			t.Errorf("accepted %s", address)
		}
	}
	for _, origin := range []string{"http://mailgate.test", "https://mailgate.test/", "https://user:pass@mailgate.test", "https://mailgate.test?x=y"} {
		bad := c
		bad.AdminOrigin = origin
		if bad.Validate() == nil {
			t.Errorf("accepted %s", origin)
		}
	}
}
