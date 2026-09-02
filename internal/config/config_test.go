// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 the aboard authors

package config

import (
	"os"
	"path/filepath"
	"testing"
)

// writeConfig writes body to a temp aboard.yml and returns its path.
func writeConfig(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "aboard.yml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path
}

// clearGlobalEnv unsets every ABOARD_* global for a test, so one test's
// environment never leaks into another.
func clearGlobalEnv(t *testing.T) {
	t.Helper()
	for _, k := range []string{
		"ABOARD_SECRETS_DIR", "ABOARD_CREATE_GROUPS", "ABOARD_PROXY",
		"ABOARD_DIGEST_SCHEDULE", "ABOARD_CONFIG",
	} {
		t.Setenv(k, "")
		os.Unsetenv(k)
	}
}

func TestLoadDefaults(t *testing.T) {
	clearGlobalEnv(t)

	// A minimal file: only the two required-by-Validate fields, everything
	// else must fall back to its fleet default.
	path := writeConfig(t, `
authentik:
  url: http://authentik-server:9000
  token: aboard-api-token
`)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	tests := []struct {
		name string
		got  any
		want any
	}{
		{"authorization flow", cfg.Flows.Authorization, DefaultAuthorizationFlow},
		{"invalidation flow", cfg.Flows.Invalidation, DefaultInvalidationFlow},
		{"outpost", cfg.Outpost, DefaultOutpost},
		{"signing key", cfg.OIDC.SigningKey, DefaultSigningKey},
		{"groups scope", cfg.OIDC.GroupsScope, DefaultGroupsScope},
		{"proxy", cfg.Proxy, DefaultProxy},
		{"middleware", cfg.Traefik.Middleware, DefaultMiddleware},
		{"traefik version", cfg.Traefik.Version, DefaultTraefikVersion},
		{"globals secrets dir", cfg.Globals.SecretsDir, DefaultSecretsDir},
		{"globals create groups", cfg.Globals.CreateGroups, false},
		{"globals digest schedule", cfg.Globals.DigestSchedule, DefaultDigestSchedule},
	}
	for _, tc := range tests {
		if tc.got != tc.want {
			t.Errorf("%s: got %v, want %v", tc.name, tc.got, tc.want)
		}
	}

	if err := cfg.Validate(); err != nil {
		t.Errorf("Validate on a minimal file: %v", err)
	}
}

func TestLoadExplicitValuesWin(t *testing.T) {
	clearGlobalEnv(t)

	path := writeConfig(t, `
authentik:
  url: http://authentik-server:9000
  public_url: https://auth.example.org
  token: aboard-api-token
flows:
  authorization: my-authz
  invalidation: my-invalidation
outpost: remote-site
oidc:
  signing_key: my-cert
  groups_scope: roles
proxy: none
traefik:
  middleware: my-mw
  version: 2
defaults:
  groups: [public-users, staff]
`)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if cfg.Authentik.PublicURL != "https://auth.example.org" {
		t.Errorf("public_url: got %q", cfg.Authentik.PublicURL)
	}
	if cfg.Flows.Authorization != "my-authz" || cfg.Flows.Invalidation != "my-invalidation" {
		t.Errorf("flows not preserved: %+v", cfg.Flows)
	}
	if cfg.Outpost != "remote-site" {
		t.Errorf("outpost: got %q", cfg.Outpost)
	}
	if cfg.OIDC.SigningKey != "my-cert" {
		t.Errorf("signing_key: got %q", cfg.OIDC.SigningKey)
	}
	if cfg.OIDC.GroupsScope != "roles" {
		t.Errorf("groups_scope: got %q, want the explicit roles", cfg.OIDC.GroupsScope)
	}
	if cfg.Proxy != ProxyNone {
		t.Errorf("proxy: got %q", cfg.Proxy)
	}
	if cfg.Traefik.Middleware != "my-mw" || cfg.Traefik.Version != 2 {
		t.Errorf("traefik not preserved: %+v", cfg.Traefik)
	}
	if len(cfg.Defaults.Groups) != 2 || cfg.Defaults.Groups[0] != "public-users" || cfg.Defaults.Groups[1] != "staff" {
		t.Errorf("defaults.groups: got %v", cfg.Defaults.Groups)
	}
}

func TestGlobalEnvOverlays(t *testing.T) {
	clearGlobalEnv(t)

	path := writeConfig(t, `
authentik:
  url: http://authentik-server:9000
  token: aboard-api-token
proxy: traefik
`)

	t.Setenv("ABOARD_SECRETS_DIR", "/custom/secrets")
	t.Setenv("ABOARD_CREATE_GROUPS", "true")
	t.Setenv("ABOARD_DIGEST_SCHEDULE", "hourly")
	// ABOARD_PROXY mirrors proxy: and overlays the yaml value.
	t.Setenv("ABOARD_PROXY", "none")

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if cfg.Globals.SecretsDir != "/custom/secrets" {
		t.Errorf("secrets dir overlay: got %q", cfg.Globals.SecretsDir)
	}
	if !cfg.Globals.CreateGroups {
		t.Errorf("create groups overlay: got false, want true")
	}
	if cfg.Globals.DigestSchedule != "hourly" {
		t.Errorf("digest schedule overlay: got %q", cfg.Globals.DigestSchedule)
	}
	if cfg.Globals.Proxy != "none" {
		t.Errorf("globals proxy: got %q", cfg.Globals.Proxy)
	}
	if cfg.Proxy != ProxyNone {
		t.Errorf("ABOARD_PROXY did not overlay proxy:, got %q", cfg.Proxy)
	}
}

func TestCreateGroupsStrictBoolean(t *testing.T) {
	clearGlobalEnv(t)
	path := writeConfig(t, `
authentik:
  url: http://authentik-server:9000
  token: aboard-api-token
`)

	// Only the exact string "true" opts in. Everything else is false, because a
	// security tool must not widen its write footprint on a typo.
	tests := []struct {
		val  string
		want bool
	}{
		{"true", true},
		{"false", false},
		{"1", false},
		{"TRUE", false},
		{"yes", false},
		{"", false},
	}
	for _, tc := range tests {
		t.Setenv("ABOARD_CREATE_GROUPS", tc.val)
		cfg, err := Load(path)
		if err != nil {
			t.Fatalf("Load(%q): %v", tc.val, err)
		}
		if cfg.Globals.CreateGroups != tc.want {
			t.Errorf("ABOARD_CREATE_GROUPS=%q: got %v, want %v", tc.val, cfg.Globals.CreateGroups, tc.want)
		}
	}
}

func TestValidate(t *testing.T) {
	base := func() *Config {
		c := &Config{
			Authentik: Authentik{URL: "http://authentik-server:9000", Token: "aboard-api-token"},
			Proxy:     ProxyTraefik,
			Traefik:   Traefik{Version: 3},
		}
		return c
	}

	tests := []struct {
		name    string
		mutate  func(*Config)
		wantErr bool
	}{
		{"valid traefik", func(*Config) {}, false},
		{"valid none proxy", func(c *Config) { c.Proxy = ProxyNone }, false},
		{"missing url", func(c *Config) { c.Authentik.URL = "" }, true},
		{"missing token", func(c *Config) { c.Authentik.Token = "" }, true},
		{"bad proxy", func(c *Config) { c.Proxy = "caddy" }, true},
		{"bad traefik version under traefik", func(c *Config) { c.Traefik.Version = 4 }, true},
		{"bad traefik version ignored under none", func(c *Config) { c.Proxy = ProxyNone; c.Traefik.Version = 4 }, false},
	}
	for _, tc := range tests {
		c := base()
		tc.mutate(c)
		err := c.Validate()
		if tc.wantErr && err == nil {
			t.Errorf("%s: want error, got nil", tc.name)
		}
		if !tc.wantErr && err != nil {
			t.Errorf("%s: want nil, got %v", tc.name, err)
		}
	}
}

func TestResolveConfigPath(t *testing.T) {
	clearGlobalEnv(t)

	// ABOARD_CONFIG wins over everything.
	t.Setenv("ABOARD_CONFIG", "/explicit/aboard.yml")
	if got := ResolveConfigPath(); got != "/explicit/aboard.yml" {
		t.Errorf("ABOARD_CONFIG override: got %q", got)
	}

	// With ABOARD_CONFIG unset and no ./aboard.yml, fall back to the /etc path.
	os.Unsetenv("ABOARD_CONFIG")
	dir := t.TempDir()
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	defer os.Chdir(cwd)
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("chdir: %v", err)
	}
	if got := ResolveConfigPath(); got != DefaultConfigPath {
		t.Errorf("no working-dir file: got %q, want %q", got, DefaultConfigPath)
	}

	// A working-directory aboard.yml is preferred over the /etc fallback.
	if err := os.WriteFile(filepath.Join(dir, "aboard.yml"), []byte("authentik: {}\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if got := ResolveConfigPath(); got != "aboard.yml" {
		t.Errorf("working-dir file: got %q, want %q", got, "aboard.yml")
	}
}

func TestLoadReadError(t *testing.T) {
	if _, err := Load(filepath.Join(t.TempDir(), "does-not-exist.yml")); err == nil {
		t.Fatal("want a read error for a missing file, got nil")
	}
}

func TestLoadParseError(t *testing.T) {
	path := writeConfig(t, "authentik: [this is not a map\n")
	if _, err := Load(path); err == nil {
		t.Fatal("want a parse error for malformed yaml, got nil")
	}
}
