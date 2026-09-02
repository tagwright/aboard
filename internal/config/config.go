// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 the aboard authors

// Package config is the aboard.yml schema and its loader. aboard.yml holds
// structure, not secrets: the Authentik endpoint, the API token NAME, the
// default flows, the outpost default, the signing-key name, the proxy setting,
// the Traefik middleware name and major version, and the fleet default groups.
// Nothing in it is ever a secret value, so it is safe to commit. Names live in
// aboard.yml and labels, secret values live in files the resolver reads at
// deploy time (see package secret).
//
// The small surviving set of ABOARD_* environment globals is loaded alongside
// the file into Globals. These are env on the aboard daemon container, not
// fields of the committed aboard.yml, so they are read from the environment and
// not from the yaml body. See the grammar's "Globals" section.
package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Fleet-default constants. Every field of aboard.yml has a default so that a
// minimal file, or none at all, still produces a coherent config. These mirror
// the "aboard.yml side" section of the grammar verbatim.
const (
	// DefaultAuthorizationFlow is the flows.authorization fallback.
	DefaultAuthorizationFlow = "default-provider-authorization-implicit-consent"

	// DefaultInvalidationFlow is the flows.invalidation fallback.
	DefaultInvalidationFlow = "default-provider-invalidation-flow"

	// DefaultOutpost is the outpost fallback. The embedded outpost is found at
	// reconcile time by its managed marker, never by a hardcoded pk (Fork 4).
	DefaultOutpost = "embedded"

	// DefaultSigningKey is the oidc.signing_key fallback: Authentik's own
	// self-signed certificate pair (Fork 7).
	DefaultSigningKey = "authentik Self-signed Certificate"

	// DefaultMiddleware is the traefik.middleware fallback (Fork 6).
	DefaultMiddleware = "authentik@docker"

	// DefaultTraefikVersion is the traefik.version fallback. Traefik v2 and v3
	// spell HostRegexp differently, so render output targets this major (Fork 6).
	DefaultTraefikVersion = 3

	// ProxyTraefik and ProxyNone are the two legal proxy values. Under
	// ProxyNone the verifier is off and aboard.host must be explicit (Fork 6).
	ProxyTraefik = "traefik"
	ProxyNone    = "none"

	// DefaultProxy is the proxy fallback.
	DefaultProxy = ProxyTraefik
)

// DefaultConfigPath is where aboard looks for aboard.yml when ABOARD_CONFIG is
// unset and no aboard.yml sits in the working directory.
const DefaultConfigPath = "/etc/aboard/aboard.yml"

// DefaultSecretsDir is the ABOARD_SECRETS_DIR fallback, the root under which
// named secret refs (the API token, OIDC client secrets) resolve file-first.
// It matches package secret's own default and the grammar's Globals section.
const DefaultSecretsDir = "/run/aboard/secrets"

// DefaultDigestSchedule is the ABOARD_DIGEST_SCHEDULE fallback for the daily
// beacon digest cadence.
const DefaultDigestSchedule = "daily"

// Authentik is the IdP endpoint block. The url is the INTERNAL endpoint aboard
// calls, because the public URL is Cloudflare-blocked for programmatic access.
// public_url composes discovery URLs in render output only. token is a secret
// NAME, resolved from a file at deploy time, never a value.
type Authentik struct {
	URL       string `yaml:"url"`
	PublicURL string `yaml:"public_url"`
	Token     string `yaml:"token"`
}

// Flows are the fleet default flow slugs every per-container reconcile starts
// from. A per-container aboard.flow overrides Authorization only.
type Flows struct {
	Authorization string `yaml:"authorization"`
	Invalidation  string `yaml:"invalidation"`
}

// OIDC is the OIDC fleet block. SigningKey is a certificate NAME, not a secret.
type OIDC struct {
	SigningKey string `yaml:"signing_key"`
}

// Traefik is the proxy-audit fleet block. Middleware is the one fleet-wide
// forward-auth middleware name, and Version is the fleet's Traefik major, which
// render output targets.
type Traefik struct {
	Middleware string `yaml:"middleware"`
	Version    int    `yaml:"version"`
}

// Defaults are the fleet default access settings. Groups is the fleet default
// group list, replaced wholesale by any aboard.groups label (Fork 5, ballast
// retention-replaces-not-merges semantics).
type Defaults struct {
	Groups []string `yaml:"groups"`
}

// Globals is the small set of ABOARD_* environment globals on the aboard
// daemon container. They are env, not committed aboard.yml fields, so Load
// reads them from the environment. See the grammar's "Globals" section.
type Globals struct {
	// SecretsDir is ABOARD_SECRETS_DIR: the root under which named secret refs
	// resolve file-first. Default DefaultSecretsDir.
	SecretsDir string

	// CreateGroups is ABOARD_CREATE_GROUPS: opt in to create-empty-and-alert on
	// a missing group. Default false (Fork 5).
	CreateGroups bool

	// Proxy is ABOARD_PROXY: mirrors aboard.yml proxy:. When set it overlays the
	// yaml value (see Load). Empty means "not set in the environment".
	Proxy string

	// DigestSchedule is ABOARD_DIGEST_SCHEDULE: the daily digest cadence.
	// Default DefaultDigestSchedule.
	DigestSchedule string
}

// Config is a parsed aboard.yml plus the loaded ABOARD_* globals.
type Config struct {
	Authentik Authentik `yaml:"authentik"`
	Flows     Flows     `yaml:"flows"`
	Outpost   string    `yaml:"outpost"`
	OIDC      OIDC      `yaml:"oidc"`
	Proxy     string    `yaml:"proxy"`
	Traefik   Traefik   `yaml:"traefik"`
	Defaults  Defaults  `yaml:"defaults"`

	// Globals holds the ABOARD_* environment globals, loaded from the
	// environment, not the yaml body.
	Globals Globals `yaml:"-"`
}

// ResolveConfigPath decides which aboard.yml to load: ABOARD_CONFIG when set,
// else ./aboard.yml when it exists, else DefaultConfigPath. It mirrors berm's
// convention of an env override over a working-directory file over an /etc
// fallback.
func ResolveConfigPath() string {
	if v := os.Getenv("ABOARD_CONFIG"); v != "" {
		return v
	}
	if _, err := os.Stat("aboard.yml"); err == nil {
		return "aboard.yml"
	}
	return DefaultConfigPath
}

// Load reads and parses aboard.yml at path, overlays the ABOARD_* environment
// globals, and fills every unset field with its fleet default so a minimal
// file still yields a coherent config. A read or parse error is returned.
// Semantic validation is Validate's job, kept separate so a caller can load and
// validate in two steps.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("config: read %s: %w", path, err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("config: parse %s: %w", path, err)
	}

	cfg.Globals = loadGlobals()

	// ABOARD_PROXY mirrors proxy:. An explicit env value overlays the yaml
	// value, before defaults fill an otherwise-empty proxy.
	if cfg.Globals.Proxy != "" {
		cfg.Proxy = cfg.Globals.Proxy
	}

	cfg.applyDefaults()
	return &cfg, nil
}

// applyDefaults fills every unset field with its fleet default. It runs after
// the env overlay so a default only lands when neither the yaml nor the
// environment supplied a value.
func (c *Config) applyDefaults() {
	if c.Flows.Authorization == "" {
		c.Flows.Authorization = DefaultAuthorizationFlow
	}
	if c.Flows.Invalidation == "" {
		c.Flows.Invalidation = DefaultInvalidationFlow
	}
	if c.Outpost == "" {
		c.Outpost = DefaultOutpost
	}
	if c.OIDC.SigningKey == "" {
		c.OIDC.SigningKey = DefaultSigningKey
	}
	if c.Proxy == "" {
		c.Proxy = DefaultProxy
	}
	if c.Traefik.Middleware == "" {
		c.Traefik.Middleware = DefaultMiddleware
	}
	if c.Traefik.Version == 0 {
		c.Traefik.Version = DefaultTraefikVersion
	}
}

// Validate checks the config file's own coherence, the settled subset that is a
// config-level concern rather than a discovery-time one. Per the grammar, a
// per-container traefik label under proxy: none is a discovery-time error a
// later chunk raises, so Validate deliberately does not flag an aboard.yml
// traefik block under proxy: none.
func (c *Config) Validate() error {
	switch c.Proxy {
	case ProxyTraefik, ProxyNone:
	default:
		return fmt.Errorf("config: proxy must be %q or %q, got %q", ProxyTraefik, ProxyNone, c.Proxy)
	}

	if c.Authentik.URL == "" {
		return fmt.Errorf("config: authentik.url is required (the internal endpoint, e.g. http://authentik-server:9000)")
	}
	if c.Authentik.Token == "" {
		return fmt.Errorf("config: authentik.token is required (the secret NAME of the API token, never a value)")
	}

	// The Traefik major only has meaning under proxy: traefik, and only 2 and 3
	// are spellings render output knows how to target.
	if c.Proxy == ProxyTraefik && c.Traefik.Version != 2 && c.Traefik.Version != 3 {
		return fmt.Errorf("config: traefik.version must be 2 or 3, got %d", c.Traefik.Version)
	}

	return nil
}

// loadGlobals reads the ABOARD_* environment globals, applying defaults for the
// three that have them.
func loadGlobals() Globals {
	g := Globals{
		SecretsDir:     os.Getenv("ABOARD_SECRETS_DIR"),
		CreateGroups:   boolEnv("ABOARD_CREATE_GROUPS"),
		Proxy:          os.Getenv("ABOARD_PROXY"),
		DigestSchedule: DefaultDigestSchedule,
	}
	if g.SecretsDir == "" {
		g.SecretsDir = DefaultSecretsDir
	}
	if v := os.Getenv("ABOARD_DIGEST_SCHEDULE"); v != "" {
		g.DigestSchedule = v
	}
	return g
}

// boolEnv parses an ABOARD_* boolean the strict grammar way: only "true" opts
// in. Anything else, including an unset or malformed value, is false, because a
// security tool must never widen its write footprint on a typo.
func boolEnv(name string) bool {
	return os.Getenv(name) == "true"
}
