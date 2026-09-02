// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 the aboard authors

package secret

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeSecret(t *testing.T, dir, name, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
		t.Fatalf("write secret %q: %v", name, err)
	}
}

func TestFileFirst(t *testing.T) {
	dir := t.TempDir()
	writeSecret(t, dir, "api-token", "file-value\n")
	// An env fallback also exists, but the file must win.
	t.Setenv("ABOARD_SECRET_API_TOKEN", "env-value")

	got, err := FileEnvResolver(dir)("api-token")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if got != "file-value" {
		t.Errorf("file-first: got %q, want %q", got, "file-value")
	}
}

func TestEnvFallback(t *testing.T) {
	dir := t.TempDir() // empty, so the file lookup misses
	t.Setenv("ABOARD_SECRET_GITEA_OIDC_CLIENT_SECRET", "env-value\n")

	got, err := FileEnvResolver(dir)("gitea-oidc-client-secret")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if got != "env-value" {
		t.Errorf("env fallback: got %q, want %q", got, "env-value")
	}
}

// TestTrimConsistency is the load-bearing property: a value from a file and the
// same value from an env var, differing only in trailing whitespace, must
// resolve identically.
func TestTrimConsistency(t *testing.T) {
	const want = "the-secret-value"

	tests := []struct {
		name string
		raw  string
	}{
		{"trailing newline", want + "\n"},
		{"trailing crlf", want + "\r\n"},
		{"leading and trailing spaces", "  " + want + "  "},
		{"trailing tab", want + "\t"},
		{"surrounding whitespace mix", "\n\t " + want + " \t\r\n"},
		{"clean", want},
	}

	for _, tc := range tests {
		// File source.
		dir := t.TempDir()
		writeSecret(t, dir, "s", tc.raw)
		fromFile, err := FileEnvResolver(dir)("s")
		if err != nil {
			t.Fatalf("%s: file resolve: %v", tc.name, err)
		}

		// Env source, from an empty dir so the file lookup misses.
		empty := t.TempDir()
		t.Setenv("ABOARD_SECRET_S", tc.raw)
		fromEnv, err := FileEnvResolver(empty)("s")
		if err != nil {
			t.Fatalf("%s: env resolve: %v", tc.name, err)
		}

		if fromFile != want {
			t.Errorf("%s: file gave %q, want %q", tc.name, fromFile, want)
		}
		if fromEnv != want {
			t.Errorf("%s: env gave %q, want %q", tc.name, fromEnv, want)
		}
		if fromFile != fromEnv {
			t.Errorf("%s: file %q and env %q disagree", tc.name, fromFile, fromEnv)
		}
	}
}

func TestMissingSecret(t *testing.T) {
	dir := t.TempDir()
	os.Unsetenv("ABOARD_SECRET_NOPE")

	_, err := FileEnvResolver(dir)("nope")
	if err == nil {
		t.Fatal("want an error for a missing secret, got nil")
	}
	// The error must name the secret so the caller can alert on it.
	if !strings.Contains(err.Error(), "nope") {
		t.Errorf("error should name the secret: %v", err)
	}
}

func TestEmptyName(t *testing.T) {
	if _, err := FileEnvResolver(t.TempDir())(""); err == nil {
		t.Fatal("want an error for an empty secret name, got nil")
	}
}

func TestEnvVarName(t *testing.T) {
	tests := []struct {
		name string
		want string
	}{
		{"api-token", "ABOARD_SECRET_API_TOKEN"},
		{"gitea-oidc-client-secret", "ABOARD_SECRET_GITEA_OIDC_CLIENT_SECRET"},
		{"plain", "ABOARD_SECRET_PLAIN"},
	}
	for _, tc := range tests {
		if got := envVarName(tc.name); got != tc.want {
			t.Errorf("envVarName(%q): got %q, want %q", tc.name, got, tc.want)
		}
	}
}

func TestDefaultSecretsDir(t *testing.T) {
	// An empty secretsDir must fall back to the default rather than resolving
	// under the working directory.
	r := FileEnvResolver("")
	t.Setenv("ABOARD_SECRET_ONLY_IN_ENV", "value")
	got, err := r("only-in-env")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if got != "value" {
		t.Errorf("default dir resolver: got %q", got)
	}
}

func TestCheckOIDCLength(t *testing.T) {
	tests := []struct {
		name    string
		value   string
		wantErr bool
	}{
		{"exactly 32", strings.Repeat("a", 32), false},
		{"longer", strings.Repeat("a", 48), false},
		{"31 too short", strings.Repeat("a", 31), true},
		{"empty", "", true},
	}
	for _, tc := range tests {
		err := CheckOIDCLength("gitea-oidc-client-secret", tc.value)
		if tc.wantErr && err == nil {
			t.Errorf("%s: want error, got nil", tc.name)
		}
		if !tc.wantErr && err != nil {
			t.Errorf("%s: want nil, got %v", tc.name, err)
		}
		// On failure the error names the secret, never the value.
		if err != nil {
			if !strings.Contains(err.Error(), "gitea-oidc-client-secret") {
				t.Errorf("%s: error should name the secret: %v", tc.name, err)
			}
			if tc.value != "" && strings.Contains(err.Error(), tc.value) {
				t.Errorf("%s: error must not leak the secret value: %v", tc.name, err)
			}
		}
	}
}
