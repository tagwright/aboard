// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 the aboard authors

package cli

import (
	"bytes"
	"strings"
	"testing"

	"github.com/tagwright/aboard/internal/version"
)

// TestCommandTree proves every documented subcommand is wired onto the root.
func TestCommandTree(t *testing.T) {
	root := newRootCmd()
	want := []string{"daemon", "status", "render", "prune", "validate", "version"}
	have := map[string]bool{}
	for _, c := range root.Commands() {
		have[c.Name()] = true
	}
	for _, name := range want {
		if !have[name] {
			t.Errorf("root command is missing subcommand %q", name)
		}
	}
}

// TestPersistentConfigFlag proves the root carries the persistent --config flag
// every subcommand shares.
func TestPersistentConfigFlag(t *testing.T) {
	root := newRootCmd()
	if root.PersistentFlags().Lookup("config") == nil {
		t.Fatalf("root is missing the persistent --config flag")
	}
}

// TestVersionCommand proves "aboard version" prints the build version, unchanged
// from the VERSION file.
func TestVersionCommand(t *testing.T) {
	root := newRootCmd()
	var buf bytes.Buffer
	root.SetOut(&buf)
	root.SetErr(&buf)
	root.SetArgs([]string{"version"})
	if err := root.Execute(); err != nil {
		t.Fatalf("version: %v", err)
	}
	want := "aboard " + version.Version + "\n"
	if buf.String() != want {
		t.Errorf("version output = %q, want %q", buf.String(), want)
	}
}

// TestRenderSetupRejectsServiceArg proves "render --setup <service>" is a usage
// error, caught before any config load or socket open.
func TestRenderSetupRejectsServiceArg(t *testing.T) {
	root := newRootCmd()
	var buf bytes.Buffer
	root.SetOut(&buf)
	root.SetErr(&buf)
	root.SetArgs([]string{"render", "--setup", "extra"})
	err := root.Execute()
	if err == nil {
		t.Fatalf("expected an error for render --setup with a service argument")
	}
	if !strings.Contains(err.Error(), "takes no service argument") {
		t.Errorf("unexpected error: %v", err)
	}
}

// TestRenderRequiresServiceOrSetup proves "render" with no service and no --setup
// is a usage error, caught before any config load or socket open.
func TestRenderRequiresServiceOrSetup(t *testing.T) {
	root := newRootCmd()
	var buf bytes.Buffer
	root.SetOut(&buf)
	root.SetErr(&buf)
	root.SetArgs([]string{"render"})
	err := root.Execute()
	if err == nil {
		t.Fatalf("expected an error for render with no service and no --setup")
	}
	if !strings.Contains(err.Error(), "exactly one <service>") {
		t.Errorf("unexpected error: %v", err)
	}
}
