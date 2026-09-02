// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 the aboard authors

// Package version carries the build version string for aboard.
//
// Version defaults to the beta recorded in the repo's VERSION file and is
// overridden at build time with -ldflags "-X
// github.com/tagwright/aboard/internal/version.Version=...". Keeping it in one
// package lets every aboard binary report the same string.
package version

// Version is the build version. It mirrors the VERSION file at the repo root
// and follows the suite's beta scheme v00.01.00bN.
var Version = "00.01.00b1"
