// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 the aboard authors

package authentik

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"testing"
)

// TestSetApplicationIconURL proves the set_icon_url action: a POST to the
// slug's set_icon_url detail route with a JSON {"url": ...} body, the shape the
// schema's FilePathRequest documents (not the multipart set_icon).
func TestSetApplicationIconURL(t *testing.T) {
	var cap capture
	cli := newTestClient(t, &cap, 200, ``)

	const iconURL = "https://cdn.example.com/icons/nutrition.png"
	if err := cli.SetApplicationIconURL(context.Background(), "nutrition", iconURL); err != nil {
		t.Fatalf("SetApplicationIconURL: %v", err)
	}

	if cap.method != http.MethodPost {
		t.Errorf("method = %q, want POST", cap.method)
	}
	if cap.path != "/api/v3/core/applications/nutrition/set_icon_url/" {
		t.Errorf("path = %q", cap.path)
	}

	var body FilePathRequest
	if err := json.Unmarshal([]byte(cap.body), &body); err != nil {
		t.Fatalf("body is not JSON: %v (%q)", err, cap.body)
	}
	if body.URL != iconURL {
		t.Errorf("body url = %q, want %q", body.URL, iconURL)
	}
}

// TestSetApplicationIconURLNotFound confirms a 404 on the action unwraps to
// ErrNotFound, so a caller can tell a missing application from a real failure.
func TestSetApplicationIconURLNotFound(t *testing.T) {
	var cap capture
	cli := newTestClient(t, &cap, 404, `{"detail":"Not found."}`)

	err := cli.SetApplicationIconURL(context.Background(), "ghost", "https://x/y.png")
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("err = %v, want ErrNotFound", err)
	}
}
