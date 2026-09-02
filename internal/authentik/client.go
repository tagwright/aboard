// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 the aboard authors

// Package authentik is aboard's typed client for Authentik's REST API. It is a
// thin layer of primitives, not an orchestrator: each method issues exactly one
// documented HTTP call (or, for a paginated list, the minimal sequence of them)
// and returns a typed result plus a real error. It carries none of the reconcile
// decision logic (lookup-then-create-or-patch, ownership markers, adoption,
// ordering); that is the reconciler's job, and it is built on top of these
// primitives.
//
// The call shapes here mirror the verified production reconciler
// SCRIPTS/create-authentik-app.sh one for one, and every field name and
// required-ness was checked against the OpenAPI schema for Authentik 2025.6.4,
// the version pinned on this host.
//
// Two rules are load-bearing. First, a lookup that finds nothing returns a nil
// result together with the ErrNotFound sentinel, never a misleading generic
// error: a caller distinguishes "the object is not there" from "the call failed"
// with errors.Is(err, ErrNotFound). Confusing those two once made a sibling
// tool's CLI report not-found on a real failure, and this package exists partly
// to not repeat it. Second, no secret value is ever logged or surfaced: the API
// token lives only in the Authorization header, an OIDC client secret flows only
// inward on a request body, and any APIError carrying a response body has the
// token and any caller-named secret scrubbed out of it before it is returned.
package authentik

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/tagwright/aboard/internal/config"
	"github.com/tagwright/aboard/internal/secret"
)

// ErrNotFound is the sentinel a lookup returns, with a nil result, when the
// requested object does not exist. It is returned both for an empty
// filtered-list response and for a 404 on a detail route (an APIError with a 404
// status unwraps to it), so a caller can test either case with
// errors.Is(err, ErrNotFound).
var ErrNotFound = errors.New("authentik: not found")

// connectTimeout and requestTimeout mirror the production script's
// curl --connect-timeout 10 --max-time 30: ten seconds to establish the
// connection, thirty for the whole request.
const (
	connectTimeout = 10 * time.Second
	requestTimeout = 30 * time.Second
)

// maxErrorBody caps how much of a non-2xx response body an APIError carries, so
// a large or hostile error page cannot bloat a log line.
const maxErrorBody = 2048

// Client talks to one Authentik instance over its REST API. It is safe for
// concurrent use. The token is held only to set the Bearer header and to scrub
// itself out of any error body; it is never logged.
type Client struct {
	baseURL string
	token   string
	http    *http.Client
}

// New builds a Client for the Authentik instance at baseURL, authenticating with
// the given API token. baseURL is the internal endpoint (for aboard,
// http://authentik-server:9000), because the public URL is Cloudflare-blocked
// for programmatic calls. A trailing slash on baseURL is trimmed so path joins
// stay clean.
func New(baseURL, token string) *Client {
	transport := &http.Transport{
		DialContext: (&net.Dialer{Timeout: connectTimeout}).DialContext,
		Proxy:       http.ProxyFromEnvironment,
	}
	return &Client{
		baseURL: strings.TrimRight(baseURL, "/"),
		token:   token,
		http: &http.Client{
			Timeout:   requestTimeout,
			Transport: transport,
		},
	}
}

// FromConfig builds a Client from a loaded aboard config, resolving the API
// token by NAME through the given secret resolver. The token value never appears
// in the config or in any log; only its name lives in aboard.yml. A resolver
// error (the named token file is missing, unreadable) is returned as-is so the
// caller can alert on it.
func FromConfig(cfg *config.Config, resolve secret.Resolver) (*Client, error) {
	if cfg.Authentik.URL == "" {
		return nil, fmt.Errorf("authentik: config has no authentik.url")
	}
	if cfg.Authentik.Token == "" {
		return nil, fmt.Errorf("authentik: config has no authentik.token name")
	}
	token, err := resolve(cfg.Authentik.Token)
	if err != nil {
		return nil, fmt.Errorf("authentik: resolve API token %q: %w", cfg.Authentik.Token, err)
	}
	return New(cfg.Authentik.URL, token), nil
}

// APIError is the typed error a non-2xx REST response produces. It carries the
// request method and path, the HTTP status, and a redacted, length-capped copy
// of the response body. The body has had the API token and any caller-named
// secret scrubbed out, so an APIError is always safe to log. A 404 status
// unwraps to ErrNotFound.
type APIError struct {
	Method string
	Path   string
	Status int
	Body   string
}

// Error renders the status, method, and path, plus the redacted body when there
// is one. It never contains a secret value.
func (e *APIError) Error() string {
	if e.Body == "" {
		return fmt.Sprintf("authentik: %s %s: HTTP %d", e.Method, e.Path, e.Status)
	}
	return fmt.Sprintf("authentik: %s %s: HTTP %d: %s", e.Method, e.Path, e.Status, e.Body)
}

// Unwrap maps a 404 to ErrNotFound so a detail-route lookup that 404s is testable
// with errors.Is(err, ErrNotFound), the same way an empty filtered list is.
func (e *APIError) Unwrap() error {
	if e.Status == http.StatusNotFound {
		return ErrNotFound
	}
	return nil
}

// do issues one request. It marshals body to JSON when body is non-nil, sets the
// Bearer and Content-Type headers, and on a 2xx decodes the response into out
// when out is non-nil. A non-2xx becomes an APIError whose body has the token and
// every value in redact scrubbed out. do never logs anything.
func (c *Client) do(ctx context.Context, method, path string, query url.Values, body, out any, redact ...string) error {
	u := c.baseURL + path
	if len(query) > 0 {
		u += "?" + query.Encode()
	}

	var reqBody io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("authentik: %s %s: encode body: %w", method, path, err)
		}
		reqBody = bytes.NewReader(encoded)
	}

	req, err := http.NewRequestWithContext(ctx, method, u, reqBody)
	if err != nil {
		return fmt.Errorf("authentik: %s %s: build request: %w", method, path, err)
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.http.Do(req)
	if err != nil {
		// A transport error (timeout, connection refused) can echo the URL, but
		// never the token, which lives only in a header. Return it plainly.
		return fmt.Errorf("authentik: %s %s: %w", method, path, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrorBody))
		return &APIError{
			Method: method,
			Path:   path,
			Status: resp.StatusCode,
			Body:   c.redact(string(raw), redact),
		}
	}

	if out != nil {
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
			return fmt.Errorf("authentik: %s %s: decode response: %w", method, path, err)
		}
	}
	return nil
}

// redact removes the API token and every non-empty value in extra from s,
// replacing each with a fixed placeholder. The token is always scrubbed because
// the client holds it; extra carries request-body secrets (an OIDC client
// secret) a caller wants kept out of any error. It guarantees an APIError never
// surfaces a secret the client sent.
func (c *Client) redact(s string, extra []string) string {
	if c.token != "" {
		s = strings.ReplaceAll(s, c.token, "[REDACTED]")
	}
	for _, v := range extra {
		if v != "" {
			s = strings.ReplaceAll(s, v, "[REDACTED]")
		}
	}
	return s
}
