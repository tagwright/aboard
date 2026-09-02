// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 the aboard authors

package authentik

import (
	"context"
	"net/http"
	"net/url"
	"strconv"
)

const (
	proxyProvidersPath  = "/api/v3/providers/proxy/"
	oauth2ProvidersPath = "/api/v3/providers/oauth2/"
)

// GetProxyProviderByName finds a proxy provider by exact name. The list endpoint
// filters by search (fuzzy), so the exact name is confirmed client-side, matching
// the production script's jq exact-equality filter. Not found returns ErrNotFound.
func (c *Client) GetProxyProviderByName(ctx context.Context, name string) (*ProxyProvider, error) {
	q := url.Values{"search": {name}}
	page, err := listPage[ProxyProvider](ctx, c, proxyProvidersPath, q)
	if err != nil {
		return nil, err
	}
	for i := range page.Results {
		if page.Results[i].Name == name {
			return &page.Results[i], nil
		}
	}
	return nil, ErrNotFound
}

// CreateProxyProvider creates a proxy provider from body and returns it.
func (c *Client) CreateProxyProvider(ctx context.Context, body ProxyProviderRequest) (*ProxyProvider, error) {
	var out ProxyProvider
	if err := c.do(ctx, http.MethodPost, proxyProvidersPath, nil, body, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// PatchProxyProvider patches the proxy provider with the given integer pk from
// body and returns the updated provider.
func (c *Client) PatchProxyProvider(ctx context.Context, pk int, body ProxyProviderRequest) (*ProxyProvider, error) {
	var out ProxyProvider
	path := proxyProvidersPath + strconv.Itoa(pk) + "/"
	if err := c.do(ctx, http.MethodPatch, path, nil, body, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// DeleteProxyProvider deletes the proxy provider with the given integer pk. A
// 404 unwraps to ErrNotFound, so a caller can treat an already-absent provider
// as a no-op.
func (c *Client) DeleteProxyProvider(ctx context.Context, pk int) error {
	path := proxyProvidersPath + strconv.Itoa(pk) + "/"
	return c.do(ctx, http.MethodDelete, path, nil, nil, nil)
}

// GetOAuth2ProviderByName finds an OAuth2 provider by exact name, same shape as
// the proxy lookup. Not found returns ErrNotFound.
func (c *Client) GetOAuth2ProviderByName(ctx context.Context, name string) (*OAuth2Provider, error) {
	q := url.Values{"search": {name}}
	page, err := listPage[OAuth2Provider](ctx, c, oauth2ProvidersPath, q)
	if err != nil {
		return nil, err
	}
	for i := range page.Results {
		if page.Results[i].Name == name {
			return &page.Results[i], nil
		}
	}
	return nil, ErrNotFound
}

// CreateOAuth2Provider creates an OAuth2 provider from body and returns it. The
// client secret aboard pushes in flows only inward: it is scrubbed from any
// error this call produces, so a validation failure that echoes the request can
// never surface the secret.
func (c *Client) CreateOAuth2Provider(ctx context.Context, body OAuth2ProviderRequest) (*OAuth2Provider, error) {
	var out OAuth2Provider
	if err := c.do(ctx, http.MethodPost, oauth2ProvidersPath, nil, body, &out, body.ClientSecret); err != nil {
		return nil, err
	}
	return &out, nil
}

// PatchOAuth2Provider patches the OAuth2 provider with the given integer pk from
// body and returns the updated provider. Any client secret in body is scrubbed
// from an error, as on create.
func (c *Client) PatchOAuth2Provider(ctx context.Context, pk int, body OAuth2ProviderRequest) (*OAuth2Provider, error) {
	var out OAuth2Provider
	path := oauth2ProvidersPath + strconv.Itoa(pk) + "/"
	if err := c.do(ctx, http.MethodPatch, path, nil, body, &out, body.ClientSecret); err != nil {
		return nil, err
	}
	return &out, nil
}

// DeleteOAuth2Provider deletes the OAuth2 provider with the given integer pk. A
// 404 unwraps to ErrNotFound.
func (c *Client) DeleteOAuth2Provider(ctx context.Context, pk int) error {
	path := oauth2ProvidersPath + strconv.Itoa(pk) + "/"
	return c.do(ctx, http.MethodDelete, path, nil, nil, nil)
}
