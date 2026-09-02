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
	samlProvidersPath   = "/api/v3/providers/saml/"
	allProvidersPath    = "/api/v3/providers/all/"
)

// Provider component discriminators, from the polymorphic /providers/all/ list
// and detail routes. Authentik returns a `component` field naming the provider
// type: a proxy provider is ak-provider-proxy-form and a genuine OAuth2/OIDC
// provider is ak-provider-oauth2-form. Because ProxyProvider is a subclass of
// OAuth2Provider, this component field is the only reliable type discriminator
// when a provider is known only by pk.
const (
	ComponentProxyProvider  = "ak-provider-proxy-form"
	ComponentOAuth2Provider = "ak-provider-oauth2-form"

	// ComponentSAMLProvider is the discriminator for a SAML provider, verified
	// against authentik/providers/saml/models.py at tag version/2025.6.4. Unlike a
	// proxy provider, a SAML provider is NOT a subclass of OAuth2Provider, so it
	// is a clean, disjoint type: the oauth2 endpoint never returns it, and it is
	// resolved by its own /providers/saml/ endpoint or the polymorphic by-pk route.
	ComponentSAMLProvider = "ak-provider-saml-form"
)

// ProviderRef is the minimal cross-type view of a provider from the polymorphic
// /providers/all/{pk}/ detail route: its integer pk, its name, and the component
// discriminator that names its concrete type. It is what lets a caller learn the
// TYPE of a provider it knows only by pk (an application's provider FK), which no
// typed endpoint can do because the oauth2 list also returns proxy providers.
type ProviderRef struct {
	PK        int    `json:"pk"`
	Name      string `json:"name"`
	Component string `json:"component"`
}

// GetProviderByPK looks up any provider by its integer pk through the polymorphic
// /providers/all/{pk}/ detail route and returns its name and component (type). A
// 404 unwraps to ErrNotFound. This is the type-accurate by-pk lookup adoption
// needs to refuse a provider-type change and to rename the right kind of provider
// in place.
func (c *Client) GetProviderByPK(ctx context.Context, pk int) (*ProviderRef, error) {
	var out ProviderRef
	path := allProvidersPath + strconv.Itoa(pk) + "/"
	if err := c.do(ctx, http.MethodGet, path, nil, nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

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

// GetSAMLProviderByName finds a SAML provider by exact name, the same shape as
// the proxy and oauth2 lookups: the list endpoint filters by fuzzy search, so
// the exact name is confirmed client-side. Not found returns ErrNotFound.
func (c *Client) GetSAMLProviderByName(ctx context.Context, name string) (*SAMLProvider, error) {
	q := url.Values{"search": {name}}
	page, err := listPage[SAMLProvider](ctx, c, samlProvidersPath, q)
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

// CreateSAMLProvider creates a SAML provider from body and returns it. No field
// in body is a secret (a SAML provider signs with a keypair Authentik holds), so
// nothing is scrubbed from an error here.
func (c *Client) CreateSAMLProvider(ctx context.Context, body SAMLProviderRequest) (*SAMLProvider, error) {
	var out SAMLProvider
	if err := c.do(ctx, http.MethodPost, samlProvidersPath, nil, body, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// PatchSAMLProvider patches the SAML provider with the given integer pk from body
// and returns the updated provider.
func (c *Client) PatchSAMLProvider(ctx context.Context, pk int, body SAMLProviderRequest) (*SAMLProvider, error) {
	var out SAMLProvider
	path := samlProvidersPath + strconv.Itoa(pk) + "/"
	if err := c.do(ctx, http.MethodPatch, path, nil, body, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// DeleteSAMLProvider deletes the SAML provider with the given integer pk. A 404
// unwraps to ErrNotFound.
func (c *Client) DeleteSAMLProvider(ctx context.Context, pk int) error {
	path := samlProvidersPath + strconv.Itoa(pk) + "/"
	return c.do(ctx, http.MethodDelete, path, nil, nil, nil)
}

// GetSAMLMetadata returns the IdP metadata for the SAML provider with the given
// pk (GET /api/v3/providers/saml/{pk}/metadata/). The response carries the
// metadata XML as a string and a download URL, both non-secret. A 404 here means
// the provider has no application assigned yet, which unwraps to ErrNotFound, so
// a caller can distinguish "not yet linked" from a transport failure.
func (c *Client) GetSAMLMetadata(ctx context.Context, pk int) (*SAMLMetadata, error) {
	var out SAMLMetadata
	path := samlProvidersPath + strconv.Itoa(pk) + "/metadata/"
	if err := c.do(ctx, http.MethodGet, path, nil, nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}
