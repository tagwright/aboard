// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 the aboard authors

package authentik

import (
	"context"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
)

// listPage issues one GET against a list endpoint and decodes the paginated
// wrapper. It is a free function, not a method, because Go methods cannot be
// generic; every typed lookup below funnels through it.
func listPage[T any](ctx context.Context, c *Client, path string, q url.Values) (Paginated[T], error) {
	var page Paginated[T]
	err := c.do(ctx, http.MethodGet, path, q, nil, &page)
	return page, err
}

// GetFlowBySlug looks up a flow by its slug. A flow slug is unique, so the
// filtered list holds at most one result. Not found returns ErrNotFound.
func (c *Client) GetFlowBySlug(ctx context.Context, slug string) (*Flow, error) {
	q := url.Values{"slug": {slug}}
	page, err := listPage[Flow](ctx, c, "/api/v3/flows/instances/", q)
	if err != nil {
		return nil, err
	}
	if len(page.Results) == 0 {
		return nil, ErrNotFound
	}
	return &page.Results[0], nil
}

// GetEmbeddedOutpost finds the embedded outpost by its managed marker. Its
// absence (the operator has disabled the embedded outpost) is a real
// configuration state, surfaced here as ErrNotFound for the caller to treat as
// the loud error it is.
func (c *Client) GetEmbeddedOutpost(ctx context.Context) (*Outpost, error) {
	q := url.Values{"managed": {ManagedEmbeddedOutpost}}
	page, err := listPage[Outpost](ctx, c, "/api/v3/outposts/instances/", q)
	if err != nil {
		return nil, err
	}
	if len(page.Results) == 0 {
		return nil, ErrNotFound
	}
	return &page.Results[0], nil
}

// GetOutpostByName finds an outpost by exact name. The list endpoint filters by
// search, which is a fuzzy match, so the exact name is confirmed client-side.
func (c *Client) GetOutpostByName(ctx context.Context, name string) (*Outpost, error) {
	q := url.Values{"search": {name}}
	page, err := listPage[Outpost](ctx, c, "/api/v3/outposts/instances/", q)
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

// GetGroupByName finds a group by exact name. The name filter is confirmed
// client-side so a fuzzy server match never returns the wrong group.
func (c *Client) GetGroupByName(ctx context.Context, name string) (*Group, error) {
	q := url.Values{"name": {name}}
	page, err := listPage[Group](ctx, c, "/api/v3/core/groups/", q)
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

// GetPolicyByName finds a policy by exact name against the polymorphic
// /policies/all/ list. That endpoint has no name filter, only search, so the
// query is a search and the exact name is confirmed client-side, the same shape
// as the provider lookups.
func (c *Client) GetPolicyByName(ctx context.Context, name string) (*Policy, error) {
	q := url.Values{"search": {name}}
	page, err := listPage[Policy](ctx, c, "/api/v3/policies/all/", q)
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

// GetCertificateByName finds a certificate keypair by exact name, for the case
// where the operator names a specific signing key rather than taking the
// default.
func (c *Client) GetCertificateByName(ctx context.Context, name string) (*CertificateKeyPair, error) {
	q := url.Values{"name": {name}}
	page, err := listPage[CertificateKeyPair](ctx, c, "/api/v3/crypto/certificatekeypairs/", q)
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

// GetFirstSigningKey returns the first certificate keypair that has a private
// key, ordered by name. It is the production script's default signing-key choice
// for an OIDC provider when the operator names none. No keypair with a private
// key returns ErrNotFound.
func (c *Client) GetFirstSigningKey(ctx context.Context) (*CertificateKeyPair, error) {
	q := url.Values{"has_key": {"true"}, "ordering": {"name"}}
	page, err := listPage[CertificateKeyPair](ctx, c, "/api/v3/crypto/certificatekeypairs/", q)
	if err != nil {
		return nil, err
	}
	if len(page.Results) == 0 {
		return nil, ErrNotFound
	}
	return &page.Results[0], nil
}

// GetScopeMappingByName finds an OAuth2 scope mapping by scope name, preferring
// Authentik's own managed mapping (managed marker starting with
// ManagedScopePrefix) over any user-created mapping of the same scope, exactly
// as the production script's jq does. This matters because a provider created
// with a user-created scope mapping behaves differently from one on the managed
// default. No mapping at all returns ErrNotFound.
func (c *Client) GetScopeMappingByName(ctx context.Context, scopeName string) (*ScopeMapping, error) {
	q := url.Values{"scope_name": {scopeName}}
	page, err := listPage[ScopeMapping](ctx, c, "/api/v3/propertymappings/provider/scope/", q)
	if err != nil {
		return nil, err
	}
	if len(page.Results) == 0 {
		return nil, ErrNotFound
	}
	for i := range page.Results {
		m := page.Results[i].Managed
		if m != nil && len(*m) >= len(ManagedScopePrefix) && (*m)[:len(ManagedScopePrefix)] == ManagedScopePrefix {
			return &page.Results[i], nil
		}
	}
	return &page.Results[0], nil
}

// samlPropertyMappingsPath is the SAML attribute property-mapping list endpoint.
const samlPropertyMappingsPath = "/api/v3/propertymappings/provider/saml/"

// GetSAMLPropertyMappings returns the pks of Authentik's own managed default SAML
// attribute mappings: every mapping whose managed marker starts with
// ManagedSAMLPrefix. These are always attached to an aboard SAML provider so its
// assertions carry attributes, the analog of the always-present OIDC scopes. The
// result is ordered by name for a stable request body. It walks one generous
// page, since the default set is small (seven mappings on 2025.6.4).
func (c *Client) GetSAMLPropertyMappings(ctx context.Context) ([]string, error) {
	q := pageSizeQuery(1, 100)
	page, err := listPage[SAMLPropertyMapping](ctx, c, samlPropertyMappingsPath, q)
	if err != nil {
		return nil, err
	}
	var pks []string
	for i := range page.Results {
		m := page.Results[i].Managed
		if m != nil && strings.HasPrefix(*m, ManagedSAMLPrefix) {
			pks = append(pks, page.Results[i].PK)
		}
	}
	sort.Strings(pks)
	return pks, nil
}

// GetSAMLPropertyMappingByName finds a SAML property mapping by exact display
// name, for an extra mapping the operator adds with aboard.saml.mappings. The
// list endpoint filters by fuzzy search, so the exact name is confirmed
// client-side. Not found returns ErrNotFound.
func (c *Client) GetSAMLPropertyMappingByName(ctx context.Context, name string) (*SAMLPropertyMapping, error) {
	q := url.Values{"search": {name}}
	page, err := listPage[SAMLPropertyMapping](ctx, c, samlPropertyMappingsPath, q)
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

// CreateGroup creates a group with the given name and returns it. It is the one
// group mutation aboard makes, gated behind the operator's create-groups opt-in
// at a higher layer.
func (c *Client) CreateGroup(ctx context.Context, name string) (*Group, error) {
	var out Group
	err := c.do(ctx, http.MethodPost, "/api/v3/core/groups/", nil, GroupRequest{Name: name}, &out)
	if err != nil {
		return nil, err
	}
	return &out, nil
}

// PatchOutpostProviders sets an outpost's providers list to exactly providers.
// The PATCH replaces the list wholesale, so the caller must have already merged
// in whatever it means to keep: this primitive sends the list it is given and
// nothing more. pk is the outpost's uuid.
func (c *Client) PatchOutpostProviders(ctx context.Context, pk string, providers []int) (*Outpost, error) {
	if providers == nil {
		providers = []int{}
	}
	var out Outpost
	path := "/api/v3/outposts/instances/" + url.PathEscape(pk) + "/"
	err := c.do(ctx, http.MethodPatch, path, nil, OutpostProvidersRequest{Providers: providers}, &out)
	if err != nil {
		return nil, err
	}
	return &out, nil
}

// pageSizeQuery builds the page/page_size query for a paginated walk.
func pageSizeQuery(page, pageSize int) url.Values {
	return url.Values{
		"page":      {strconv.Itoa(page)},
		"page_size": {strconv.Itoa(pageSize)},
	}
}
