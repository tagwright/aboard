// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 the aboard authors

package authentik

import (
	"context"
	"net/http"
	"net/url"
)

const (
	applicationsPath = "/api/v3/core/applications/"
	bindingsPath     = "/api/v3/policies/bindings/"
)

// GetApplicationBySlug finds an application by slug through the list filter. The
// slug is unique, so the filtered list holds at most one result. Not found
// returns ErrNotFound. (Mutations below address the application by its slug
// detail route, since slug is its REST lookup field.)
//
// superuser_full_list=true is REQUIRED and verified against the live 2025.6.4
// API: the applications LIST endpoint otherwise applies per-application access
// filtering to the result set (the policy engine is run for the token's user and
// apps it may not launch are dropped, while the pagination count is computed
// BEFORE that filter, so count can exceed the results). Without this flag a
// reconciler cannot see an application it manages but whose access policy its own
// service-account user does not pass, and would then try to CREATE a duplicate
// and get a 400 slug-conflict. A reconciler must see every application
// deterministically, which is exactly what this flag gives a superuser token.
func (c *Client) GetApplicationBySlug(ctx context.Context, slug string) (*Application, error) {
	q := url.Values{"slug": {slug}, "superuser_full_list": {"true"}}
	page, err := listPage[Application](ctx, c, applicationsPath, q)
	if err != nil {
		return nil, err
	}
	for i := range page.Results {
		if page.Results[i].Slug == slug {
			return &page.Results[i], nil
		}
	}
	return nil, ErrNotFound
}

// CreateApplication creates an application from body and returns it.
func (c *Client) CreateApplication(ctx context.Context, body ApplicationRequest) (*Application, error) {
	var out Application
	if err := c.do(ctx, http.MethodPost, applicationsPath, nil, body, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// PatchApplication patches the application identified by slug from body and
// returns the updated application. The detail route keys on slug, not pk, which
// is Authentik's lookup field for the Application resource.
func (c *Client) PatchApplication(ctx context.Context, slug string, body ApplicationRequest) (*Application, error) {
	var out Application
	path := applicationsPath + url.PathEscape(slug) + "/"
	if err := c.do(ctx, http.MethodPatch, path, nil, body, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// DeleteApplication deletes the application identified by slug. A 404 unwraps to
// ErrNotFound, so an already-absent application is a caller-decidable no-op.
func (c *Client) DeleteApplication(ctx context.Context, slug string) error {
	path := applicationsPath + url.PathEscape(slug) + "/"
	return c.do(ctx, http.MethodDelete, path, nil, nil, nil)
}

// SetApplicationIconURL sets the application's library icon to iconURL through
// the dedicated set_icon_url action, POST
// /api/v3/core/applications/{slug}/set_icon_url/ with a JSON FilePathRequest
// body. This is the only way to set the icon: meta_icon is read-only on
// ApplicationRequest, so it cannot ride along on a normal create or PATCH. The
// icon is a cosmetic field, so the reconciler calls this only when the label
// declared one (declared-means-managed). A 404 unwraps to ErrNotFound.
func (c *Client) SetApplicationIconURL(ctx context.Context, slug, iconURL string) error {
	path := applicationsPath + url.PathEscape(slug) + "/set_icon_url/"
	return c.do(ctx, http.MethodPost, path, nil, FilePathRequest{URL: iconURL}, nil)
}

// ListApplications returns every application, following pagination.next across
// pages with an explicit page_size. It is the one place a full-fleet listing can
// span multiple pages (the reconcile-on-boot pass), so unlike the script's
// single-app filters it must not assume a single page.
func (c *Client) ListApplications(ctx context.Context, pageSize int) ([]Application, error) {
	if pageSize <= 0 {
		pageSize = 100
	}
	var all []Application
	page := 1
	for {
		// superuser_full_list=true is required so the orphan scan sees EVERY
		// application, not only the ones the token's user is allowed to launch: the
		// list endpoint otherwise access-filters the result set (see
		// GetApplicationBySlug). An orphan scan that silently misses filtered apps
		// would under-report orphans and let prune leave live objects behind.
		q := pageSizeQuery(page, pageSize)
		q.Set("superuser_full_list", "true")
		resp, err := listPage[Application](ctx, c, applicationsPath, q)
		if err != nil {
			return nil, err
		}
		all = append(all, resp.Results...)
		// On Authentik 2025.6.4 the pagination "next" field is a page NUMBER that
		// is 0 (not null) on the last page, verified against the live API. So a
		// non-nil Next is not by itself "there is another page": the walk stops
		// unless Next names a page strictly beyond the current one. Treating 0 as
		// "keep going" is exactly what made this loop request page 0 and get a 404
		// "Invalid page." from Django REST.
		if resp.Pagination.Next == nil || *resp.Pagination.Next <= page {
			break
		}
		page = *resp.Pagination.Next
	}
	return all, nil
}

// ListBindingsForTarget returns every policy binding whose target is the given
// application pk. It is the reconciler's input for the strict binding-ownership
// pass. An application with no bindings yields an empty slice and a nil error,
// which is not a not-found condition.
func (c *Client) ListBindingsForTarget(ctx context.Context, appPK string) ([]PolicyBinding, error) {
	q := url.Values{"target": {appPK}}
	page, err := listPage[PolicyBinding](ctx, c, bindingsPath, q)
	if err != nil {
		return nil, err
	}
	return page.Results, nil
}

// CreateBinding creates a policy binding from body and returns it.
func (c *Client) CreateBinding(ctx context.Context, body PolicyBindingRequest) (*PolicyBinding, error) {
	var out PolicyBinding
	if err := c.do(ctx, http.MethodPost, bindingsPath, nil, body, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// DeleteBinding deletes the policy binding with the given uuid pk. A 404 unwraps
// to ErrNotFound.
func (c *Client) DeleteBinding(ctx context.Context, pk string) error {
	path := bindingsPath + url.PathEscape(pk) + "/"
	return c.do(ctx, http.MethodDelete, path, nil, nil, nil)
}
