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

// GetApplicationBySlug finds an application by slug through the list filter,
// matching the production script. The slug is unique, so the filtered list holds
// at most one result. Not found returns ErrNotFound. (Mutations below address the
// application by its slug detail route, since slug is its REST lookup field.)
func (c *Client) GetApplicationBySlug(ctx context.Context, slug string) (*Application, error) {
	q := url.Values{"slug": {slug}}
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
		q := pageSizeQuery(page, pageSize)
		resp, err := listPage[Application](ctx, c, applicationsPath, q)
		if err != nil {
			return nil, err
		}
		all = append(all, resp.Results...)
		if resp.Pagination.Next == nil {
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
