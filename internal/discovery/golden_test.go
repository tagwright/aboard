// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 the aboard authors

package discovery

import (
	"reflect"
	"testing"

	"github.com/tagwright/aboard/internal/config"
	"github.com/tagwright/aboard/internal/spec"
)

// The four worked examples from the Aboard Label Grammar, asserted as golden
// inputs so a change to the parser that breaks the contract fails here.

// (a) Canonical minimal: whole-host forward-auth, the hero demo. One aboard
// label, host inferred from the single router.
func TestGoldenWhoami(t *testing.T) {
	labels := map[string]string{
		"traefik.enable":                          "true",
		"traefik.http.routers.whoami.rule":        "Host(`whoami.example.com`)",
		"traefik.http.routers.whoami.entrypoints": "websecure",
		"traefik.http.routers.whoami.middlewares": "authentik@docker",
		"aboard.enable":                           "true",
	}
	sp, issues := Discover(&config.Config{Proxy: config.ProxyTraefik}, Input{ContainerName: "whoami", Labels: labels})
	if len(issues) != 0 {
		t.Fatalf("hero demo must have no issues, got %v", issues)
	}
	if !sp.Enable || sp.Name != "whoami" || sp.Slug != "whoami" || sp.Title != "whoami" {
		t.Errorf("identity: Enable=%v Name=%q Slug=%q Title=%q", sp.Enable, sp.Name, sp.Slug, sp.Title)
	}
	if sp.Provider != spec.ProviderForwardAuth {
		t.Errorf("provider = %q, want forwardauth", sp.Provider)
	}
	if sp.Host != "whoami.example.com" {
		t.Errorf("host = %q, want whoami.example.com", sp.Host)
	}
	if sp.GroupsSet {
		t.Error("no aboard.groups means GroupsSet false (fleet default applies at reconcile)")
	}
	if sp.Require != spec.RequireAny {
		t.Errorf("require = %q, want any", sp.Require)
	}
}

// The org doorway spelling of (a) must produce the identical result.
func TestGoldenWhoamiOrgDoorway(t *testing.T) {
	labels := map[string]string{
		"traefik.http.routers.whoami.rule": "Host(`whoami.example.com`)",
		"tagwright.auth.enable":            "true",
	}
	sp, issues := Discover(&config.Config{Proxy: config.ProxyTraefik}, Input{ContainerName: "whoami", Labels: labels})
	if len(issues) != 0 {
		t.Fatalf("org doorway must have no issues, got %v", issues)
	}
	if !sp.Enable || sp.Host != "whoami.example.com" {
		t.Errorf("Enable=%v Host=%q", sp.Enable, sp.Host)
	}
}

// (b) Group-gated, explicit title.
func TestGoldenNutrition(t *testing.T) {
	labels := map[string]string{
		"traefik.http.routers.nutrition.rule":        "Host(`nutrition.natecalvert.org`)",
		"traefik.http.routers.nutrition.middlewares": "authentik@docker",
		"aboard.enable":                              "true",
		"aboard.title":                               "Nutrition",
		"aboard.groups":                              "nutrition-users",
	}
	sp, issues := Discover(&config.Config{Proxy: config.ProxyTraefik}, Input{ContainerName: "nutrition", Labels: labels})
	if len(issues) != 0 {
		t.Fatalf("nutrition must have no issues, got %v", issues)
	}
	if sp.Title != "Nutrition" {
		t.Errorf("title = %q, want Nutrition", sp.Title)
	}
	if !sp.GroupsSet || !reflect.DeepEqual(sp.Groups, []string{"nutrition-users"}) {
		t.Errorf("groups: GroupsSet=%v Groups=%v", sp.GroupsSet, sp.Groups)
	}
	if sp.Host != "nutrition.natecalvert.org" {
		t.Errorf("host = %q", sp.Host)
	}
}

// (c) Mixed host: public site, protected admin subpath. Two routers, one
// distinct host, aboard.traefik.routers names the protected router.
func TestGoldenTravels(t *testing.T) {
	labels := map[string]string{
		"traefik.http.routers.travels.rule":              "Host(`travels.natecalvert.org`)",
		"traefik.http.routers.travels.priority":          "1",
		"traefik.http.routers.travels-admin.rule":        "Host(`travels.natecalvert.org`) && PathPrefix(`/admin`)",
		"traefik.http.routers.travels-admin.middlewares": "authentik@docker",
		"traefik.http.routers.travels-admin.priority":    "10",
		"aboard.enable":                                  "true",
		"aboard.title":                                   "Travels",
		"aboard.traefik.routers":                         "travels-admin",
	}
	sp, issues := Discover(&config.Config{Proxy: config.ProxyTraefik}, Input{ContainerName: "travels", Labels: labels})
	if len(issues) != 0 {
		t.Fatalf("travels must have no issues, got %v", issues)
	}
	if sp.Host != "travels.natecalvert.org" {
		t.Errorf("host = %q, want travels.natecalvert.org", sp.Host)
	}
	if !reflect.DeepEqual(sp.ForwardAuth.TraefikRouters, []string{"travels-admin"}) {
		t.Errorf("traefik routers = %v, want [travels-admin]", sp.ForwardAuth.TraefikRouters)
	}
}

// (d) OIDC, secret flows inward.
func TestGoldenGitea(t *testing.T) {
	labels := map[string]string{
		"traefik.http.routers.gitea.rule": "Host(`git.natecalvert.org`)",
		"aboard.enable":                   "true",
		"aboard.provider":                 "oidc",
		"aboard.title":                    "Gitea",
		"aboard.oidc.redirect":            "https://git.natecalvert.org/user/oauth2/authentik/callback",
		"aboard.oidc.secret":              "gitea-oidc-client-secret",
		"aboard.groups":                   "public-users",
	}
	sp, issues := Discover(&config.Config{Proxy: config.ProxyTraefik}, Input{ContainerName: "gitea", Labels: labels})
	if len(issues) != 0 {
		t.Fatalf("gitea must have no issues, got %v", issues)
	}
	if sp.Provider != spec.ProviderOIDC {
		t.Errorf("provider = %q, want oidc", sp.Provider)
	}
	if sp.Host != "git.natecalvert.org" {
		t.Errorf("host = %q", sp.Host)
	}
	if sp.OIDC.ClientKind != spec.ClientConfidential {
		t.Errorf("client kind = %q, want confidential", sp.OIDC.ClientKind)
	}
	if sp.OIDC.ClientID != "gitea" { // defaults to the slug
		t.Errorf("client id = %q, want gitea", sp.OIDC.ClientID)
	}
	if sp.OIDC.SecretName != "gitea-oidc-client-secret" {
		t.Errorf("secret name = %q", sp.OIDC.SecretName)
	}
	want := []string{"https://git.natecalvert.org/user/oauth2/authentik/callback"}
	if !reflect.DeepEqual(sp.OIDC.Redirect, want) {
		t.Errorf("redirect = %v, want %v", sp.OIDC.Redirect, want)
	}
	if !reflect.DeepEqual(sp.Groups, []string{"public-users"}) {
		t.Errorf("groups = %v", sp.Groups)
	}
}
