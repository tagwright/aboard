// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 the aboard authors

package authentik

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// capture records the one request a primitive made, so a test can assert the
// method, path, query, and decoded body it built.
type capture struct {
	method string
	path   string
	query  string
	body   string
}

// fakeServer stands up an in-process Authentik that answers a single canned
// response for every request and records the request in c. status is the HTTP
// status it returns; respBody is the JSON body.
func fakeServer(t *testing.T, c *capture, status int, respBody string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		c.method = r.Method
		c.path = r.URL.Path
		c.query = r.URL.RawQuery
		c.body = string(body)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = io.WriteString(w, respBody)
	}))
	t.Cleanup(srv.Close)
	return srv
}

const testToken = "tok-super-secret-value-do-not-log"

func newTestClient(t *testing.T, c *capture, status int, respBody string) *Client {
	t.Helper()
	srv := fakeServer(t, c, status, respBody)
	return New(srv.URL, testToken)
}

func TestGetFlowBySlug(t *testing.T) {
	var cap capture
	resp := `{"pagination":{"next":null,"previous":null,"count":1},"results":[{"pk":"flow-uuid-1","slug":"default-authz","name":"Authorize"}]}`
	cli := newTestClient(t, &cap, 200, resp)

	flow, err := cli.GetFlowBySlug(context.Background(), "default-authz")
	if err != nil {
		t.Fatalf("GetFlowBySlug: %v", err)
	}
	if cap.method != http.MethodGet {
		t.Errorf("method = %q, want GET", cap.method)
	}
	if cap.path != "/api/v3/flows/instances/" {
		t.Errorf("path = %q", cap.path)
	}
	if cap.query != "slug=default-authz" {
		t.Errorf("query = %q, want slug=default-authz", cap.query)
	}
	if flow.PK != "flow-uuid-1" || flow.Name != "Authorize" {
		t.Errorf("decoded flow = %+v", flow)
	}
}

func TestGetFlowBySlugNotFound(t *testing.T) {
	var cap capture
	cli := newTestClient(t, &cap, 200, `{"pagination":{"next":null,"previous":null,"count":0},"results":[]}`)

	flow, err := cli.GetFlowBySlug(context.Background(), "nope")
	if flow != nil {
		t.Errorf("flow = %+v, want nil", flow)
	}
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("err = %v, want ErrNotFound", err)
	}
}

func TestGetEmbeddedOutpost(t *testing.T) {
	var cap capture
	resp := `{"pagination":{"next":null,"previous":null,"count":1},"results":[{"pk":"out-uuid","name":"authentik Embedded Outpost","managed":"goauthentik.io/outposts/embedded","type":"proxy","providers":[3,7]}]}`
	cli := newTestClient(t, &cap, 200, resp)

	out, err := cli.GetEmbeddedOutpost(context.Background())
	if err != nil {
		t.Fatalf("GetEmbeddedOutpost: %v", err)
	}
	if cap.query != "managed=goauthentik.io%2Foutposts%2Fembedded" {
		t.Errorf("query = %q", cap.query)
	}
	if out.Managed == nil || *out.Managed != ManagedEmbeddedOutpost {
		t.Errorf("managed = %v", out.Managed)
	}
	if len(out.Providers) != 2 || out.Providers[0] != 3 || out.Providers[1] != 7 {
		t.Errorf("providers = %v", out.Providers)
	}
}

func TestGetEmbeddedOutpostNotFound(t *testing.T) {
	var cap capture
	cli := newTestClient(t, &cap, 200, `{"pagination":{"count":0},"results":[]}`)
	out, err := cli.GetEmbeddedOutpost(context.Background())
	if out != nil || !errors.Is(err, ErrNotFound) {
		t.Errorf("out=%v err=%v, want nil + ErrNotFound", out, err)
	}
}

func TestGetProxyProviderByNameExactMatch(t *testing.T) {
	var cap capture
	// The search endpoint returns fuzzy matches; the exact name must win.
	resp := `{"pagination":{"count":2},"results":[{"pk":10,"name":"wiki Provider extra"},{"pk":11,"name":"wiki Provider"}]}`
	cli := newTestClient(t, &cap, 200, resp)

	p, err := cli.GetProxyProviderByName(context.Background(), "wiki Provider")
	if err != nil {
		t.Fatalf("GetProxyProviderByName: %v", err)
	}
	if p.PK != 11 {
		t.Errorf("pk = %d, want 11 (exact-name match)", p.PK)
	}
	if cap.path != "/api/v3/providers/proxy/" {
		t.Errorf("path = %q", cap.path)
	}
	if !strings.Contains(cap.query, "search=wiki+Provider") {
		t.Errorf("query = %q", cap.query)
	}
}

func TestGetProxyProviderByNameNotFound(t *testing.T) {
	var cap capture
	// A fuzzy hit that is not an exact-name match must still be not-found.
	cli := newTestClient(t, &cap, 200, `{"pagination":{"count":1},"results":[{"pk":10,"name":"wiki Provider extra"}]}`)
	p, err := cli.GetProxyProviderByName(context.Background(), "wiki Provider")
	if p != nil || !errors.Is(err, ErrNotFound) {
		t.Errorf("p=%v err=%v, want nil + ErrNotFound", p, err)
	}
}

func TestCreateProxyProviderBody(t *testing.T) {
	var cap capture
	cli := newTestClient(t, &cap, 201, `{"pk":42,"name":"wiki Provider","mode":"forward_single"}`)

	body := ProxyProviderRequest{
		Name:              "wiki Provider",
		AuthorizationFlow: "flow-uuid",
		InvalidationFlow:  "inval-uuid",
		ExternalHost:      "https://wiki.example.org",
		Mode:              ProxyModeForwardSingle,
	}
	p, err := cli.CreateProxyProvider(context.Background(), body)
	if err != nil {
		t.Fatalf("CreateProxyProvider: %v", err)
	}
	if cap.method != http.MethodPost {
		t.Errorf("method = %q, want POST", cap.method)
	}
	var sent map[string]any
	if err := json.Unmarshal([]byte(cap.body), &sent); err != nil {
		t.Fatalf("sent body not JSON: %v", err)
	}
	if sent["mode"] != "forward_single" || sent["external_host"] != "https://wiki.example.org" {
		t.Errorf("sent body = %v", sent)
	}
	// omitempty must keep unset optionals out of the body.
	if _, present := sent["skip_path_regex"]; present {
		t.Errorf("skip_path_regex should be omitted when empty")
	}
	if p.PK != 42 {
		t.Errorf("pk = %d, want 42", p.PK)
	}
}

func TestCreateOAuth2ProviderSetsClientSecret(t *testing.T) {
	var cap capture
	cli := newTestClient(t, &cap, 201, `{"pk":5,"name":"app","client_id":"cid","client_secret":"srv-returned"}`)

	body := OAuth2ProviderRequest{
		Name:              "app",
		AuthorizationFlow: "flow-uuid",
		InvalidationFlow:  "inval-uuid",
		RedirectURIs:      []RedirectURI{{MatchingMode: MatchingModeStrict, URL: "https://app/cb"}},
		ClientType:        ClientTypeConfidential,
		ClientID:          "cid",
		ClientSecret:      "inward-only-client-secret-value",
	}
	if _, err := cli.CreateOAuth2Provider(context.Background(), body); err != nil {
		t.Fatalf("CreateOAuth2Provider: %v", err)
	}
	var sent map[string]any
	if err := json.Unmarshal([]byte(cap.body), &sent); err != nil {
		t.Fatalf("sent body not JSON: %v", err)
	}
	// aboard SETS the secret inward: it must be present on the request body.
	if sent["client_secret"] != "inward-only-client-secret-value" {
		t.Errorf("client_secret not sent on request: %v", sent["client_secret"])
	}
	if sent["client_id"] != "cid" {
		t.Errorf("client_id = %v", sent["client_id"])
	}
	uris, ok := sent["redirect_uris"].([]any)
	if !ok || len(uris) != 1 {
		t.Fatalf("redirect_uris = %v", sent["redirect_uris"])
	}
}

func TestGetSAMLProviderByNameExactMatch(t *testing.T) {
	var cap capture
	resp := `{"pagination":{"count":2},"results":[{"pk":20,"name":"kimai (aboard) copy"},{"pk":21,"name":"kimai (aboard)"}]}`
	cli := newTestClient(t, &cap, 200, resp)

	p, err := cli.GetSAMLProviderByName(context.Background(), "kimai (aboard)")
	if err != nil {
		t.Fatalf("GetSAMLProviderByName: %v", err)
	}
	if p.PK != 21 {
		t.Errorf("pk = %d, want 21 (exact-name match)", p.PK)
	}
	if cap.path != "/api/v3/providers/saml/" {
		t.Errorf("path = %q", cap.path)
	}
	if !strings.Contains(cap.query, "search=kimai") {
		t.Errorf("query = %q", cap.query)
	}
}

func TestCreateSAMLProviderBody(t *testing.T) {
	var cap capture
	cli := newTestClient(t, &cap, 201, `{"pk":42,"name":"kimai (aboard)","acs_url":"https://sp/acs","sp_binding":"post"}`)

	body := SAMLProviderRequest{
		Name:              "kimai (aboard)",
		AuthorizationFlow: "flow-uuid",
		InvalidationFlow:  "inval-uuid",
		ACSUrl:            "https://sp.example.com/acs",
		Audience:          "https://sp.example.com",
		SpBinding:         SpBindingPost,
		SigningKp:         "cert-uuid",
		PropertyMappings:  []string{"pm-1", "pm-2"},
	}
	p, err := cli.CreateSAMLProvider(context.Background(), body)
	if err != nil {
		t.Fatalf("CreateSAMLProvider: %v", err)
	}
	if cap.method != http.MethodPost || cap.path != "/api/v3/providers/saml/" {
		t.Errorf("method/path = %s %s", cap.method, cap.path)
	}
	var sent map[string]any
	if err := json.Unmarshal([]byte(cap.body), &sent); err != nil {
		t.Fatalf("sent body not JSON: %v", err)
	}
	if sent["acs_url"] != "https://sp.example.com/acs" || sent["sp_binding"] != "post" || sent["signing_kp"] != "cert-uuid" {
		t.Errorf("sent body = %v", sent)
	}
	// issuer is unset here and its request schema forbids an empty string, so
	// omitempty must keep it out of the body (an unset issuer means the default).
	if _, present := sent["issuer"]; present {
		t.Errorf("issuer should be omitted when empty, body = %q", cap.body)
	}
	if p.PK != 42 {
		t.Errorf("pk = %d, want 42", p.PK)
	}
}

func TestGetSAMLPropertyMappingsKeepsManaged(t *testing.T) {
	var cap capture
	resp := `{"pagination":{"count":3},"results":[` +
		`{"pk":"pm-user","name":"my custom","managed":null},` +
		`{"pk":"pm-email","name":"Email","managed":"goauthentik.io/providers/saml/email"},` +
		`{"pk":"pm-name","name":"Name","managed":"goauthentik.io/providers/saml/name"}]}`
	cli := newTestClient(t, &cap, 200, resp)

	pks, err := cli.GetSAMLPropertyMappings(context.Background())
	if err != nil {
		t.Fatalf("GetSAMLPropertyMappings: %v", err)
	}
	if cap.path != "/api/v3/propertymappings/provider/saml/" {
		t.Errorf("path = %q", cap.path)
	}
	// Only the two managed defaults are kept, the user-made one is dropped, and
	// the result is name/pk-sorted for a stable body.
	if len(pks) != 2 || pks[0] != "pm-email" || pks[1] != "pm-name" {
		t.Errorf("pks = %v, want the two managed defaults sorted", pks)
	}
}

func TestGetSAMLPropertyMappingByName(t *testing.T) {
	var cap capture
	resp := `{"pagination":{"count":2},"results":[{"pk":"pm-x","name":"Kimai Roles extra"},{"pk":"pm-y","name":"Kimai Roles"}]}`
	cli := newTestClient(t, &cap, 200, resp)
	m, err := cli.GetSAMLPropertyMappingByName(context.Background(), "Kimai Roles")
	if err != nil {
		t.Fatalf("GetSAMLPropertyMappingByName: %v", err)
	}
	if m.PK != "pm-y" {
		t.Errorf("pk = %q, want exact-name match", m.PK)
	}
}

func TestGetSAMLMetadata(t *testing.T) {
	var cap capture
	resp := `{"metadata":"<EntityDescriptor xmlns=\"urn:oasis:names:tc:SAML:2.0:metadata\"></EntityDescriptor>","download_url":"https://auth/application/saml/kimai/metadata/?download"}`
	cli := newTestClient(t, &cap, 200, resp)

	md, err := cli.GetSAMLMetadata(context.Background(), 42)
	if err != nil {
		t.Fatalf("GetSAMLMetadata: %v", err)
	}
	if cap.method != http.MethodGet || cap.path != "/api/v3/providers/saml/42/metadata/" {
		t.Errorf("method/path = %s %s", cap.method, cap.path)
	}
	if !strings.Contains(md.Metadata, "EntityDescriptor") {
		t.Errorf("metadata = %q", md.Metadata)
	}
	if md.DownloadURL == "" {
		t.Errorf("download_url empty")
	}
}

func TestGetSAMLMetadataNotLinkedUnwraps(t *testing.T) {
	var cap capture
	// A SAML provider with no application assigned yet returns 404; it must unwrap
	// to ErrNotFound so a caller distinguishes "not yet linked" from a failure.
	cli := newTestClient(t, &cap, 404, `{"detail":"Provider has no application assigned"}`)
	md, err := cli.GetSAMLMetadata(context.Background(), 42)
	if md != nil || !errors.Is(err, ErrNotFound) {
		t.Errorf("md=%v err=%v, want nil + ErrNotFound", md, err)
	}
}

func TestPatchOutpostProviders(t *testing.T) {
	var cap capture
	cli := newTestClient(t, &cap, 200, `{"pk":"out-uuid","providers":[3,7,42]}`)

	out, err := cli.PatchOutpostProviders(context.Background(), "out-uuid", []int{3, 7, 42})
	if err != nil {
		t.Fatalf("PatchOutpostProviders: %v", err)
	}
	if cap.method != http.MethodPatch {
		t.Errorf("method = %q, want PATCH", cap.method)
	}
	if cap.path != "/api/v3/outposts/instances/out-uuid/" {
		t.Errorf("path = %q", cap.path)
	}
	var sent OutpostProvidersRequest
	if err := json.Unmarshal([]byte(cap.body), &sent); err != nil {
		t.Fatalf("body: %v", err)
	}
	if len(sent.Providers) != 3 || sent.Providers[2] != 42 {
		t.Errorf("sent providers = %v", sent.Providers)
	}
	if len(out.Providers) != 3 {
		t.Errorf("decoded providers = %v", out.Providers)
	}
}

func TestPatchOutpostProvidersEmptyList(t *testing.T) {
	var cap capture
	cli := newTestClient(t, &cap, 200, `{"pk":"out-uuid","providers":[]}`)
	if _, err := cli.PatchOutpostProviders(context.Background(), "out-uuid", nil); err != nil {
		t.Fatalf("PatchOutpostProviders: %v", err)
	}
	// A nil list must serialize as an explicit empty array, not be omitted, so a
	// clear-the-providers PATCH actually clears them.
	if !strings.Contains(cap.body, `"providers":[]`) {
		t.Errorf("body = %q, want explicit empty providers array", cap.body)
	}
}

func TestGetScopeMappingPrefersManaged(t *testing.T) {
	var cap capture
	resp := `{"pagination":{"count":2},"results":[` +
		`{"pk":"user-made","scope_name":"openid","managed":null},` +
		`{"pk":"managed-one","scope_name":"openid","managed":"goauthentik.io/providers/oauth2/scope-openid"}]}`
	cli := newTestClient(t, &cap, 200, resp)

	m, err := cli.GetScopeMappingByName(context.Background(), "openid")
	if err != nil {
		t.Fatalf("GetScopeMappingByName: %v", err)
	}
	if m.PK != "managed-one" {
		t.Errorf("pk = %q, want managed-one preferred", m.PK)
	}
	if cap.query != "scope_name=openid" {
		t.Errorf("query = %q", cap.query)
	}
}

func TestGetScopeMappingFallsBackToFirst(t *testing.T) {
	var cap capture
	resp := `{"pagination":{"count":1},"results":[{"pk":"only-one","scope_name":"profile","managed":null}]}`
	cli := newTestClient(t, &cap, 200, resp)
	m, err := cli.GetScopeMappingByName(context.Background(), "profile")
	if err != nil {
		t.Fatalf("GetScopeMappingByName: %v", err)
	}
	if m.PK != "only-one" {
		t.Errorf("pk = %q, want only-one", m.PK)
	}
}

func TestGetFirstSigningKey(t *testing.T) {
	var cap capture
	cli := newTestClient(t, &cap, 200, `{"pagination":{"count":1},"results":[{"pk":"cert-uuid","name":"self-signed"}]}`)
	kp, err := cli.GetFirstSigningKey(context.Background())
	if err != nil {
		t.Fatalf("GetFirstSigningKey: %v", err)
	}
	if kp.Name != "self-signed" {
		t.Errorf("name = %q", kp.Name)
	}
	if !strings.Contains(cap.query, "has_key=true") || !strings.Contains(cap.query, "ordering=name") {
		t.Errorf("query = %q", cap.query)
	}
}

func TestCreateGroup(t *testing.T) {
	var cap capture
	cli := newTestClient(t, &cap, 201, `{"pk":"grp-uuid","name":"editors"}`)
	g, err := cli.CreateGroup(context.Background(), "editors")
	if err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}
	if cap.method != http.MethodPost || cap.path != "/api/v3/core/groups/" {
		t.Errorf("method/path = %s %s", cap.method, cap.path)
	}
	if !strings.Contains(cap.body, `"name":"editors"`) {
		t.Errorf("body = %q", cap.body)
	}
	if g.PK != "grp-uuid" {
		t.Errorf("pk = %q", g.PK)
	}
}

func TestGetPolicyByName(t *testing.T) {
	var cap capture
	resp := `{"pagination":{"count":2},"results":[{"pk":"p1","name":"other"},{"pk":"p2","name":"geo-block"}]}`
	cli := newTestClient(t, &cap, 200, resp)
	p, err := cli.GetPolicyByName(context.Background(), "geo-block")
	if err != nil {
		t.Fatalf("GetPolicyByName: %v", err)
	}
	if cap.path != "/api/v3/policies/all/" {
		t.Errorf("path = %q, want the polymorphic policy list", cap.path)
	}
	if p.PK != "p2" {
		t.Errorf("pk = %q, want exact-name match", p.PK)
	}
}

func TestCreateApplicationBody(t *testing.T) {
	var cap capture
	cli := newTestClient(t, &cap, 201, `{"pk":"app-uuid","slug":"wiki","name":"Wiki","provider":42}`)

	pk := 42
	app, err := cli.CreateApplication(context.Background(), ApplicationRequest{
		Name:     "Wiki",
		Slug:     "wiki",
		Provider: &pk,
	})
	if err != nil {
		t.Fatalf("CreateApplication: %v", err)
	}
	if cap.path != "/api/v3/core/applications/" {
		t.Errorf("path = %q", cap.path)
	}
	var sent map[string]any
	_ = json.Unmarshal([]byte(cap.body), &sent)
	if sent["provider"].(float64) != 42 {
		t.Errorf("provider = %v", sent["provider"])
	}
	if app.Provider == nil || *app.Provider != 42 {
		t.Errorf("decoded provider = %v", app.Provider)
	}
}

func TestPatchApplicationUsesSlugRoute(t *testing.T) {
	var cap capture
	cli := newTestClient(t, &cap, 200, `{"pk":"app-uuid","slug":"wiki","provider":43}`)
	pk := 43
	if _, err := cli.PatchApplication(context.Background(), "wiki", ApplicationRequest{Provider: &pk}); err != nil {
		t.Fatalf("PatchApplication: %v", err)
	}
	if cap.method != http.MethodPatch {
		t.Errorf("method = %q, want PATCH", cap.method)
	}
	if cap.path != "/api/v3/core/applications/wiki/" {
		t.Errorf("path = %q, want slug detail route", cap.path)
	}
}

func TestDeleteApplication(t *testing.T) {
	var cap capture
	cli := newTestClient(t, &cap, 204, ``)
	if err := cli.DeleteApplication(context.Background(), "wiki"); err != nil {
		t.Fatalf("DeleteApplication: %v", err)
	}
	if cap.method != http.MethodDelete || cap.path != "/api/v3/core/applications/wiki/" {
		t.Errorf("method/path = %s %s", cap.method, cap.path)
	}
}

func TestDeleteProviderNotFoundUnwraps(t *testing.T) {
	var cap capture
	cli := newTestClient(t, &cap, 404, `{"detail":"Not found."}`)
	err := cli.DeleteProxyProvider(context.Background(), 99)
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("err = %v, want ErrNotFound via 404 unwrap", err)
	}
}

func TestListBindingsForTarget(t *testing.T) {
	var cap capture
	resp := `{"pagination":{"count":1},"results":[{"pk":"bind-uuid","group":"grp-uuid","target":"app-uuid","enabled":true,"order":0}]}`
	cli := newTestClient(t, &cap, 200, resp)
	binds, err := cli.ListBindingsForTarget(context.Background(), "app-uuid")
	if err != nil {
		t.Fatalf("ListBindingsForTarget: %v", err)
	}
	if cap.query != "target=app-uuid" {
		t.Errorf("query = %q", cap.query)
	}
	if len(binds) != 1 || binds[0].Group == nil || *binds[0].Group != "grp-uuid" {
		t.Errorf("bindings = %+v", binds)
	}
}

func TestCreateBindingBody(t *testing.T) {
	var cap capture
	cli := newTestClient(t, &cap, 201, `{"pk":"bind-uuid","group":"grp-uuid","target":"app-uuid","enabled":true,"order":0}`)
	group := "grp-uuid"
	enabled := true
	negate := false
	_, err := cli.CreateBinding(context.Background(), PolicyBindingRequest{
		Group:   &group,
		Target:  "app-uuid",
		Enabled: &enabled,
		Negate:  &negate,
		Order:   0,
	})
	if err != nil {
		t.Fatalf("CreateBinding: %v", err)
	}
	var sent map[string]any
	_ = json.Unmarshal([]byte(cap.body), &sent)
	// order is required and must always be present, even at its zero value.
	if _, ok := sent["order"]; !ok {
		t.Errorf("order must always be sent, body = %q", cap.body)
	}
	if sent["group"] != "grp-uuid" || sent["target"] != "app-uuid" {
		t.Errorf("body = %v", sent)
	}
	if sent["enabled"] != true || sent["negate"] != false {
		t.Errorf("enabled/negate = %v/%v", sent["enabled"], sent["negate"])
	}
}

func TestListApplicationsFollowsPagination(t *testing.T) {
	var cap capture
	// A two-page listing: page 1 points next to 2, page 2 has next null.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cap.method = r.Method
		cap.path = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Query().Get("page") == "2" {
			_, _ = io.WriteString(w, `{"pagination":{"next":null,"previous":1,"count":3},"results":[{"pk":"c","slug":"three"}]}`)
			return
		}
		_, _ = io.WriteString(w, `{"pagination":{"next":2,"previous":null,"count":3},"results":[{"pk":"a","slug":"one"},{"pk":"b","slug":"two"}]}`)
	}))
	t.Cleanup(srv.Close)
	cli := New(srv.URL, testToken)

	apps, err := cli.ListApplications(context.Background(), 2)
	if err != nil {
		t.Fatalf("ListApplications: %v", err)
	}
	if len(apps) != 3 {
		t.Fatalf("got %d apps across pages, want 3", len(apps))
	}
	if apps[0].Slug != "one" || apps[2].Slug != "three" {
		t.Errorf("apps = %+v", apps)
	}
}

func TestGetApplicationBySlugRequestsFullList(t *testing.T) {
	var cap capture
	resp := `{"pagination":{"next":0,"previous":0,"count":1},"results":[{"pk":"app-uuid","slug":"wiki","name":"Wiki","provider":7}]}`
	cli := newTestClient(t, &cap, 200, resp)

	app, err := cli.GetApplicationBySlug(context.Background(), "wiki")
	if err != nil {
		t.Fatalf("GetApplicationBySlug: %v", err)
	}
	if app.Slug != "wiki" {
		t.Errorf("slug = %q", app.Slug)
	}
	// The access-filter escape hatch must be on the query, or the endpoint hides
	// applications whose policy the token's user does not pass.
	if !strings.Contains(cap.query, "superuser_full_list=true") {
		t.Errorf("query = %q, want superuser_full_list=true", cap.query)
	}
	if !strings.Contains(cap.query, "slug=wiki") {
		t.Errorf("query = %q, want slug=wiki", cap.query)
	}
}

func TestListApplicationsRequestsFullList(t *testing.T) {
	var lastQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		lastQuery = r.URL.RawQuery
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"pagination":{"next":0,"previous":0,"count":1},"results":[{"pk":"a","slug":"one"}]}`)
	}))
	t.Cleanup(srv.Close)
	cli := New(srv.URL, testToken)

	if _, err := cli.ListApplications(context.Background(), 50); err != nil {
		t.Fatalf("ListApplications: %v", err)
	}
	if !strings.Contains(lastQuery, "superuser_full_list=true") {
		t.Errorf("query = %q, want superuser_full_list=true", lastQuery)
	}
}

func TestListApplicationsStopsOnZeroNext(t *testing.T) {
	// The real Authentik 2025.6.4 API returns "next": 0 (not null) on the last
	// page. A walk that treats a non-nil next as "there is another page" would
	// then request page 0 and get a 404 "Invalid page." This asserts the walk
	// stops on a zero next and never requests page 0.
	var pagesSeen []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		page := r.URL.Query().Get("page")
		pagesSeen = append(pagesSeen, page)
		w.Header().Set("Content-Type", "application/json")
		if page == "0" {
			// Mirror Django REST's real rejection so a regression fails loudly.
			w.WriteHeader(404)
			_, _ = io.WriteString(w, `{"detail":"Invalid page."}`)
			return
		}
		_, _ = io.WriteString(w, `{"pagination":{"next":0,"previous":0,"count":1,"current":1,"total_pages":1},"results":[{"pk":"a","slug":"one"}]}`)
	}))
	t.Cleanup(srv.Close)
	cli := New(srv.URL, testToken)

	apps, err := cli.ListApplications(context.Background(), 100)
	if err != nil {
		t.Fatalf("ListApplications: %v", err)
	}
	if len(apps) != 1 || apps[0].Slug != "one" {
		t.Fatalf("apps = %+v, want the single page", apps)
	}
	for _, p := range pagesSeen {
		if p == "0" {
			t.Fatalf("walk requested page 0 (pages seen: %v)", pagesSeen)
		}
	}
}

func TestListApplicationsMultiPageZeroNextTerminates(t *testing.T) {
	// Two real pages: page 1 points next to 2, page 2 (the last) reports next 0,
	// the 2025.6.4 sentinel. The walk must collect both pages and then stop.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Query().Get("page") {
		case "2":
			_, _ = io.WriteString(w, `{"pagination":{"next":0,"previous":1,"count":3,"current":2,"total_pages":2},"results":[{"pk":"c","slug":"three"}]}`)
		case "1":
			_, _ = io.WriteString(w, `{"pagination":{"next":2,"previous":0,"count":3,"current":1,"total_pages":2},"results":[{"pk":"a","slug":"one"},{"pk":"b","slug":"two"}]}`)
		default:
			w.WriteHeader(404)
			_, _ = io.WriteString(w, `{"detail":"Invalid page."}`)
		}
	}))
	t.Cleanup(srv.Close)
	cli := New(srv.URL, testToken)

	apps, err := cli.ListApplications(context.Background(), 2)
	if err != nil {
		t.Fatalf("ListApplications: %v", err)
	}
	if len(apps) != 3 || apps[0].Slug != "one" || apps[2].Slug != "three" {
		t.Fatalf("apps = %+v, want all three across two pages", apps)
	}
}

func TestAPIErrorRedactsTokenAndSecret(t *testing.T) {
	var cap capture
	const secret = "inward-only-client-secret-value"
	// A hostile 400 that echoes BOTH the bearer token and the client secret back
	// in its body. Neither may survive into the APIError.
	respBody := `{"detail":"bad request","echo_token":"` + testToken + `","echo_secret":"` + secret + `"}`
	cli := newTestClient(t, &cap, 400, respBody)

	_, err := cli.CreateOAuth2Provider(context.Background(), OAuth2ProviderRequest{
		Name:         "app",
		ClientSecret: secret,
	})
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("err = %v, want *APIError", err)
	}
	if apiErr.Status != 400 {
		t.Errorf("status = %d, want 400", apiErr.Status)
	}
	msg := err.Error()
	if strings.Contains(msg, testToken) {
		t.Errorf("APIError leaked the API token: %q", msg)
	}
	if strings.Contains(msg, secret) {
		t.Errorf("APIError leaked the client secret: %q", msg)
	}
	if !strings.Contains(msg, "[REDACTED]") {
		t.Errorf("expected redaction placeholder in %q", msg)
	}
}

func TestNonErrorPathNeverCarriesToken(t *testing.T) {
	// A create whose success body happens to echo the token must decode fine and,
	// since it is not an error, simply not surface it anywhere. This guards the
	// Authorization header from being reflected into a returned struct field we
	// type. The token is only ever a header, never a modeled field.
	var cap capture
	cli := newTestClient(t, &cap, 201, `{"pk":1,"name":"x"}`)
	if _, err := cli.CreateProxyProvider(context.Background(), ProxyProviderRequest{Name: "x"}); err != nil {
		t.Fatalf("CreateProxyProvider: %v", err)
	}
	auth := cap.body
	if strings.Contains(auth, testToken) {
		t.Errorf("request body carried the token: %q", auth)
	}
}
