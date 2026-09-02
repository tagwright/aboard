// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 the aboard authors

package reconcile

import (
	"context"

	"github.com/tagwright/aboard/internal/authentik"
	"github.com/tagwright/aboard/internal/config"
	"github.com/tagwright/aboard/internal/spec"
)

// fakeAPI is an in-memory API. It records the ordered sequence of method calls
// (so the attach-last ordering contract is provable), stores canned lookups, and
// records what was created, patched, and deleted. errOn forces a chosen method
// to fail, which is how the tests drive a mid-reconcile failure and prove the
// attach is skipped.
type fakeAPI struct {
	flows           map[string]*authentik.Flow
	proxyByName     map[string]*authentik.ProxyProvider
	oauthByName     map[string]*authentik.OAuth2Provider
	samlByName      map[string]*authentik.SAMLProvider
	providerRefByPK map[int]*authentik.ProviderRef
	appBySlug      map[string]*authentik.Application
	allProviders   []authentik.AllProvider
	groups         map[string]*authentik.Group
	policies       map[string]*authentik.Policy
	certs          map[string]*authentik.CertificateKeyPair
	firstKey       *authentik.CertificateKeyPair
	scopes         map[string]*authentik.ScopeMapping
	embedded       *authentik.Outpost
	outpostsByName map[string]*authentik.Outpost
	bindings       map[string][]authentik.PolicyBinding

	calls []string
	errOn map[string]error

	nextProviderPK int
	nextBindingN   int

	createdProxy    []authentik.ProxyProviderRequest
	patchedProxy    map[int]authentik.ProxyProviderRequest
	createdOAuth    []authentik.OAuth2ProviderRequest
	patchedOAuth    map[int]authentik.OAuth2ProviderRequest
	createdSAML     []authentik.SAMLProviderRequest
	patchedSAML     map[int]authentik.SAMLProviderRequest
	samlMappings    []string
	samlMappingByName map[string]*authentik.SAMLPropertyMapping
	createdApps     []authentik.ApplicationRequest
	patchedApps     map[string]authentik.ApplicationRequest
	createdBindings []authentik.PolicyBindingRequest
	deletedBindings []string
	createdGroups   []string
	iconSet         map[string]string
	patchedOutpost  []int
	deletedProxyPKs []int
	deletedOAuthPKs []int
	deletedSAMLPKs  []int
	deletedApps     []string
}

func newFake() *fakeAPI {
	return &fakeAPI{
		flows:           map[string]*authentik.Flow{},
		proxyByName:     map[string]*authentik.ProxyProvider{},
		oauthByName:     map[string]*authentik.OAuth2Provider{},
		samlByName:      map[string]*authentik.SAMLProvider{},
		samlMappingByName: map[string]*authentik.SAMLPropertyMapping{},
		providerRefByPK: map[int]*authentik.ProviderRef{},
		appBySlug:      map[string]*authentik.Application{},
		groups:         map[string]*authentik.Group{},
		policies:       map[string]*authentik.Policy{},
		certs:          map[string]*authentik.CertificateKeyPair{},
		scopes:         map[string]*authentik.ScopeMapping{},
		outpostsByName: map[string]*authentik.Outpost{},
		bindings:       map[string][]authentik.PolicyBinding{},
		errOn:          map[string]error{},
		patchedProxy:   map[int]authentik.ProxyProviderRequest{},
		patchedOAuth:   map[int]authentik.OAuth2ProviderRequest{},
		patchedSAML:    map[int]authentik.SAMLProviderRequest{},
		patchedApps:    map[string]authentik.ApplicationRequest{},
		iconSet:        map[string]string{},
	}
}

// rec records a call and returns any injected error for it.
func (f *fakeAPI) rec(name string) error {
	f.calls = append(f.calls, name)
	return f.errOn[name]
}

// callIndex returns the index of the first call to name, or -1.
func (f *fakeAPI) callIndex(name string) int {
	for i, c := range f.calls {
		if c == name {
			return i
		}
	}
	return -1
}

// called reports whether name was ever called.
func (f *fakeAPI) called(name string) bool { return f.callIndex(name) >= 0 }

func (f *fakeAPI) GetFlowBySlug(_ context.Context, slug string) (*authentik.Flow, error) {
	if err := f.rec("GetFlowBySlug"); err != nil {
		return nil, err
	}
	if fl, ok := f.flows[slug]; ok {
		return fl, nil
	}
	return nil, authentik.ErrNotFound
}

func (f *fakeAPI) GetProxyProviderByName(_ context.Context, name string) (*authentik.ProxyProvider, error) {
	if err := f.rec("GetProxyProviderByName"); err != nil {
		return nil, err
	}
	if p, ok := f.proxyByName[name]; ok {
		return p, nil
	}
	return nil, authentik.ErrNotFound
}

func (f *fakeAPI) CreateProxyProvider(_ context.Context, body authentik.ProxyProviderRequest) (*authentik.ProxyProvider, error) {
	if err := f.rec("CreateProxyProvider"); err != nil {
		return nil, err
	}
	f.nextProviderPK++
	p := &authentik.ProxyProvider{PK: f.nextProviderPK, Name: body.Name, ExternalHost: body.ExternalHost, Mode: body.Mode}
	f.proxyByName[body.Name] = p
	f.createdProxy = append(f.createdProxy, body)
	return p, nil
}

func (f *fakeAPI) PatchProxyProvider(_ context.Context, pk int, body authentik.ProxyProviderRequest) (*authentik.ProxyProvider, error) {
	if err := f.rec("PatchProxyProvider"); err != nil {
		return nil, err
	}
	f.patchedProxy[pk] = body
	p := &authentik.ProxyProvider{PK: pk, Name: body.Name}
	// A rename PATCH (name set) makes the provider findable by its new name, as
	// the real API does, so the adoption in-place rename can be looked up by the
	// marker name on the converge step that follows it.
	if body.Name != "" {
		f.proxyByName[body.Name] = p
		f.providerRefByPK[pk] = &authentik.ProviderRef{PK: pk, Name: body.Name, Component: authentik.ComponentProxyProvider}
	}
	return p, nil
}

func (f *fakeAPI) GetProviderByPK(_ context.Context, pk int) (*authentik.ProviderRef, error) {
	if err := f.rec("GetProviderByPK"); err != nil {
		return nil, err
	}
	if ref, ok := f.providerRefByPK[pk]; ok {
		return ref, nil
	}
	return nil, authentik.ErrNotFound
}

func (f *fakeAPI) DeleteProxyProvider(_ context.Context, pk int) error {
	if err := f.rec("DeleteProxyProvider"); err != nil {
		return err
	}
	f.deletedProxyPKs = append(f.deletedProxyPKs, pk)
	return nil
}

func (f *fakeAPI) GetOAuth2ProviderByName(_ context.Context, name string) (*authentik.OAuth2Provider, error) {
	if err := f.rec("GetOAuth2ProviderByName"); err != nil {
		return nil, err
	}
	if p, ok := f.oauthByName[name]; ok {
		return p, nil
	}
	return nil, authentik.ErrNotFound
}

func (f *fakeAPI) CreateOAuth2Provider(_ context.Context, body authentik.OAuth2ProviderRequest) (*authentik.OAuth2Provider, error) {
	if err := f.rec("CreateOAuth2Provider"); err != nil {
		return nil, err
	}
	f.nextProviderPK++
	p := &authentik.OAuth2Provider{PK: f.nextProviderPK, Name: body.Name, ClientType: body.ClientType, ClientID: body.ClientID}
	f.oauthByName[body.Name] = p
	f.createdOAuth = append(f.createdOAuth, body)
	return p, nil
}

func (f *fakeAPI) PatchOAuth2Provider(_ context.Context, pk int, body authentik.OAuth2ProviderRequest) (*authentik.OAuth2Provider, error) {
	if err := f.rec("PatchOAuth2Provider"); err != nil {
		return nil, err
	}
	f.patchedOAuth[pk] = body
	p := &authentik.OAuth2Provider{PK: pk, Name: body.Name, ClientType: body.ClientType, ClientID: body.ClientID}
	if body.Name != "" {
		f.oauthByName[body.Name] = p
		f.providerRefByPK[pk] = &authentik.ProviderRef{PK: pk, Name: body.Name, Component: authentik.ComponentOAuth2Provider}
	}
	return p, nil
}

func (f *fakeAPI) DeleteOAuth2Provider(_ context.Context, pk int) error {
	if err := f.rec("DeleteOAuth2Provider"); err != nil {
		return err
	}
	f.deletedOAuthPKs = append(f.deletedOAuthPKs, pk)
	return nil
}

func (f *fakeAPI) GetSAMLProviderByName(_ context.Context, name string) (*authentik.SAMLProvider, error) {
	if err := f.rec("GetSAMLProviderByName"); err != nil {
		return nil, err
	}
	if p, ok := f.samlByName[name]; ok {
		return p, nil
	}
	return nil, authentik.ErrNotFound
}

func (f *fakeAPI) CreateSAMLProvider(_ context.Context, body authentik.SAMLProviderRequest) (*authentik.SAMLProvider, error) {
	if err := f.rec("CreateSAMLProvider"); err != nil {
		return nil, err
	}
	f.nextProviderPK++
	p := &authentik.SAMLProvider{PK: f.nextProviderPK, Name: body.Name, ACSUrl: body.ACSUrl, Audience: body.Audience,
		Issuer: body.Issuer, SpBinding: body.SpBinding, SigningKp: strPtr(body.SigningKp), PropertyMappings: body.PropertyMappings}
	f.samlByName[body.Name] = p
	f.createdSAML = append(f.createdSAML, body)
	return p, nil
}

func (f *fakeAPI) PatchSAMLProvider(_ context.Context, pk int, body authentik.SAMLProviderRequest) (*authentik.SAMLProvider, error) {
	if err := f.rec("PatchSAMLProvider"); err != nil {
		return nil, err
	}
	f.patchedSAML[pk] = body
	p := &authentik.SAMLProvider{PK: pk, Name: body.Name, ACSUrl: body.ACSUrl, Audience: body.Audience,
		Issuer: body.Issuer, SpBinding: body.SpBinding, PropertyMappings: body.PropertyMappings}
	if body.Name != "" {
		f.samlByName[body.Name] = p
		f.providerRefByPK[pk] = &authentik.ProviderRef{PK: pk, Name: body.Name, Component: authentik.ComponentSAMLProvider}
	}
	return p, nil
}

func (f *fakeAPI) DeleteSAMLProvider(_ context.Context, pk int) error {
	if err := f.rec("DeleteSAMLProvider"); err != nil {
		return err
	}
	f.deletedSAMLPKs = append(f.deletedSAMLPKs, pk)
	return nil
}

func (f *fakeAPI) GetSAMLPropertyMappings(_ context.Context) ([]string, error) {
	if err := f.rec("GetSAMLPropertyMappings"); err != nil {
		return nil, err
	}
	return append([]string{}, f.samlMappings...), nil
}

func (f *fakeAPI) GetSAMLPropertyMappingByName(_ context.Context, name string) (*authentik.SAMLPropertyMapping, error) {
	if err := f.rec("GetSAMLPropertyMappingByName"); err != nil {
		return nil, err
	}
	if m, ok := f.samlMappingByName[name]; ok {
		return m, nil
	}
	return nil, authentik.ErrNotFound
}

func (f *fakeAPI) GetApplicationBySlug(_ context.Context, slug string) (*authentik.Application, error) {
	if err := f.rec("GetApplicationBySlug"); err != nil {
		return nil, err
	}
	if a, ok := f.appBySlug[slug]; ok {
		return a, nil
	}
	return nil, authentik.ErrNotFound
}

func (f *fakeAPI) CreateApplication(_ context.Context, body authentik.ApplicationRequest) (*authentik.Application, error) {
	if err := f.rec("CreateApplication"); err != nil {
		return nil, err
	}
	a := &authentik.Application{PK: "app-" + body.Slug, Name: body.Name, Slug: body.Slug, Provider: body.Provider, PolicyEngineMode: body.PolicyEngineMode}
	f.appBySlug[body.Slug] = a
	f.createdApps = append(f.createdApps, body)
	return a, nil
}

func (f *fakeAPI) PatchApplication(_ context.Context, slug string, body authentik.ApplicationRequest) (*authentik.Application, error) {
	if err := f.rec("PatchApplication"); err != nil {
		return nil, err
	}
	f.patchedApps[slug] = body
	pk := "app-" + slug
	if a, ok := f.appBySlug[slug]; ok {
		pk = a.PK
	}
	return &authentik.Application{PK: pk, Name: body.Name, Slug: slug, Provider: body.Provider, PolicyEngineMode: body.PolicyEngineMode}, nil
}

func (f *fakeAPI) DeleteApplication(_ context.Context, slug string) error {
	if err := f.rec("DeleteApplication"); err != nil {
		return err
	}
	f.deletedApps = append(f.deletedApps, slug)
	return nil
}

func (f *fakeAPI) ListAllProviders(_ context.Context, _ int) ([]authentik.AllProvider, error) {
	if err := f.rec("ListAllProviders"); err != nil {
		return nil, err
	}
	return f.allProviders, nil
}

func (f *fakeAPI) SetApplicationIconURL(_ context.Context, slug, iconURL string) error {
	if err := f.rec("SetApplicationIconURL"); err != nil {
		return err
	}
	f.iconSet[slug] = iconURL
	return nil
}

func (f *fakeAPI) ListBindingsForTarget(_ context.Context, appPK string) ([]authentik.PolicyBinding, error) {
	if err := f.rec("ListBindingsForTarget"); err != nil {
		return nil, err
	}
	return f.bindings[appPK], nil
}

func (f *fakeAPI) CreateBinding(_ context.Context, body authentik.PolicyBindingRequest) (*authentik.PolicyBinding, error) {
	if err := f.rec("CreateBinding"); err != nil {
		return nil, err
	}
	f.nextBindingN++
	pk := "bind-" + itoa(f.nextBindingN)
	b := authentik.PolicyBinding{PK: pk, Policy: body.Policy, Group: body.Group, Target: body.Target, Order: body.Order}
	f.bindings[body.Target] = append(f.bindings[body.Target], b)
	f.createdBindings = append(f.createdBindings, body)
	return &b, nil
}

func (f *fakeAPI) DeleteBinding(_ context.Context, pk string) error {
	if err := f.rec("DeleteBinding"); err != nil {
		return err
	}
	f.deletedBindings = append(f.deletedBindings, pk)
	for target, bs := range f.bindings {
		kept := bs[:0:0]
		for _, b := range bs {
			if b.PK != pk {
				kept = append(kept, b)
			}
		}
		f.bindings[target] = kept
	}
	return nil
}

func (f *fakeAPI) GetGroupByName(_ context.Context, name string) (*authentik.Group, error) {
	if err := f.rec("GetGroupByName"); err != nil {
		return nil, err
	}
	if g, ok := f.groups[name]; ok {
		return g, nil
	}
	return nil, authentik.ErrNotFound
}

func (f *fakeAPI) CreateGroup(_ context.Context, name string) (*authentik.Group, error) {
	if err := f.rec("CreateGroup"); err != nil {
		return nil, err
	}
	g := &authentik.Group{PK: "grp-" + name, Name: name}
	f.groups[name] = g
	f.createdGroups = append(f.createdGroups, name)
	return g, nil
}

func (f *fakeAPI) GetPolicyByName(_ context.Context, name string) (*authentik.Policy, error) {
	if err := f.rec("GetPolicyByName"); err != nil {
		return nil, err
	}
	if p, ok := f.policies[name]; ok {
		return p, nil
	}
	return nil, authentik.ErrNotFound
}

func (f *fakeAPI) GetCertificateByName(_ context.Context, name string) (*authentik.CertificateKeyPair, error) {
	if err := f.rec("GetCertificateByName"); err != nil {
		return nil, err
	}
	if c, ok := f.certs[name]; ok {
		return c, nil
	}
	return nil, authentik.ErrNotFound
}

func (f *fakeAPI) GetFirstSigningKey(_ context.Context) (*authentik.CertificateKeyPair, error) {
	if err := f.rec("GetFirstSigningKey"); err != nil {
		return nil, err
	}
	if f.firstKey != nil {
		return f.firstKey, nil
	}
	return nil, authentik.ErrNotFound
}

func (f *fakeAPI) GetScopeMappingByName(_ context.Context, scopeName string) (*authentik.ScopeMapping, error) {
	if err := f.rec("GetScopeMappingByName"); err != nil {
		return nil, err
	}
	if m, ok := f.scopes[scopeName]; ok {
		return m, nil
	}
	return nil, authentik.ErrNotFound
}

func (f *fakeAPI) GetEmbeddedOutpost(_ context.Context) (*authentik.Outpost, error) {
	if err := f.rec("GetEmbeddedOutpost"); err != nil {
		return nil, err
	}
	if f.embedded != nil {
		return f.embedded, nil
	}
	return nil, authentik.ErrNotFound
}

func (f *fakeAPI) GetOutpostByName(_ context.Context, name string) (*authentik.Outpost, error) {
	if err := f.rec("GetOutpostByName"); err != nil {
		return nil, err
	}
	if o, ok := f.outpostsByName[name]; ok {
		return o, nil
	}
	return nil, authentik.ErrNotFound
}

func (f *fakeAPI) PatchOutpostProviders(_ context.Context, pk string, providers []int) (*authentik.Outpost, error) {
	if err := f.rec("PatchOutpostProviders"); err != nil {
		return nil, err
	}
	f.patchedOutpost = append([]int{}, providers...)
	name := ""
	if f.embedded != nil && f.embedded.PK == pk {
		f.embedded.Providers = append([]int{}, providers...)
		name = f.embedded.Name
	}
	for _, o := range f.outpostsByName {
		if o.PK == pk {
			o.Providers = append([]int{}, providers...)
		}
	}
	return &authentik.Outpost{PK: pk, Name: name, Providers: providers}, nil
}

// itoa is a tiny local int-to-string so the fake needs no strconv import churn.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

// testConfig is a baseline config with resolvable flows, the embedded outpost,
// and a fleet default group.
func testConfig() *config.Config {
	c := &config.Config{}
	c.Flows.Authorization = "default-authz"
	c.Flows.Invalidation = "default-inval"
	c.Outpost = config.DefaultOutpost
	c.OIDC.SigningKey = "authentik Self-signed Certificate"
	c.SAML.SigningKey = "authentik Self-signed Certificate"
	c.Defaults.Groups = []string{"public-users"}
	return c
}

// withFlows preloads the two default flows the config names.
func (f *fakeAPI) withFlows() *fakeAPI {
	f.flows["default-authz"] = &authentik.Flow{PK: "flow-authz", Slug: "default-authz"}
	f.flows["default-inval"] = &authentik.Flow{PK: "flow-inval", Slug: "default-inval"}
	return f
}

// withEmbedded preloads an embedded outpost carrying the given provider pks.
func (f *fakeAPI) withEmbedded(providers ...int) *fakeAPI {
	f.embedded = &authentik.Outpost{PK: "outpost-embedded", Name: "authentik Embedded Outpost", Providers: providers}
	return f
}

// fixedResolver returns a Resolver that always yields value.
func fixedResolver(value string) func(string) (string, error) {
	return func(string) (string, error) { return value, nil }
}

// strPtr and intPtr are test helpers.
func strPtr(s string) *string { return &s }
func intPtr(n int) *int       { return &n }

// baseForwardSpec is a minimal forward-auth spec with one explicit group.
func baseForwardSpec() spec.Spec {
	return spec.Spec{
		Enable:    true,
		Name:      "whoami",
		Slug:      "whoami",
		Title:     "whoami",
		Provider:  spec.ProviderForwardAuth,
		Host:      "whoami.example.com",
		Require:   spec.RequireAny,
		Groups:    []string{"g-admins"},
		GroupsSet: true,
	}
}

// baseSAMLSpec is a minimal SAML spec with one explicit group. SAML is
// server-served: no host, no outpost, no client secret.
func baseSAMLSpec() spec.Spec {
	return spec.Spec{
		Enable:    true,
		Name:      "kimai",
		Slug:      "kimai",
		Title:     "Kimai",
		Provider:  spec.ProviderSAML,
		Require:   spec.RequireAny,
		Groups:    []string{"g-admins"},
		GroupsSet: true,
		SAML: spec.SAMLSpec{
			ACSUrl:   "https://kimai.example.com/auth/saml/acs",
			Audience: "https://kimai.example.com",
			Binding:  spec.SAMLBindingPost,
		},
	}
}

// withSAMLDefaults preloads the signing cert and the managed default SAML
// property mappings the SAML convergence resolves.
func (f *fakeAPI) withSAMLDefaults() *fakeAPI {
	f.certs["authentik Self-signed Certificate"] = &authentik.CertificateKeyPair{PK: "cert-1", Name: "authentik Self-signed Certificate"}
	f.groups["g-admins"] = &authentik.Group{PK: "grp-admins", Name: "g-admins"}
	f.samlMappings = []string{"pm-email", "pm-name"}
	return f
}
