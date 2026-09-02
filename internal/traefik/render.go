// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 the aboard authors

package traefik

import (
	"fmt"
	"strings"

	"github.com/tagwright/aboard/internal/config"
	"github.com/tagwright/aboard/internal/spec"
)

// bt is a single backtick, the character Traefik quotes matcher arguments with.
// It is spelled as a hex escape so the rendered rule strings stay readable and
// so this file's own Go string literals never fight the backtick.
const bt = "\x60"

// authentikServiceName is the Traefik service the callback routers point at. It
// is a load-balancer to authentik-server, shaped like the authentik-svc
// definition travels and cum share.
const authentikServiceName = "authentik-svc"

// outpostAuthPath is the forward-auth address path on authentik-server that the
// shared middleware calls (grammar Fork 6, matching traefik/docker-compose.yml).
const outpostAuthPath = "/outpost.goauthentik.io/auth/traefik"

// authResponseHeaders is the forward-auth authResponseHeaders list, reproduced
// verbatim from the fleet's traefik/docker-compose.yml so aboard render --setup
// emits the same middleware the fleet already runs.
const authResponseHeaders = "X-authentik-username,X-authentik-groups,X-authentik-email,X-authentik-name,X-authentik-uid,X-authentik-jwt,X-authentik-meta-jwks,X-authentik-meta-outpost,X-authentik-meta-provider,X-authentik-meta-app,X-authentik-meta-version"

// maxResponseBodySize is the 4 MiB cap on Authentik's auth response body, from
// the fleet middleware definition.
const maxResponseBodySize = "4194304"

// fleetCatchAllPriority is the priority the recommended fleet catch-all callback
// router carries: above any app router, so the outpost callback path always
// wins over an application route on any fleet subdomain.
const fleetCatchAllPriority = 100

// RenderService returns the exact Traefik labels an operator should paste for
// this service (grammar Fork 6). It emits the middleware line for each protected
// router and, when the mixed-host rule requires a callback router and no fleet
// catch-all is asserted, the full callback-router block shaped like travels and
// cum: rule, entrypoints, tls, middleware, service pointed at authentik-server,
// and a priority above the unprotected routers. It NEVER writes anything, it
// returns a string. res is the Verify outcome for this container, which carries
// the protected set and the callback decision so render and verify agree.
func RenderService(cfg *config.Config, sp *spec.Spec, res VerifyResult) string {
	if res.Skipped {
		return "# aboard: nothing to render for " + sp.Name + ": " + res.Reason + "\n"
	}

	mw := cfg.Traefik.Middleware
	var b strings.Builder

	fmt.Fprintf(&b, "# aboard render %s: paste into the %s service labels.\n", sp.Name, sp.Name)
	b.WriteString("# aboard never writes Traefik config, these are for you to paste.\n")

	// Middleware line for each protected router.
	if len(res.ProtectedRouters) > 0 {
		b.WriteString("# Protected router(s) must carry the forward-auth middleware:\n")
		for _, name := range res.ProtectedRouters {
			label(&b, fmt.Sprintf("traefik.http.routers.%s.middlewares=%s", name, mw))
		}
	}

	switch {
	case res.CallbackRequired && res.CallbackSatisfied && res.FleetCallbackPresent:
		b.WriteString("# Mixed host, but the fleet catch-all callback router on authentik-server\n")
		b.WriteString("# (aboard render --setup) covers it, so no per-app callback router is needed.\n")
	case res.CallbackRequired && !res.CallbackSatisfied:
		renderCallbackBlock(&b, cfg, sp, res)
	case !res.CallbackRequired:
		b.WriteString("# Whole host: every router on this host carries the middleware, no callback router needed.\n")
	}

	return b.String()
}

// renderCallbackBlock writes the per-app outpost callback router (the travels /
// cum shape) plus its authentik-server service definition. The callback rule is
// Host(h) && PathPrefix(/outpost.goauthentik.io/), it carries the middleware, it
// points at authentik-server, and it sits above the unprotected routers on the
// host so the callback path is not swallowed by the public router.
func renderCallbackBlock(b *strings.Builder, cfg *config.Config, sp *spec.Spec, res VerifyResult) {
	router := sp.Slug + "-outpost"
	rule := hostMatch(sp.Host) + " && " + pathPrefixMatch(callbackPathPrefix)

	b.WriteString("# Mixed host: a public router sits beside a protected one, so the outpost\n")
	b.WriteString("# callback needs its own router above the public router, pointed at\n")
	b.WriteString("# authentik-server. Delete this block if the fleet catch-all callback\n")
	b.WriteString("# router (aboard render --setup) is present on authentik-server.\n")
	label(b, fmt.Sprintf("traefik.http.routers.%s.rule=%s", router, rule))
	label(b, fmt.Sprintf("traefik.http.routers.%s.entrypoints=websecure", router))
	label(b, fmt.Sprintf("traefik.http.routers.%s.tls=true", router))
	label(b, fmt.Sprintf("traefik.http.routers.%s.tls.certresolver=cloudflare", router))
	label(b, fmt.Sprintf("traefik.http.routers.%s.middlewares=%s", router, cfg.Traefik.Middleware))
	label(b, fmt.Sprintf("traefik.http.routers.%s.service=%s", router, authentikServiceName))
	label(b, fmt.Sprintf("traefik.http.routers.%s.priority=%d", router, res.CallbackPriority))
	label(b, fmt.Sprintf("traefik.http.services.%s.loadbalancer.server.url=%s", authentikServiceName, authentikURL(cfg)))
	b.WriteString("# entrypoints/tls above match the fleet convention (websecure + cloudflare):\n")
	b.WriteString("# adjust them to your own entrypoint and cert resolver if they differ.\n")
}

// RenderSetup returns the once-per-fleet Traefik pieces (grammar Fork 6): the
// shared forward-auth middleware definition matching traefik/docker-compose.yml,
// and the recommended fleet catch-all callback router on authentik-server. With
// the catch-all present, no per-app callback router is ever needed again. The
// HostRegexp syntax is version-correct for cfg.Traefik.Version, since Traefik v2
// and v3 spell it differently. It NEVER writes anything, it returns a string.
func RenderSetup(cfg *config.Config) string {
	if cfg.Proxy == config.ProxyNone {
		return "# aboard render --setup: proxy is none, no Traefik setup to render.\n"
	}

	var b strings.Builder
	name := middlewareLabelName(cfg.Traefik.Middleware)

	b.WriteString("# aboard render --setup: once-per-fleet Traefik pieces. Paste as labels.\n")
	b.WriteString("#\n")
	b.WriteString("# (1) The shared forward-auth middleware, on the traefik container.\n")
	b.WriteString("#     Referenced by app routers as " + cfg.Traefik.Middleware + ".\n")
	label(&b, fmt.Sprintf("traefik.http.middlewares.%s.forwardauth.address=%s", name, authentikURL(cfg)+outpostAuthPath))
	label(&b, fmt.Sprintf("traefik.http.middlewares.%s.forwardauth.trustForwardHeader=true", name))
	label(&b, fmt.Sprintf("traefik.http.middlewares.%s.forwardauth.authResponseHeaders=%s", name, authResponseHeaders))
	label(&b, fmt.Sprintf("traefik.http.middlewares.%s.forwardauth.maxResponseBodySize=%s", name, maxResponseBodySize))

	b.WriteString("#\n")
	b.WriteString("# (2) The recommended fleet catch-all callback router, on the\n")
	b.WriteString("#     authentik-server container. With it present, no per-app callback\n")
	b.WriteString("#     router is needed for any host under the fleet domain.\n")

	domain, guessed := fleetDomain(cfg)
	if guessed {
		b.WriteString("#     NOTE: the fleet domain below is a guess from authentik.public_url.\n")
		b.WriteString("#     Confirm it, or edit it, to match the domain your apps live under.\n")
	}
	regexp, versionNote := hostRegexpFor(cfg.Traefik.Version, domain)
	b.WriteString("#     " + versionNote + "\n")
	rule := regexp + " && " + pathPrefixMatch(callbackPathPrefix)
	label(&b, fmt.Sprintf("traefik.http.routers.aboard-outpost.rule=%s", rule))
	label(&b, "traefik.http.routers.aboard-outpost.entrypoints=websecure")
	label(&b, "traefik.http.routers.aboard-outpost.tls=true")
	label(&b, "traefik.http.routers.aboard-outpost.tls.certresolver=cloudflare")
	label(&b, fmt.Sprintf("traefik.http.routers.aboard-outpost.middlewares=%s", cfg.Traefik.Middleware))
	label(&b, "traefik.http.routers.aboard-outpost.service=authentik@internal")
	label(&b, fmt.Sprintf("traefik.http.routers.aboard-outpost.priority=%d", fleetCatchAllPriority))

	return b.String()
}

// hostRegexpFor returns the version-correct HostRegexp matcher for the fleet
// domain and a one-line note citing which syntax belongs to which Traefik major.
//
// Traefik v2 uses a NAMED-GROUP syntax: the argument is a template where
// {name:pattern} declares a named capture, e.g.
//
//	HostRegexp(`{subdomain:[a-z0-9-]+}.natecalvert.org`)
//
// Traefik v3 changed to STANDARD Go (RE2) regexp, anchored, e.g.
//
//	HostRegexp(`^[a-z0-9-]+\.natecalvert\.org$`)
//
// The dots are literal-escaped for v3 because there the argument is a real Go
// regexp, where an unescaped dot matches any character.
func hostRegexpFor(version int, domain string) (matcher, note string) {
	switch version {
	case 2:
		// v2 named-group template syntax.
		arg := "{subdomain:[a-z0-9-]+}." + domain
		return "HostRegexp(" + bt + arg + bt + ")",
			"Traefik v2 HostRegexp uses the {name:pattern} named-group template syntax."
	default:
		// v3 (and the default) standard Go RE2 regexp syntax.
		arg := "^[a-z0-9-]+\\." + strings.ReplaceAll(domain, ".", "\\.") + "$"
		return "HostRegexp(" + bt + arg + bt + ")",
			"Traefik v3 HostRegexp uses standard Go (RE2) regexp syntax, anchored, dots escaped."
	}
}

// fleetDomain derives the fleet apex domain from authentik.public_url by
// dropping the left-most label (auth.natecalvert.org becomes natecalvert.org).
// It returns guessed true when the value is a derivation to warn the operator
// about, or a placeholder when public_url is unknown.
func fleetDomain(cfg *config.Config) (domain string, guessed bool) {
	pub := cfg.Authentik.PublicURL
	if pub == "" {
		return "fleet.example.com", true
	}
	host := pub
	host = strings.TrimPrefix(host, "https://")
	host = strings.TrimPrefix(host, "http://")
	if i := strings.IndexAny(host, "/:"); i >= 0 {
		host = host[:i]
	}
	labels := strings.Split(host, ".")
	if len(labels) > 2 {
		return strings.Join(labels[1:], "."), true
	}
	return host, true
}

// authentikURL is the internal authentik-server endpoint, trailing slash
// trimmed, from aboard.yml authentik.url.
func authentikURL(cfg *config.Config) string {
	return strings.TrimRight(cfg.Authentik.URL, "/")
}

// middlewareLabelName is the middleware's Traefik label name: the part of a
// provider-qualified reference before the @provider (authentik@docker becomes
// authentik), since the definition labels key off the bare name.
func middlewareLabelName(ref string) string {
	if i := strings.IndexByte(ref, '@'); i >= 0 {
		return ref[:i]
	}
	return ref
}

// hostMatch renders a literal Host() matcher.
func hostMatch(host string) string {
	return "Host(" + bt + host + bt + ")"
}

// pathPrefixMatch renders a PathPrefix() matcher.
func pathPrefixMatch(path string) string {
	return "PathPrefix(" + bt + path + bt + ")"
}

// label writes one compose label in the list-item style travels and cum use.
func label(b *strings.Builder, kv string) {
	b.WriteString("- \"")
	b.WriteString(kv)
	b.WriteString("\"\n")
}
