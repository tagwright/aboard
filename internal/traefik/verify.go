// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 the aboard authors

package traefik

import (
	"fmt"
	"sort"
	"strings"

	"github.com/tagwright/aboard/internal/config"
	"github.com/tagwright/aboard/internal/discovery"
	"github.com/tagwright/aboard/internal/spec"
)

// Traefik verifier finding codes. Each reuses discovery.Issue and is a
// SeverityError, so it is sticky in the beacon digest until fixed: a skipped or
// unwired gate is exactly what a security tool must not let scroll out of sight.
const (
	// CodeUnwiredMiddleware is a router declared protected that carries no
	// forward-auth middleware. The airlock declared-but-unarmed pattern applied
	// to SSO: the labels say protected, the proxy says open.
	CodeUnwiredMiddleware = "unwired-middleware"

	// CodeMissingCallback is a mixed host (a public router beside a protected
	// one) with no outpost callback router and no asserted fleet catch-all. The
	// login callback would land on the public router and 404.
	CodeMissingCallback = "missing-callback"

	// CodeCallbackPriority is a mixed host whose callback router exists but sits
	// at or below an unprotected router's priority, so the unprotected router
	// wins the callback path and the login loop is not closed.
	CodeCallbackPriority = "callback-priority"

	// CodeRouterUnknown is an aboard.traefik.routers entry naming a router that
	// does not exist on the container.
	CodeRouterUnknown = "router-unknown"

	// CodeGroupsHeaderMissing is a forward-auth app that wants group-claim while
	// the shared middleware's authResponseHeaders is confirmed NOT to carry
	// X-authentik-groups: the app is protected but will never receive the user's
	// group membership. Unlike the other Traefik findings this is a WARNING, not a
	// sticky error: authentication still works, only the app's own role mapping is
	// starved, and aboard cannot fix it (the header lives in the shared middleware
	// definition, which is immutable at runtime and aboard never mutates). Its job
	// here is verify-and-surface, per the group-claim design.
	CodeGroupsHeaderMissing = "groups-header-missing"
)

// GroupsResponseHeader is the forward-auth response header that carries the
// user's Authentik group membership to a protected app. Under forward-auth,
// group delivery rides this header inside the SHARED middleware's
// authResponseHeaders (not anything on aboard's side), so aboard's job is to
// VERIFY it is present and SURFACE a finding when it is not, never to mutate it.
const GroupsResponseHeader = "X-authentik-groups"

// GroupsHeaderState is the tri-state outcome of scanning the fleet for the
// forward-auth middleware definition's authResponseHeaders.
type GroupsHeaderState int

const (
	// GroupsHeaderUnknown means the middleware definition was not found among the
	// scanned labels. It may live in Traefik file or static config aboard cannot
	// read, so this is deliberately NOT treated as a gap: a false alarm on a
	// working fleet is its own harm.
	GroupsHeaderUnknown GroupsHeaderState = iota

	// GroupsHeaderPresent means the definition was found and its
	// authResponseHeaders includes X-authentik-groups.
	GroupsHeaderPresent

	// GroupsHeaderAbsent means the definition was found and its
	// authResponseHeaders does NOT include X-authentik-groups: a confirmed gap
	// aboard surfaces.
	GroupsHeaderAbsent
)

// DetectGroupsHeader scans labelSets for the definition of the forward-auth
// middleware named ref (cfg.Traefik.Middleware) and reports whether its
// authResponseHeaders includes X-authentik-groups. It is the group-delivery
// analog of fleet-callback detection (fleet.go): the middleware definition lives
// on the traefik container, so the daemon scans every container's labels once
// and passes the result into the per-container verify. The middleware label name
// is the bare name before any @provider (authentik@docker keys off "authentik").
func DetectGroupsHeader(labelSets []map[string]string, ref string) GroupsHeaderState {
	name := middlewareLabelName(ref)
	key := "traefik.http.middlewares." + name + ".forwardauth.authResponseHeaders"
	for _, labels := range labelSets {
		v, ok := labels[key]
		if !ok {
			continue
		}
		for _, h := range strings.Split(v, ",") {
			if strings.EqualFold(strings.TrimSpace(h), GroupsResponseHeader) {
				return GroupsHeaderPresent
			}
		}
		return GroupsHeaderAbsent
	}
	return GroupsHeaderUnknown
}

// VerifyGroupsDelivery returns the forward-auth group-delivery finding for one
// container, or nil. It fires only when the proxy is Traefik, the provider is
// forward-auth, group-claim is on, and the middleware definition was found and
// confirmed to lack X-authentik-groups. A not-found middleware (Unknown) and a
// present header both draw nothing. This keeps the forward-auth path light: the
// meat of group-claim is OIDC, and here aboard only verifies and surfaces.
func VerifyGroupsDelivery(cfg *config.Config, sp *spec.Spec, state GroupsHeaderState) *discovery.Issue {
	if cfg.Proxy != config.ProxyTraefik || sp.Provider != spec.ProviderForwardAuth || !sp.GroupsClaim {
		return nil
	}
	if state != GroupsHeaderAbsent {
		return nil
	}
	return &discovery.Issue{
		Severity: discovery.SeverityWarning,
		Code:     CodeGroupsHeaderMissing,
		Message: fmt.Sprintf("%s wants group-claim but the forward-auth middleware %s does not carry %s in authResponseHeaders: the app will not receive the user's groups. Add it to the middleware definition (aboard render --setup shows the full set), or set aboard.groups.claim=false",
			sp.Name, cfg.Traefik.Middleware, GroupsResponseHeader),
	}
}

// VerifyResult is the outcome of auditing one container's Traefik labels against
// the mixed-host callback rule. Findings are the sticky errors to alert on.
// CallbackRequired and CallbackSatisfied drive whether RenderService emits a
// callback block. Skipped with Reason covers the no-op cases (proxy is none, or
// an OIDC provider that has no Traefik half).
type VerifyResult struct {
	// Findings are the per-container Traefik Issues, all sticky errors.
	Findings []discovery.Issue

	// Skipped reports that the verifier did no work, with Reason saying why. It
	// is set for proxy: none and for a non-forward-auth provider.
	Skipped bool

	// Reason explains a Skipped result, or a no-finding pass, in one line.
	Reason string

	// ProtectedRouters are the router names the rule treats as protected for this
	// host, in sorted order: the aboard.traefik.routers set if given, else every
	// host-matching non-callback router.
	ProtectedRouters []string

	// UnprotectedRouters are host-matching non-callback routers that lack the
	// middleware, the ones a callback router must out-prioritize. Sorted.
	UnprotectedRouters []string

	// CallbackRequired reports the mixed-host case: at least one host-matching
	// router lacks the middleware, so a callback router is needed.
	CallbackRequired bool

	// CallbackSatisfied reports that the callback requirement is met, either by a
	// correctly-prioritized callback router on the container or by an asserted
	// fleet catch-all.
	CallbackSatisfied bool

	// CallbackPriority is the priority a rendered callback router should carry to
	// sit above every router on this host. Meaningful when CallbackRequired.
	CallbackPriority int

	// FleetCallbackPresent echoes the input: a fleet-wide catch-all callback
	// router on authentik-server is known to exist, satisfying the mixed-host
	// rule for every host.
	FleetCallbackPresent bool
}

// HasError reports whether the result carries any finding. Every Traefik finding
// is a SeverityError, so any finding is a skip-and-alert.
func (r VerifyResult) HasError() bool {
	return discovery.HasError(r.Findings)
}

// Verify audits a container's Traefik router labels against the mixed-host
// callback rule (Fork 6). It is the pure core: the daemon (chunk 6) supplies
// fleetCallbackPresent by detecting a catch-all router on authentik-server once,
// and the verifier never touches a socket.
//
// sp is the discovered Spec (Host, Provider, and ForwardAuth.TraefikRouters
// drive the rule). labels is the container's full label map. cfg supplies the
// middleware name and the proxy switch. fleetCallbackPresent, when true, means a
// fleet-wide catch-all callback router is known to exist, satisfying the
// mixed-host callback requirement for every host.
func Verify(cfg *config.Config, sp *spec.Spec, labels map[string]string, fleetCallbackPresent bool) VerifyResult {
	res := VerifyResult{FleetCallbackPresent: fleetCallbackPresent}

	// Proxy off: the daemon skips the verifier entirely, but if called, this is a
	// clean no-op with a reason rather than a spurious pass.
	if cfg.Proxy == config.ProxyNone {
		res.Skipped = true
		res.Reason = "proxy is none: the Traefik verifier is off, aboard.host is explicit"
		return res
	}

	// A server-served provider has no Traefik half: the forward-auth middleware
	// and the outpost callback are a proxy-provider concern, and the verifier is
	// not applied to OIDC or SAML providers (grammar worked example d).
	if sp.Provider != spec.ProviderForwardAuth {
		res.Skipped = true
		res.Reason = fmt.Sprintf("provider is %q: a server-served provider has no Traefik forward-auth half to verify", sp.Provider)
		return res
	}

	routers := ParseRouters(labels)

	// Host-matching routers: those carrying a literal Host() for the Spec's host.
	// Split into callback routers and app routers.
	var (
		hostRouters []*Router
		callbacks   []*Router
	)
	for _, r := range sortedRouters(routers) {
		if !r.MatchesHost(sp.Host) {
			continue
		}
		hostRouters = append(hostRouters, r)
		if r.IsCallback() {
			callbacks = append(callbacks, r)
		}
	}

	// Protected set (Fork 6): the aboard.traefik.routers names if given, else
	// every host-matching router except a recognized callback router.
	protected := resolveProtected(sp, routers, hostRouters, &res.Findings)
	protectedNames := map[string]bool{}
	for _, r := range protected {
		protectedNames[r.Name] = true
		res.ProtectedRouters = append(res.ProtectedRouters, r.Name)
	}
	sort.Strings(res.ProtectedRouters)

	mw := cfg.Traefik.Middleware

	// Every protected router must carry the middleware. A protected router
	// missing it is a sticky error: declared protected, proxy open.
	for _, r := range protected {
		if !r.HasMiddleware(mw) {
			res.Findings = append(res.Findings, discovery.Issue{
				Severity: discovery.SeverityError,
				Code:     CodeUnwiredMiddleware,
				Message: fmt.Sprintf("%s is declared protected and router %s carries no forward-auth middleware (%s)",
					sp.Name, r.Name, mw),
			})
		}
	}

	// Whole-host vs mixed-host. The public routers on this host are the
	// host-matching non-callback routers that are NOT in the protected set: a
	// router the operator deliberately left bare (named by omission from
	// aboard.traefik.routers). A protected router that merely lacks the
	// middleware is the unwired case above, not a public router, so it does not
	// make the host mixed. A host with no public router is whole-host and needs
	// no dedicated callback router. A host with a public router beside a
	// protected one needs one.
	var unprotected []*Router
	for _, r := range hostRouters {
		if r.IsCallback() || protectedNames[r.Name] {
			continue
		}
		unprotected = append(unprotected, r)
	}
	for _, r := range unprotected {
		res.UnprotectedRouters = append(res.UnprotectedRouters, r.Name)
	}
	sort.Strings(res.UnprotectedRouters)

	res.CallbackRequired = len(unprotected) > 0

	// The priority a rendered callback must carry to win the callback path: above
	// every router on this host. Computed even when a callback exists, so render
	// and the priority check share one number.
	res.CallbackPriority = callbackPriorityAbove(hostRouters)

	if !res.CallbackRequired {
		// Whole-host: nothing else needed. See the package MUST-VERIFY note.
		res.CallbackSatisfied = true
		if len(res.Findings) == 0 {
			res.Reason = "whole-host: every router on this host carries the forward-auth middleware"
		}
		return res
	}

	// Mixed-host: the callback requirement is satisfied by an asserted fleet
	// catch-all, or by a correctly-prioritized callback router on the container.
	if fleetCallbackPresent {
		res.CallbackSatisfied = true
		if len(res.Findings) == 0 {
			res.Reason = "mixed-host: satisfied by the fleet catch-all callback router on authentik-server"
		}
		return res
	}

	maxUnprotected := maxEffectivePriority(unprotected)
	switch {
	case len(callbacks) == 0:
		res.Findings = append(res.Findings, discovery.Issue{
			Severity: discovery.SeverityError,
			Code:     CodeMissingCallback,
			Message: fmt.Sprintf("%s is declared protected and host %s has a public router but no outpost callback router: add Host(`%s`) && PathPrefix(`%s`) carrying %s, pointed at authentik-server",
				sp.Name, sp.Host, sp.Host, callbackPathPrefix, mw),
		})
	default:
		// A callback router exists. It must carry the middleware and sit above
		// every unprotected router, or the unprotected router wins the callback
		// path and the login loop stays open.
		satisfied := false
		for _, c := range callbacks {
			if c.HasMiddleware(mw) && c.EffectivePriority() > maxUnprotected {
				satisfied = true
				break
			}
		}
		if satisfied {
			res.CallbackSatisfied = true
			if len(res.Findings) == 0 {
				res.Reason = "mixed-host: satisfied by a callback router on the container"
			}
		} else {
			res.Findings = append(res.Findings, discovery.Issue{
				Severity: discovery.SeverityError,
				Code:     CodeCallbackPriority,
				Message: fmt.Sprintf("%s host %s has an outpost callback router but it does not out-prioritize the public router(s) %v carrying %s: raise its priority above %d",
					sp.Name, sp.Host, res.UnprotectedRouters, mw, maxUnprotected),
			})
		}
	}

	return res
}

// resolveProtected computes the protected router set (Fork 6). When
// aboard.traefik.routers is set, those named routers are protected, and a name
// that does not exist on the container is a sticky error. When it is unset,
// every host-matching non-callback router is protected, the whole-host default.
func resolveProtected(sp *spec.Spec, all map[string]*Router, hostRouters []*Router, findings *[]discovery.Issue) []*Router {
	named := sp.ForwardAuth.TraefikRouters
	if len(named) == 0 {
		var out []*Router
		for _, r := range hostRouters {
			if !r.IsCallback() {
				out = append(out, r)
			}
		}
		return out
	}

	var out []*Router
	for _, name := range named {
		r, ok := all[name]
		if !ok {
			*findings = append(*findings, discovery.Issue{
				Severity: discovery.SeverityError,
				Code:     CodeRouterUnknown,
				Message: fmt.Sprintf("%s: aboard.traefik.routers names router %q which does not exist on the container",
					sp.Name, name),
			})
			continue
		}
		out = append(out, r)
	}
	return out
}

// callbackPriorityAbove returns a priority above every router on the host: the
// maximum effective priority plus a step, so a rendered callback router wins the
// callback path. The step matches the travels and cum shape (public 1, admin 10,
// outpost 20).
func callbackPriorityAbove(hostRouters []*Router) int {
	max := maxEffectivePriority(hostRouters)
	return max + 10
}

// maxEffectivePriority returns the highest EffectivePriority among routers, or 0
// for an empty set.
func maxEffectivePriority(routers []*Router) int {
	max := 0
	for _, r := range routers {
		if p := r.EffectivePriority(); p > max {
			max = p
		}
	}
	return max
}

// sortedRouters returns the routers sorted by name, for deterministic iteration
// and stable finding order.
func sortedRouters(m map[string]*Router) []*Router {
	names := make([]string, 0, len(m))
	for n := range m {
		names = append(names, n)
	}
	sort.Strings(names)
	out := make([]*Router, 0, len(names))
	for _, n := range names {
		out = append(out, m[n])
	}
	return out
}
