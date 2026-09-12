// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 the aboard authors

package reconcile

import (
	"context"
	"testing"

	"github.com/tagwright/aboard/internal/authentik"
	"github.com/tagwright/aboard/internal/discovery"
	"github.com/tagwright/aboard/internal/spec"
)

// These lock in the four hardening fault paths from the two production incidents.
// Each proves the failure SURFACES (a sticky error, nothing goes live), never a
// silent success, per the ratified Testing Standard's fault-injection rule.

// Fix 1: a second aboard-owned provider claiming an external_host another
// aboard-owned provider already holds is REFUSED before any write. Two providers
// on one host collide in the embedded outpost and 302-loop forever, the redirect
// outage this guard exists to prevent.
func TestReconcile_DuplicateExternalHostRefused(t *testing.T) {
	f := newFake().withFlows().withEmbedded()
	f.groups["g-admins"] = &authentik.Group{PK: "grp-admins", Name: "g-admins"}
	// An orphaned/renamed aboard provider for a DIFFERENT slug already claims the
	// host this spec wants (whoami.example.com).
	f.proxyList = []authentik.ProxyProvider{
		{PK: 42, Name: "oldwhoami (aboard)", ExternalHost: "https://whoami.example.com"},
	}

	r := New(f, testConfig(), fixedResolver("unused"))
	res, err := r.Reconcile(context.Background(), baseForwardSpec())

	if errCode(err) != CodeDuplicateHost {
		t.Fatalf("a duplicate external_host must surface as %s, got err=%v", CodeDuplicateHost, err)
	}
	if !hasIssue(res, discovery.SeverityError, CodeDuplicateHost) {
		t.Error("the duplicate-host refusal must be recorded as a sticky SeverityError issue")
	}
	if f.called("CreateProxyProvider") || f.called("CreateApplication") {
		t.Error("REFUSAL must happen before any write: no provider or application may be created")
	}
	if res.Attached || f.called("PatchOutpostProviders") {
		t.Error("nothing may be attached to the outpost when the host collides")
	}
}

// The negative fixture for Fix 1: the SAME slug re-running against its OWN
// existing provider on the same host is NOT a collision, so the guard does not
// false-positive and block a normal idempotent reconcile.
func TestReconcile_SameSlugSameHostNotACollision(t *testing.T) {
	f := newFake().withFlows().withEmbedded()
	f.groups["g-admins"] = &authentik.Group{PK: "grp-admins", Name: "g-admins"}
	// The provider this slug already owns (marker name "whoami (aboard)") holding
	// its own host must not be read as a collision with itself.
	own := &authentik.ProxyProvider{PK: 7, Name: "whoami (aboard)", ExternalHost: "https://whoami.example.com"}
	f.proxyByName["whoami (aboard)"] = own
	f.proxyList = []authentik.ProxyProvider{*own}

	r := New(f, testConfig(), fixedResolver("unused"))
	res, err := r.Reconcile(context.Background(), baseForwardSpec())
	if err != nil {
		t.Fatalf("a same-slug re-run must not be flagged as a duplicate host: %v", err)
	}
	if !res.Attached {
		t.Error("the normal re-run should still go live")
	}
}

// Fix 3: the go-live serve probe erroring must surface as CodeGoLiveUnverified
// with Attached=false. aboard must not report a go-live it could not confirm.
func TestReconcile_GoLiveProbeErrorSurfaces(t *testing.T) {
	f := newFake().withFlows().withEmbedded()
	f.groups["g-admins"] = &authentik.Group{PK: "grp-admins", Name: "g-admins"}
	f.errOn["OutpostServesHost"] = errBoom

	r := New(f, testConfig(), fixedResolver("unused"))
	res, err := r.Reconcile(context.Background(), baseForwardSpec())

	if errCode(err) != CodeGoLiveUnverified {
		t.Fatalf("an unverifiable go-live must surface as %s, got err=%v", CodeGoLiveUnverified, err)
	}
	if res.Attached {
		t.Error("Attached must be false when go-live could not be verified")
	}
}

// Fix 3, the #605 reproduction: the provider is ALREADY in the outpost's DB
// providers list (so the old attachOutpost skipped the PATCH and reported success
// on the DB list alone), yet the LIVE outpost does not serve the host. aboard must
// force a reload and, still not served, surface CodeGoLiveStale with Attached
// false, never the silent go-live-on-attach the incident hit.
func TestReconcile_GoLiveStaleAttachedButNotServedSurfaces(t *testing.T) {
	// The first created provider gets pk 1; seed the embedded outpost to already
	// contain pk 1, so the attach step finds it present and would skip the PATCH.
	f := newFake().withFlows().withEmbedded(1)
	f.groups["g-admins"] = &authentik.Group{PK: "grp-admins", Name: "g-admins"}
	// The live outpost does not serve the host: attached-but-stale.
	f.serves["whoami.example.com"] = false

	r := New(f, testConfig(), fixedResolver("unused"))
	res, err := r.Reconcile(context.Background(), baseForwardSpec())

	if errCode(err) != CodeGoLiveStale {
		t.Fatalf("an attached-but-stale outpost must surface as %s, got err=%v", CodeGoLiveStale, err)
	}
	if res.Attached {
		t.Error("Attached must be false for an attached-but-stale outpost")
	}
	// The stale path must have FORCED a reload even though the provider was already
	// in the DB list (the exact gap #605 hit: no PATCH, no reload).
	if !f.called("PatchOutpostProviders") {
		t.Error("a stale outpost must trigger a forced reload PATCH, even when the provider is already in the DB list")
	}
}

// Fix 2: the orphan scan marks a forward-auth orphan STILL in the embedded
// outpost's providers list as Attached, so the daemon can surface the dangerous,
// collision-causing kind loudly. An orphan not in the list is not attached.
func TestOrphans_MarksStillAttached(t *testing.T) {
	f := newFake()
	f.allProviders = []authentik.AllProvider{
		{PK: 7, Name: "old (aboard)", Component: authentik.ComponentProxyProvider, AssignedApplicationSlug: "old"},
		{PK: 8, Name: "gone (aboard)", Component: authentik.ComponentProxyProvider, AssignedApplicationSlug: "gone"},
	}
	// pk 7 is still attached to the embedded outpost; pk 8 is not.
	f.embedded = &authentik.Outpost{PK: "outpost-embedded", Name: "authentik Embedded Outpost", Providers: []int{7}}

	r := New(f, testConfig(), fixedResolver("unused"))
	orphans, err := r.Orphans(context.Background(), nil)
	if err != nil {
		t.Fatalf("orphan scan errored: %v", err)
	}

	byPK := map[int]Orphan{}
	for _, o := range orphans {
		byPK[o.ProviderPK] = o
	}
	if !byPK[7].Attached {
		t.Error("an orphan still in the outpost providers list must be marked Attached")
	}
	if byPK[8].Attached {
		t.Error("an orphan not in the outpost providers list must not be marked Attached")
	}
}

// Fix 4: ConfirmLive returns DRIFT for an app that is attached in the DB but not
// served by the live outpost, so status can distinguish CONFIRMED from merely
// DISCOVERED and never report an unprovisioned app as fine.
func TestConfirmLive_AttachedButStaleIsDrift(t *testing.T) {
	f := newFake()
	f.proxyByName["whoami (aboard)"] = &authentik.ProxyProvider{PK: 3, Name: "whoami (aboard)"}
	f.embedded = &authentik.Outpost{PK: "outpost-embedded", Name: "authentik Embedded Outpost", Providers: []int{3}}
	f.serves["whoami.example.com"] = false // attached, but the live outpost is stale

	r := New(f, testConfig(), fixedResolver("unused"))
	got, err := r.ConfirmLive(context.Background(), []LiveCheck{
		{Slug: "whoami", Host: "whoami.example.com", Provider: spec.ProviderForwardAuth},
	})
	if err != nil {
		t.Fatalf("ConfirmLive errored: %v", err)
	}
	if len(got) != 1 || got[0].State != LiveDrift {
		t.Fatalf("an attached-but-stale app must confirm as LiveDrift, got %+v", got)
	}
}

// ConfirmLive returns DRIFT for an enabled app that Authentik never provisioned
// (no provider), the exact "container present but never provisioned" mismatch the
// meta-lesson is about.
func TestConfirmLive_NeverProvisionedIsDrift(t *testing.T) {
	f := newFake().withEmbedded()

	r := New(f, testConfig(), fixedResolver("unused"))
	got, err := r.ConfirmLive(context.Background(), []LiveCheck{
		{Slug: "ghost", Host: "ghost.example.com", Provider: spec.ProviderForwardAuth},
	})
	if err != nil {
		t.Fatalf("ConfirmLive errored: %v", err)
	}
	if len(got) != 1 || got[0].State != LiveDrift {
		t.Fatalf("an unprovisioned app must confirm as LiveDrift, got %+v", got)
	}
}
