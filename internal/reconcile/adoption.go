// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 the aboard authors

package reconcile

import (
	"context"
	"strings"

	"github.com/tagwright/aboard/internal/authentik"
	"github.com/tagwright/aboard/internal/spec"
)

// adoptionGate decides whether a pre-existing, not-yet-aboard-owned application
// may be reconciled to this Spec (Fork 9). It is called only when the
// application exists and is not already aboard-owned of the desired provider
// type, and it runs read-only before any write, so a refusal leaves nothing
// behind.
//
// own is the ownership already resolved for this application. Because the caller
// established the app is not owned by an aboard provider of the DESIRED type,
// own.owned being true here means it is owned by an aboard provider of the OTHER
// type: a provider-type change, which is never adoptable, even with the
// affirmation. Otherwise the app points at a hand-made (or stale) provider, and
// adoption is gated on whether reconciling would change anything material.
//
// The material surface compared is the observable one: the application title,
// the policy engine mode, and the binding set. The pre-existing provider's own
// fields (external_host, redirect URIs) are not compared, because the authentik
// primitives expose no provider lookup by pk and the marker rename creates or
// re-points to the aboard-named provider rather than reading the old one. See
// the package note; this is the one place adoption is coarser than a full
// field-by-field diff.
func (r *Reconciler) adoptionGate(ctx context.Context, res *Result, s spec.Spec, slug string, app *authentik.Application, own ownership, desired []desiredBinding) error {
	if own.owned && own.kind != s.Provider {
		return r.fail(res, CodeAdoptTypeChange,
			"application "+slug+" has an aboard "+string(own.kind)+" provider but the label asks for "+
				string(s.Provider)+": a provider-type change is never adopted, do it deliberately in two steps")
	}

	var diffs []string
	if app.Name != s.Title {
		diffs = append(diffs, "title ("+app.Name+" -> "+s.Title+")")
	}
	want := policyEngineMode(s.Require)
	if app.PolicyEngineMode != "" && app.PolicyEngineMode != want {
		diffs = append(diffs, "access rule ("+app.PolicyEngineMode+" -> "+want+")")
	}

	existing, err := r.api.ListBindingsForTarget(ctx, app.PK)
	if err != nil {
		return r.fail(res, CodeAPI, "list bindings for application "+app.PK+": "+err.Error())
	}
	if bd := bindingDiff(existing, desired); bd != "" {
		diffs = append(diffs, bd)
	}

	if len(diffs) == 0 {
		r.info(res, CodeAdopted,
			"adopted pre-existing application "+slug+"; reconcile is a no-op beyond carrying the ownership marker")
		res.Adopted = true
		return nil
	}

	if !s.Adopt {
		return r.fail(res, CodeAdoptConflict,
			"application "+slug+" exists and reconciling would change: "+strings.Join(diffs, "; ")+
				" (set aboard.adopt=true to take ownership)")
	}

	r.info(res, CodeAdopted, "adopted application "+slug+" with changes: "+strings.Join(diffs, "; "))
	res.Adopted = true
	return nil
}

// bindingDiff describes how the existing binding set differs from the desired
// one, or "" when they match. It is the binding half of the adoption material
// diff, comparing by resolved pk so a hand-made binding to the same group as the
// label is not counted as a change.
func bindingDiff(existing []authentik.PolicyBinding, desired []desiredBinding) string {
	existingKeys := make(map[string]bool, len(existing))
	for _, b := range existing {
		if k := existingBindingKey(b); k != "" {
			existingKeys[k] = true
		}
	}
	desiredKeys := make(map[string]bool, len(desired))
	for _, d := range desired {
		desiredKeys[d.key()] = true
	}

	var adds, removes []string
	for _, d := range desired {
		if !existingKeys[d.key()] {
			adds = append(adds, d.name)
		}
	}
	for _, b := range existing {
		k := existingBindingKey(b)
		if k == "" || !desiredKeys[k] {
			removes = append(removes, describeExistingBinding(b))
		}
	}
	if len(adds) == 0 && len(removes) == 0 {
		return ""
	}
	var parts []string
	if len(adds) > 0 {
		parts = append(parts, "add "+strings.Join(adds, ","))
	}
	if len(removes) > 0 {
		parts = append(parts, "remove "+strings.Join(removes, ","))
	}
	return "bindings (" + strings.Join(parts, "; ") + ")"
}
