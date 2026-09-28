// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 the aboard authors

package reconcile

import (
	"context"
	"strings"
	"testing"

	"github.com/tagwright/aboard/internal/authentik"
)

// Level 3 guard, per the ratified tagwright Testing Standard: the missing-
// group enrichment (build doc "aboard group discovery", #1140/#1143) asserts
// the structural invariant that a CodeGroupMissing error always names the
// available group namespace, so a typo in aboard.groups tells the operator
// what actually exists instead of sending them to read Authentik directly.
//
// Its committed negative fixture is the PRE-ENRICHMENT behavior: the bare
// message built before groupMissingMessage existed ("group %s does not exist
// (set ABOARD_CREATE_GROUPS=true to create it empty)"), with no available-
// groups list appended. Proven red-then-green: with resolveBindings reverted to
// that bare message (git stash / a temporary local edit during this build),
// TestGuard_MissingGroupErrorListsAvailableGroups FAILS, because the bare
// message names no available group. With the enrichment in place, as shipped,
// it PASSES. See the build chat's report for the actual red run's output; the
// assertion below is what caught it and is what must keep catching it.

// TestGuard_MissingGroupErrorListsAvailableGroups is the guard itself: an
// unresolvable aboard.groups name must surface an error that both still names
// the missing group and lists the groups that do exist.
func TestGuard_MissingGroupErrorListsAvailableGroups(t *testing.T) {
	f := newFake().withFlows().withEmbedded()
	f.groups["g-editors"] = &authentik.Group{PK: "grp-editors", Name: "g-editors"}
	f.groups["g-viewers"] = &authentik.Group{PK: "grp-viewers", Name: "g-viewers"}
	// baseForwardSpec asks for "g-admins", deliberately never registered here.

	r := New(f, testConfig(), fixedResolver("unused"))
	_, err := r.Reconcile(context.Background(), baseForwardSpec())

	if err == nil {
		t.Fatal("an unresolvable aboard.groups name must surface an error, not a silent success")
	}
	if errCode(err) != CodeGroupMissing {
		t.Fatalf("err code = %q, want %q", errCode(err), CodeGroupMissing)
	}
	msg := err.Error()
	if !strings.Contains(msg, "g-admins") {
		t.Fatalf("GUARD: the error must still name the missing group (g-admins), got: %q", msg)
	}
	// This is the assertion the negative fixture (the pre-enrichment bare
	// message) fails: it names no available group at all.
	if !strings.Contains(msg, "g-editors") || !strings.Contains(msg, "g-viewers") {
		t.Fatalf("GUARD: the error must list the available groups (g-editors, g-viewers) so the operator sees the real namespace at the point of the typo, got: %q", msg)
	}
}

// TestGuard_MissingGroupEnrichmentIsBestEffortNeverMasksPrimaryFailure proves
// the fail-closed half of the same guard: when the available-groups lookup
// ITSELF fails, the primary CodeGroupMissing error must still surface naming
// the missing group. The enrichment may degrade (and says so in the message)
// but must never replace, swallow, or silently succeed past the real failure.
func TestGuard_MissingGroupEnrichmentIsBestEffortNeverMasksPrimaryFailure(t *testing.T) {
	f := newFake().withFlows().withEmbedded()
	f.errOn["ListGroups"] = errBoom
	// g-admins is not registered either, so both the group lookup and the
	// enrichment's own ListGroups call fail.

	r := New(f, testConfig(), fixedResolver("unused"))
	_, err := r.Reconcile(context.Background(), baseForwardSpec())

	if err == nil {
		t.Fatal("a missing group must still surface even when the available-groups lookup itself errors")
	}
	if errCode(err) != CodeGroupMissing {
		t.Fatalf("err code = %q, want %q (a failed enrichment must never change the error code)", errCode(err), CodeGroupMissing)
	}
	if !strings.Contains(err.Error(), "g-admins") {
		t.Fatalf("the primary missing-group message must survive a failed enrichment lookup, got: %q", err.Error())
	}
}
