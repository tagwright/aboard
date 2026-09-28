// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 the aboard authors

package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"sort"
	"strings"
	"testing"

	"github.com/tagwright/aboard/internal/authentik"
)

// fakeGroupLister is an in-memory groupLister: it returns a canned group slice
// or a forced error, and records that ListGroups was the only thing called, so
// the command's read-only posture is provable without a live Authentik.
type fakeGroupLister struct {
	groups []authentik.Group
	err    error
	calls  int
}

func (f *fakeGroupLister) ListGroups(context.Context) ([]authentik.Group, error) {
	f.calls++
	if f.err != nil {
		return nil, f.err
	}
	return f.groups, nil
}

func strPtr(s string) *string { return &s }

// --- Level 1: groupRows is pure. Invariant tests over an arbitrary input
// space, not a handful of hand-picked examples, per the Testing Standard.

// TestGroupRows_SortedAndCompleteOverRandomInputs feeds many randomly generated
// group sets and asserts three invariants hold for every one: the output is
// sorted by name, every input group appears exactly once, and member count
// matches the input's user-pk-list length exactly.
func TestGroupRows_SortedAndCompleteOverRandomInputs(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	for trial := 0; trial < 200; trial++ {
		n := rng.Intn(12)
		groups := make([]authentik.Group, n)
		wantCount := map[string]int{}
		for i := 0; i < n; i++ {
			name := fmt.Sprintf("g-%03d-%d", rng.Intn(500), i) // unique per index
			users := make([]int, rng.Intn(6))
			for j := range users {
				users[j] = j
			}
			var parent *string
			if rng.Intn(2) == 0 {
				parent = strPtr(fmt.Sprintf("parent-%d", rng.Intn(5)))
			}
			groups[i] = authentik.Group{PK: fmt.Sprintf("pk-%d", i), Name: name, ParentName: parent, Users: users}
			wantCount[name] = len(users)
		}

		rows := groupRows(groups)

		if len(rows) != n {
			t.Fatalf("trial %d: got %d rows for %d input groups", trial, len(rows), n)
		}
		seen := map[string]bool{}
		for i, r := range rows {
			if seen[r.Name] {
				t.Fatalf("trial %d: group %q appeared more than once", trial, r.Name)
			}
			seen[r.Name] = true
			if r.MemberCount != wantCount[r.Name] {
				t.Fatalf("trial %d: group %q member count = %d, want %d", trial, r.Name, r.MemberCount, wantCount[r.Name])
			}
			if i > 0 && rows[i-1].Name >= r.Name {
				t.Fatalf("trial %d: rows not sorted by name at index %d: %q >= %q", trial, i, rows[i-1].Name, r.Name)
			}
		}
		for name := range wantCount {
			if !seen[name] {
				t.Fatalf("trial %d: input group %q missing from output", trial, name)
			}
		}
	}
}

// TestGroupRows_BlankParentRendersEmptyStringNotNil proves a nil ParentName (a
// top-level group) renders as the empty string, never the literal text "nil"
// or "<nil>", both in the row and downstream in JSON.
func TestGroupRows_BlankParentRendersEmptyStringNotNil(t *testing.T) {
	rows := groupRows([]authentik.Group{
		{PK: "p1", Name: "top-level", ParentName: nil, Users: []int{1}},
		{PK: "p2", Name: "child", ParentName: strPtr("top-level"), Users: nil},
	})
	byName := map[string]groupRow{}
	for _, r := range rows {
		byName[r.Name] = r
	}
	if byName["top-level"].Parent != "" {
		t.Errorf("top-level parent = %q, want empty string", byName["top-level"].Parent)
	}
	if byName["child"].Parent != "top-level" {
		t.Errorf("child parent = %q, want top-level", byName["child"].Parent)
	}
	if byName["child"].MemberCount != 0 {
		t.Errorf("child with nil Users member count = %d, want 0", byName["child"].MemberCount)
	}
}

// TestGroupRows_JSONRoundTripsToSameSet proves the JSON encoding round-trips to
// the same set of {name, member_count, parent} the rows describe, for a
// randomized input, and that a blank parent marshals as "" not null.
func TestGroupRows_JSONRoundTripsToSameSet(t *testing.T) {
	rng := rand.New(rand.NewSource(2))
	groups := make([]authentik.Group, 0, 10)
	for i := 0; i < 10; i++ {
		var parent *string
		if i%3 != 0 {
			parent = strPtr(fmt.Sprintf("p%d", i%4))
		}
		groups = append(groups, authentik.Group{
			PK:         fmt.Sprintf("pk-%d", i),
			Name:       fmt.Sprintf("g%02d", i),
			ParentName: parent,
			Users:      make([]int, rng.Intn(4)),
		})
	}
	rows := groupRows(groups)

	buf := &strings.Builder{}
	if err := json.NewEncoder(buf).Encode(rows); err != nil {
		t.Fatalf("encode: %v", err)
	}
	var decoded []groupRow
	if err := json.Unmarshal([]byte(buf.String()), &decoded); err != nil {
		t.Fatalf("decode: %v", err)
	}
	sort.Slice(decoded, func(i, j int) bool { return decoded[i].Name < decoded[j].Name })
	if len(decoded) != len(rows) {
		t.Fatalf("decoded %d rows, want %d", len(decoded), len(rows))
	}
	for i := range rows {
		if decoded[i] != rows[i] {
			t.Errorf("row %d round-tripped to %+v, want %+v", i, decoded[i], rows[i])
		}
	}
	if !strings.Contains(buf.String(), `"parent":""`) {
		t.Errorf("expected a blank parent to marshal as an empty string, not null, in %s", buf.String())
	}
}

// --- Level 2: runGroups is the wiring. Driven over a fake groupLister with a
// fault knob, per the Testing Standard's fault-injection rule.

func TestRunGroups_TablePrintsSortedRows(t *testing.T) {
	l := &fakeGroupLister{groups: []authentik.Group{
		{PK: "p2", Name: "zzz-last", ParentName: nil, Users: []int{1, 2}},
		{PK: "p1", Name: "aaa-first", ParentName: strPtr("parent-x"), Users: []int{1}},
	}}
	u, buf := newTestUI()
	if err := runGroups(context.Background(), l, u, false); err != nil {
		t.Fatalf("runGroups: %v", err)
	}
	out := buf.String()
	firstIdx := strings.Index(out, "aaa-first")
	lastIdx := strings.Index(out, "zzz-last")
	if firstIdx == -1 || lastIdx == -1 || firstIdx > lastIdx {
		t.Errorf("expected aaa-first before zzz-last (sorted by name), got:\n%s", out)
	}
	if !strings.Contains(out, "members=1") || !strings.Contains(out, "members=2") {
		t.Errorf("expected member counts in output, got:\n%s", out)
	}
	if !strings.Contains(out, "parent-x") {
		t.Errorf("expected the parent name in output, got:\n%s", out)
	}
	if l.calls != 1 {
		t.Errorf("ListGroups called %d times, want exactly 1", l.calls)
	}
}

func TestRunGroups_JSONFlagEmitsParseableArray(t *testing.T) {
	l := &fakeGroupLister{groups: []authentik.Group{
		{PK: "p1", Name: "editors", ParentName: nil, Users: []int{1, 2, 3}},
		{PK: "p2", Name: "viewers", ParentName: strPtr("editors"), Users: []int{4}},
	}}
	u, buf := newTestUI()
	if err := runGroups(context.Background(), l, u, true); err != nil {
		t.Fatalf("runGroups --json: %v", err)
	}
	var rows []groupRow
	if err := json.Unmarshal(buf.Bytes(), &rows); err != nil {
		t.Fatalf("--json output did not parse as JSON: %v\noutput:\n%s", err, buf.String())
	}
	if len(rows) != 2 {
		t.Fatalf("got %d rows, want 2", len(rows))
	}
	if rows[0].Name != "editors" || rows[0].MemberCount != 3 || rows[0].Parent != "" {
		t.Errorf("row 0 = %+v", rows[0])
	}
	if rows[1].Name != "viewers" || rows[1].MemberCount != 1 || rows[1].Parent != "editors" {
		t.Errorf("row 1 = %+v", rows[1])
	}
}

// TestRunGroups_EmptyFleetJSONIsEmptyArrayNotNull proves an empty group set
// still prints valid, parseable JSON ("[]"), not the bare token "null", so a
// scripting consumer's JSON parser never has to special-case an empty fleet.
func TestRunGroups_EmptyFleetJSONIsEmptyArrayNotNull(t *testing.T) {
	l := &fakeGroupLister{groups: nil}
	u, buf := newTestUI()
	if err := runGroups(context.Background(), l, u, true); err != nil {
		t.Fatalf("runGroups --json: %v", err)
	}
	got := strings.TrimSpace(buf.String())
	if got != "[]" {
		t.Errorf("empty-fleet --json output = %q, want []", got)
	}
}

// TestRunGroups_ListFailureSurfacesNonZeroNeverPrintsEmptyList is the fail-
// closed proof (acceptance criterion 5 sibling / the standard's hard rule): a
// ListGroups failure must return an error and print nothing that looks like a
// legitimate, if empty, group report. A pre-fix build that swallowed the error
// and printed "none: Authentik reports no groups" would pass this test's old
// shape and fail this one, which is exactly the silent-empty-list failure mode
// this guards against.
func TestRunGroups_ListFailureSurfacesNeverPrintsEmptyList(t *testing.T) {
	l := &fakeGroupLister{err: fmt.Errorf("authentik: GET /api/v3/core/groups/: HTTP 500")}
	u, buf := newTestUI()
	err := runGroups(context.Background(), l, u, false)
	if err == nil {
		t.Fatal("a ListGroups failure must surface as a command error, not a silent empty report")
	}
	if strings.Contains(buf.String(), "none") {
		t.Errorf("must not print an empty-fleet table on failure, got:\n%s", buf.String())
	}
}

// TestRunGroups_OnlyCallsListGroups proves criterion 4 (strictly read-only) at
// the command level: the only method the fake records is ListGroups, both for
// the table and the --json path.
func TestRunGroups_OnlyCallsListGroups(t *testing.T) {
	l := &fakeGroupLister{groups: []authentik.Group{{PK: "p1", Name: "a"}}}
	u, _ := newTestUI()
	if err := runGroups(context.Background(), l, u, false); err != nil {
		t.Fatalf("runGroups: %v", err)
	}
	if err := runGroups(context.Background(), l, u, true); err != nil {
		t.Fatalf("runGroups --json: %v", err)
	}
	if l.calls != 2 {
		t.Errorf("ListGroups called %d times across two runs, want exactly 2 (no other method exists on the seam)", l.calls)
	}
}
