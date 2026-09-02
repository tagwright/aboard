// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 the aboard authors

package spec

import "testing"

// TestGroupsThreeState locks the three-state Groups model: unset (use the fleet
// default), the explicit none sentinel (no group gate), and an explicit list.
func TestGroupsThreeState(t *testing.T) {
	tests := []struct {
		name     string
		spec     Spec
		wantNone bool
	}{
		{"unset uses fleet default", Spec{GroupsSet: false}, false},
		{"explicit none sentinel", Spec{GroupsSet: true, Groups: nil}, true},
		{"explicit empty slice is none", Spec{GroupsSet: true, Groups: []string{}}, true},
		{"explicit list is not none", Spec{GroupsSet: true, Groups: []string{"staff"}}, false},
	}
	for _, tc := range tests {
		if got := tc.spec.GroupsNone(); got != tc.wantNone {
			t.Errorf("%s: GroupsNone got %v, want %v", tc.name, got, tc.wantNone)
		}
	}
}
