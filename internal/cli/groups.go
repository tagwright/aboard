// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 the aboard authors

package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"

	"github.com/spf13/cobra"

	"github.com/tagwright/aboard/internal/authentik"
	"github.com/tagwright/aboard/internal/config"
	"github.com/tagwright/aboard/internal/secret"
)

// groupLister is the narrow slice of the Authentik client "aboard groups"
// drives: enumerate every group the credential can read, pagination fully
// walked. *authentik.Client satisfies it structurally, and a test injects a
// fake, so the command's read-only posture (only GET reaches Authentik, no
// reconcile/prune/create/patch/delete) is provable without a live Authentik.
type groupLister interface {
	ListGroups(ctx context.Context) ([]authentik.Group, error)
}

// Compile-time proof the real client satisfies the seam.
var _ groupLister = (*authentik.Client)(nil)

// newAuthentikClient builds the Authentik REST client "aboard groups" reads
// through, resolving the API token by NAME exactly as newReconciler does for
// status and prune. groups needs the raw client (ListGroups is not part of the
// reconciler's narrow API seam, which only exposes what convergence uses).
func newAuthentikClient(cfg *config.Config) (*authentik.Client, error) {
	resolve := secret.FileEnvResolver(cfg.Globals.SecretsDir)
	return authentik.FromConfig(cfg, resolve)
}

// groupRow is one group's printable and JSON-serializable shape: name, member
// count, and parent name (blank for a top-level group). Building rows from raw
// Authentik groups is pure (no I/O), so it is exhaustively invariant-tested
// separately from the command wiring.
type groupRow struct {
	Name        string `json:"name"`
	MemberCount int    `json:"member_count"`
	Parent      string `json:"parent"`
}

// newGroupsCmd wires "aboard groups": a READ-ONLY listing of every Authentik
// group the aboard credential can see, so an operator can discover the
// assignable group namespace before naming one in aboard.groups or a
// downstream role-mapping rule. It is modeled on newStatusCmd (it reads live
// Authentik and prints), not newRenderCmd (deliberately Authentik-free): it
// performs no reconcile, prune, create, patch, or delete, only GET requests
// reach Authentik.
func newGroupsCmd() *cobra.Command {
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "groups",
		Short: "List every Authentik group the credential can read",
		Long: `groups enumerates the Authentik group namespace, read-only, with pagination
fully walked, so an operator can see which groups exist before naming one in
aboard.groups or a downstream role-mapping rule. It performs no reconcile,
prune, create, or write: only GET requests reach Authentik.

Each row shows the group's name, its member count, and its parent group's
name (blank for a top-level group). The table is sorted by name with a stable
column order.

With --json, prints the same data as a JSON array of objects shaped
{"name": string, "member_count": int, "parent": string}, parent an empty
string ("") for a top-level group, for scripting access-as-code.

If the group namespace cannot be enumerated (an Authentik error, a decode
failure, or a truncated response), groups exits non-zero with that error. It
never prints an empty list as if the fleet had no groups.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := loadConfig()
			if err != nil {
				return err
			}
			client, err := newAuthentikClient(cfg)
			if err != nil {
				return err
			}
			return runGroups(cmd.Context(), client, newUI(cmd.OutOrStdout()), asJSON)
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "print the group list as a JSON array of {name, member_count, parent}")
	return cmd
}

// runGroups lists every group through lister and prints it as a table or, with
// asJSON, a JSON array. A ListGroups failure is returned as-is so the command
// exits non-zero: it is fail-closed by construction, since there is no branch
// that prints a partial or empty list on error.
func runGroups(ctx context.Context, lister groupLister, u ui, asJSON bool) error {
	groups, err := lister.ListGroups(ctx)
	if err != nil {
		return fmt.Errorf("list groups: %w", err)
	}
	rows := groupRows(groups)
	if asJSON {
		return printGroupsJSON(u, rows)
	}
	printGroupsTable(u, rows)
	return nil
}

// groupRows converts raw Authentik groups into the sorted, printable rows. It
// is pure: no I/O, so it is where the Level 1 invariant tests live (sorted by
// name, every group appears exactly once, a blank parent renders "" not a
// literal "nil", member count matches the input's user-pk-list length).
func groupRows(groups []authentik.Group) []groupRow {
	rows := make([]groupRow, 0, len(groups))
	for _, g := range groups {
		parent := ""
		if g.ParentName != nil {
			parent = *g.ParentName
		}
		rows = append(rows, groupRow{
			Name:        g.Name,
			MemberCount: len(g.Users),
			Parent:      parent,
		})
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].Name < rows[j].Name })
	return rows
}

// printGroupsTable prints the human-readable table, one group per line, name
// first so the column order is stable.
func printGroupsTable(u ui, rows []groupRow) {
	u.printf("%s\n", u.bold("Groups"))
	if len(rows) == 0 {
		u.printf("  %s\n", u.dim("none: Authentik reports no groups"))
		return
	}
	for _, r := range rows {
		parent := r.Parent
		if parent == "" {
			parent = "-"
		}
		u.printf("  %-30s  %s  %s\n",
			r.Name,
			u.dim(fmt.Sprintf("members=%d", r.MemberCount)),
			u.dim("parent="+parent))
	}
}

// printGroupsJSON prints rows as an indented JSON array, an empty array (never
// null) when there are no groups, so the shape stays parseable either way.
func printGroupsJSON(u ui, rows []groupRow) error {
	if rows == nil {
		rows = []groupRow{}
	}
	enc := json.NewEncoder(u.w)
	enc.SetIndent("", "  ")
	return enc.Encode(rows)
}
