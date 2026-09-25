# Enforceability layer

These are the CI-enforceable checks the [tagwright Testing Standard][std]
calls its enforceability layer (task #552). They turn several of the standard's
rules from prose into gates that re-run on every CI, so a rule fails the build
the moment it stops being true rather than living in someone's memory.

They run on the **hosted** CI leg (`.github/workflows/ci.yml`), not the
self-hosted runner. None needs a Docker socket or kernel privilege: they are
static analysis and `go test`-level, so they belong beside `go build` / `go
vet` / `go test`, and the self-hosted runner stays reserved for the live
integration harness (`test/integration/run-all.sh`).

Run them all locally the same way CI does, inside the repo's `golang:1.25`
container (there is no host Go):

    docker run --rm -v "$PWD":/w -v aboard-gomodcache:/go/pkg/mod -w /w \
      -e GOPRIVATE=github.com/tagwright/* -e GOFLAGS=-buildvcs=false golang:1.25 \
      sh -c 'test/enforce/run-all.sh'

## The checks

### `check-skip-budget.sh` — the skip budget

A `t.Skip` is how a test goes green without proving anything, so the standard
caps them. This check splits skips into two buckets by build tag:

- **Always-run leg** (test files with no `//go:build integration` tag, the ones
  `go test ./...` compiles and runs on every CI): skips are banned outright,
  budget **0**, no ratchet. That leg runs in plain CI where every resource a
  test needs is present, so a skip there can only be skip-to-get-green.
- **Integration leg** (`//go:build integration` files, run by the live harness
  on the self-hosted runner or by the operator): skips are the *allowed*
  resource-absent kind. Their count is capped at the committed budget in
  `skip-budget.txt`, a **ratchet**: removing a skip never breaks the build, and
  raising the budget is a reviewed change that must name the new resource-absent
  skip it admits.

aboard has zero `t.Skip` today and its live harness is shell, not Go, so the
integration budget is 0. See `skip-budget.txt`.

### `check-wiring-coverage.sh` — the wiring-package coverage floor

A per-package statement-coverage floor, committed in `coverage-floor.txt`,
scoped to the **wiring** packages only (`internal/discovery`,
`internal/reconcile`, `internal/daemon`, `internal/authentik`) — the
socket-event-to-effect and drive-the-backend layer where this suite's confirmed
bugs actually live. It is deliberately not a global percentage: a global number
rewards testing the cheap pure core and is satisfied while the wiring stays
untouched. aboard's Traefik verifier (`internal/traefik`) is pure core, not
wiring, and is not floored here; see the note in `coverage-floor.txt`. The floor
is a ratchet: it may only rise. Edit a number upward when coverage climbs; never
downward to make a regression pass.

### `check-deadcode.sh` — the built-but-not-wired analyzer

Runs `golang.org/x/tools/cmd/deadcode` (pinned) rooted at the real `main`.
aboard is a daemon module (`cmd/aboard` has a `main`), so the analyzer roots at
`deadcode ./...` (never `-test`, which would hide the built-but-not-wired class
this gate exists to catch). Any function unreachable from the production
entrypoint is reported and fails the build. This machine-checks the
built-but-not-wired class directly — the Billet dead-code lesson that every unit
test passed over. Zero tolerance: aboard has zero dead code today (test-only
helpers live in `_test.go` files, not the production tree) and the gate keeps it
that way.

### `check-testing-doc.sh` — the docs/TESTING.md gate-check

Asserts every test name and file path `docs/TESTING.md` cites actually exists in
the tree, so the honest-reporting doc cannot rot into citing tests that were
renamed or files that moved. Citations are the backtick-quoted code spans in the
doc. See the script header for the exact citation grammar and the cross-module
rule.

### `check-last-run.sh` — the live-harness LAST-RUN attestation

Asserts `test/integration/LAST-RUN` exists and is well-formed. In `--release`
mode (run by the release job at the tag) it also asserts that, if any
operator-run scenarios are recorded, their attestation `sha` equals the tag being
published exactly. With `operator_run: none` — aboard's current state, since the
harness CI-gates every scenario (api, pass, golive) — there is nothing that can
go stale, so it passes. See `../integration/LAST-RUN`.

## The committed data files

- `skip-budget.txt` — the integration-leg skip ceiling.
- `coverage-floor.txt` — per-wiring-package floors, `<package> <percent>`.

Bumping either is a normal reviewed edit. Lowering a floor, or raising the skip
budget without naming the skip it admits, is the move the standard's "never
weaken a gate to make code pass" rule forbids.

[std]: the tagwright Testing Standard (wiki, tagwright/operating/Testing Standard)
