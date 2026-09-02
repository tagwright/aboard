// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 the aboard authors

// Package daemon is aboard's event-driven control loop. It wires the shared
// runtime socket watch (github.com/tagwright/core) to discovery, the reconciler,
// the Traefik verifier, and beacon, and runs them as one long-lived companion to
// Authentik. It realizes the architecture's "Control loop and state" section
// exactly: watch the socket, debounce container churn, reconcile the affected
// container INSIDE Authentik, audit its Traefik wiring, and alert through beacon,
// with a daily digest that re-emits the sticky errors and the orphan set until
// they are fixed.
//
// Two design points are load-bearing and are deliberate departures from the
// sibling tools' daemons, made for correctness this tool needs and they do not:
//
//   - SERIAL reconciles. Every forward-auth reconcile does a read-modify-write
//     PATCH on the embedded outpost's shared providers list (read the list, add
//     its own provider pk, PATCH the whole list back, because the PATCH replaces
//     rather than merges). Two concurrent reconciles would both read the old
//     list and the second PATCH would clobber the first app's freshly-added
//     membership, silently un-attaching an app that still looks configured. So
//     aboard runs EVERY Authentik-touching operation through a single serial
//     worker goroutine (worker.go). berm's per-container keyedMutex is not
//     enough here, because it lets two DIFFERENT containers reconcile at once,
//     which is exactly the outpost-list hazard. This is proven by a test.
//
//   - DEBOUNCE. A `docker compose up --force-recreate` is a rapid die-plus-start
//     for the same service, and acting on each raw event would thrash Authentik
//     objects. aboard coalesces rapid events per stable service identity over a
//     short quiet window before enqueuing work (debounce.go). There is no
//     server-side rate limit at Authentik 2025.6.4, so this debounce is aboard's
//     own hygiene, not a workaround for one.
//
// Removal follows Fork 8 KEEP: a die or destroy event NEVER tears anything down.
// It just recomputes the orphan set (the removed container's aboard-owned
// objects become orphans, OIDC providers first because they are live
// credentials) and lets the digest carry them. Teardown is `aboard prune` only,
// never the daemon.
package daemon

import (
	"context"
	"io"
	"log/slog"
	"sync"
	"time"

	"github.com/tagwright/beacon"
	"github.com/tagwright/core/runtime"

	"github.com/tagwright/aboard/internal/config"
	"github.com/tagwright/aboard/internal/reconcile"
	"github.com/tagwright/aboard/internal/spec"
)

// DefaultDebounceWindow is the quiet window a stable service identity must go
// without a new lifecycle event before its coalesced change is enqueued. It is
// long enough to swallow a force-recreate's die-plus-start burst and short
// enough that a real change reconciles promptly.
const DefaultDebounceWindow = 750 * time.Millisecond

// DefaultDockerSocket is the runtime socket the CLI-facing Serve dials when no
// other is configured. aboard reads the socket, it never writes to it.
const DefaultDockerSocket = "/var/run/docker.sock"

// Runtime is the narrow slice of github.com/tagwright/core's runtime the daemon
// drives: list every container, inspect one by id, and watch the socket for
// lifecycle events. It is a consumer-defined interface (the Go idiom and the
// house style, matching reconcile.API): declared here, listing only what the
// daemon calls, and satisfied structurally by *runtime.DockerRuntime and
// *runtime.PodmanRuntime without core knowing this interface exists. A tiny fake
// stands in for it in tests, so the whole control loop is exercised without a
// live socket.
type Runtime interface {
	List(ctx context.Context) ([]runtime.Container, error)
	Inspect(ctx context.Context, id string) (runtime.Container, error)
	Watch(ctx context.Context) (<-chan runtime.Event, <-chan error)
}

// Reconciler is the slice of the reconcile package the daemon drives. It is a
// seam for the same reason: a fake proves the serial-execution ordering (the
// shared-outpost hazard) and the KEEP-on-removal behavior without a live
// Authentik. It is satisfied structurally by *reconcile.Reconciler.
//
// Teardown is intentionally part of the seam so a test can PROVE the daemon
// never calls it on a removal event: under Fork 8 KEEP, a die never tears down.
type Reconciler interface {
	Reconcile(ctx context.Context, s spec.Spec) (*reconcile.Result, error)
	Orphans(ctx context.Context, enabledSlugs []string) ([]reconcile.Orphan, error)
	Teardown(ctx context.Context, slug string) error
}

// Notifier is the beacon seam: immediate alerts and the composed digest both go
// through Notify (beacon v0.1.0 has no digest-shaped report method, so the
// digest is a hand-composed Notification, the same path the sibling tools use).
// It is satisfied by *beacon.Beacon and is nil-tolerant at the call site.
type Notifier interface {
	Notify(ctx context.Context, n beacon.Notification) error
}

// Compile-time proof the concrete types satisfy the seams, so the interfaces can
// never drift from what they abstract.
var (
	_ Reconciler = (*reconcile.Reconciler)(nil)
	_ Notifier   = (*beacon.Beacon)(nil)
)

// Config constructs a Daemon. The three seams (Runtime, Reconciler, Notifier)
// and the loaded aboard config are required; the rest default. Injecting the
// seams is what makes the control loop testable.
type Config struct {
	// Runtime is the socket watch/list/inspect seam. Required.
	Runtime Runtime

	// Reconciler converges Authentik and computes orphans. Required.
	Reconciler Reconciler

	// Notifier is the beacon alert path. Nil is tolerated (alerts are dropped),
	// but the CLI always supplies BuildNotifier's log-floored beacon.
	Notifier Notifier

	// Config is the loaded aboard.yml plus globals: the proxy switch and Traefik
	// middleware for the verifier, and the digest schedule. Required.
	Config *config.Config

	// Logger is the structured log. Nil floors to a discard logger, so the daemon
	// never panics on a missing logger (the berm New convention).
	Logger *slog.Logger

	// DebounceWindow overrides DefaultDebounceWindow. Zero uses the default.
	DebounceWindow time.Duration

	// DigestSchedule overrides the cadence. Empty uses the config global
	// (ABOARD_DIGEST_SCHEDULE, default daily).
	DigestSchedule string

	// Now overrides the clock, for tests. Nil uses time.Now.
	Now func() time.Time
}

// Daemon is aboard's running control loop. It holds the seams, the loaded
// config, and the minimal in-memory state the architecture allows: the last
// fleet-callback finding, the current orphan set, the last-applied per-container
// view, and the sticky-error set. There is no datastore and no secret at rest:
// the ownership marker lives in Authentik itself.
type Daemon struct {
	rt         Runtime
	reconciler Reconciler
	notifier   Notifier
	cfg        *config.Config
	log        *slog.Logger
	now        func() time.Time

	debounceWindow time.Duration
	digestSchedule string

	queue  *workQueue
	deb    *debouncer
	sticky *stickySet

	// mu guards the mutable state below.
	mu            sync.Mutex
	fleetCallback bool
	orphans       []reconcile.Orphan
	applied       map[string]appliedView
}

// appliedView is the last-applied summary for one slug: enough for status and
// the digest, never a secret. It is the "last-applied per-container view" the
// architecture's minimal-state section calls for.
type appliedView struct {
	Slug     string
	Provider spec.ProviderType
	Attached bool
	When     time.Time
}

// New builds a Daemon from cfg, applying defaults and validating the required
// seams. It does no socket or network I/O, so construction never blocks and a
// test can build a Daemon over fakes instantly.
func New(cfg Config) (*Daemon, error) {
	if cfg.Runtime == nil {
		return nil, errRequired("a runtime")
	}
	if cfg.Reconciler == nil {
		return nil, errRequired("a reconciler")
	}
	if cfg.Config == nil {
		return nil, errRequired("a loaded aboard config")
	}

	log := cfg.Logger
	if log == nil {
		log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	window := cfg.DebounceWindow
	if window <= 0 {
		window = DefaultDebounceWindow
	}
	schedule := cfg.DigestSchedule
	if schedule == "" {
		schedule = cfg.Config.Globals.DigestSchedule
	}

	d := &Daemon{
		rt:             cfg.Runtime,
		reconciler:     cfg.Reconciler,
		notifier:       cfg.Notifier,
		cfg:            cfg.Config,
		log:            log,
		now:            now,
		debounceWindow: window,
		digestSchedule: schedule,
		queue:          newWorkQueue(),
		sticky:         newStickySet(),
		applied:        map[string]appliedView{},
	}
	// The debouncer's flush enqueues a coalesced per-service sync onto the single
	// serial queue. onFlush is called from a timer goroutine with no context, so
	// the job captures the service key and container id and re-derives the current
	// state when the worker runs it.
	d.deb = newDebouncer(window, func(key, id string) {
		d.queue.push(job{
			key: key,
			run: func(ctx context.Context) { d.syncKey(ctx, key, id) },
		})
	})
	return d, nil
}

// Run starts the control loop and blocks until ctx is cancelled. It starts the
// single serial worker and the digest ticker, enqueues the boot full pass, then
// runs the socket watch in the foreground. On cancellation it closes the queue
// and waits for the background goroutines to drain, the berm Run shape.
func (d *Daemon) Run(ctx context.Context) error {
	d.log.Info("aboard daemon starting",
		"proxy", d.cfg.Proxy,
		"debounce", d.debounceWindow.String(),
		"digest", d.digestSchedule)

	var wg sync.WaitGroup

	// The single serial worker. Every Authentik-touching operation runs here, one
	// at a time, which is what keeps the shared outpost providers list safe.
	wg.Add(1)
	go func() {
		defer wg.Done()
		d.runWorker(ctx)
	}()

	// The daily digest ticker, when the schedule parses to a positive interval.
	if interval := parseSchedule(d.digestSchedule); interval > 0 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			d.runDigest(ctx, interval)
		}()
	} else {
		d.log.Warn("digest disabled: schedule did not parse to a positive interval",
			"schedule", d.digestSchedule)
	}

	// The boot pass: detect the fleet catch-all once, reconcile every enabled
	// container, and compute the orphan set. It runs on the serial worker like
	// everything else.
	d.enqueueFullPass()

	// The socket watch in the foreground, with reconnect-with-backoff. Blocks
	// until ctx is cancelled.
	d.runLoop(ctx)

	// Shutdown: close the queue so the worker drains and exits, then wait.
	d.queue.close()
	d.deb.stop()
	wg.Wait()
	d.log.Info("aboard daemon stopped")
	return nil
}

// enqueueFullPass queues the boot/full reconcile pass onto the serial worker.
func (d *Daemon) enqueueFullPass() {
	d.queue.push(job{
		key: fullPassKey,
		run: func(ctx context.Context) { d.fullPass(ctx) },
	})
}

// setFleetCallback records the latest fleet catch-all finding under the lock.
func (d *Daemon) setFleetCallback(present bool) {
	d.mu.Lock()
	prev := d.fleetCallback
	d.fleetCallback = present
	d.mu.Unlock()
	if prev != present {
		d.log.Info("fleet catch-all callback router detection changed", "present", present)
	}
}

// fleetCallbackPresent reads the latest fleet catch-all finding.
func (d *Daemon) fleetCallbackPresent() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.fleetCallback
}

// setOrphans stores the recomputed orphan set.
func (d *Daemon) setOrphans(orphans []reconcile.Orphan) {
	d.mu.Lock()
	d.orphans = orphans
	d.mu.Unlock()
}

// snapshotOrphans returns a copy of the current orphan set for the digest.
func (d *Daemon) snapshotOrphans() []reconcile.Orphan {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := make([]reconcile.Orphan, len(d.orphans))
	copy(out, d.orphans)
	return out
}

// recordApplied stores the last-applied view for a slug.
func (d *Daemon) recordApplied(sp spec.Spec, res *reconcile.Result) {
	d.mu.Lock()
	d.applied[sp.Slug] = appliedView{
		Slug:     sp.Slug,
		Provider: sp.Provider,
		Attached: res.Attached,
		When:     d.now(),
	}
	d.mu.Unlock()
}
