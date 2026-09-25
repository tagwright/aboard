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
	"sort"
	"sync"
	"time"

	"github.com/tagwright/core/runtime"
	"github.com/tagwright/courier"

	"github.com/tagwright/aboard/internal/config"
	"github.com/tagwright/aboard/internal/reconcile"
	"github.com/tagwright/aboard/internal/spec"
	"github.com/tagwright/aboard/internal/traefik"
)

// DefaultDebounceWindow is the quiet window a stable service identity must go
// without a new lifecycle event before its coalesced change is enqueued. It is
// long enough to swallow a force-recreate's die-plus-start burst and short
// enough that a real change reconciles promptly.
const DefaultDebounceWindow = 750 * time.Millisecond

// DefaultShutdownStall bounds how long the graceful drain waits with NO job
// completing before it treats the in-flight reconcile as hung and cancels the
// worker. It is progress-relative, not a global deadline: a healthy backlog
// completes a job well within this window, so a steady stream of completions
// keeps resetting it and the drain runs for as long as real progress continues,
// however large the backlog. Only a genuinely stuck reconcile (a wedged Authentik
// REST call that never returns) lets this window elapse, and then it is cut
// promptly rather than at a fixed whole-drain deadline.
const DefaultShutdownStall = 5 * time.Second

// DefaultShutdownCeiling is the absolute backstop on the graceful drain: however
// much progress the worker keeps reporting, the drain cannot outlive this ceiling.
// It caps a pathological case that keeps "completing" trivial work forever (which
// would keep resetting the stall window and never let it fire), so the drain
// always self-bounds. It is set below a typical service-manager stop timeout
// (systemd SIGKILLs at TimeoutStopSec), so aboard cancels its own in-flight work
// cleanly rather than being killed mid-write.
const DefaultShutdownCeiling = 30 * time.Second

// DefaultDockerSocket is the socket BuildRuntime dials for runtime "docker" when
// no socket override is configured. aboard reads the socket, it never writes to
// it. The podman counterpart is DefaultPodmanSocket in runtime.go.
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
// It is satisfied by *courier.Beacon and is nil-tolerant at the call site.
type Notifier interface {
	Notify(ctx context.Context, n courier.Notification) error
}

// Compile-time proof the concrete types satisfy the seams, so the interfaces can
// never drift from what they abstract.
var (
	_ Reconciler = (*reconcile.Reconciler)(nil)
	_ Notifier   = (*courier.Beacon)(nil)
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
	// but the CLI always supplies BuildNotifier's log-floored courier.
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

	// shutdownStall and shutdownCeiling bound the graceful drain (see Run). They
	// are set from the Default* consts in New so a test can inject small values and
	// drive the watchdog deterministically.
	shutdownStall   time.Duration
	shutdownCeiling time.Duration

	// jobDone is the drain watchdog's progress signal: the serial worker does a
	// non-blocking send on it after every job it finishes, and the shutdown drain
	// resets its stall timer on each one. Size 1 so a burst coalesces to a single
	// pending signal and the send never blocks the worker.
	jobDone chan struct{}

	queue  *workQueue
	deb    *debouncer
	sticky *stickySet

	// mu guards the mutable state below.
	mu            sync.Mutex
	fleetCallback bool
	groupsHeader  traefik.GroupsHeaderState
	orphans       []reconcile.Orphan
	applied       map[string]appliedView
	// slugByKey maps a debounce key (the stable service identity) to the Authentik
	// slug last resolved for it. A removal event carries only the key (the
	// container is gone, so its labels can no longer be read to re-derive the
	// slug), and the sticky set is keyed by slug, so this index is what lets a
	// single removal clear exactly that slug's sticky errors.
	slugByKey map[string]string
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
		rt:              cfg.Runtime,
		reconciler:      cfg.Reconciler,
		notifier:        cfg.Notifier,
		cfg:             cfg.Config,
		log:             log,
		now:             now,
		debounceWindow:  window,
		digestSchedule:  schedule,
		shutdownStall:   DefaultShutdownStall,
		shutdownCeiling: DefaultShutdownCeiling,
		jobDone:         make(chan struct{}, 1),
		queue:           newWorkQueue(),
		sticky:          newStickySet(),
		applied:         map[string]appliedView{},
		slugByKey:       map[string]string{},
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

	// The serial worker runs on its OWN context, rooted at Background rather than
	// the caller's ctx. On shutdown (ctx cancelled) we flush the debouncer's
	// pending work onto the queue and let the worker drain it; if the worker shared
	// the already-cancelled ctx it would abort every in-flight reconcile the moment
	// ctx was done, so the flush would enqueue work that never ran. workerCtx keeps
	// the drain alive, and the progress-aware watchdog below cancels it if a
	// reconcile hangs or the absolute ceiling fires, so shutdown still always
	// completes.
	workerCtx, cancelWorker := context.WithCancel(context.Background())
	defer cancelWorker()

	// The single serial worker. Every Authentik-touching operation runs here, one
	// at a time, which is what keeps the shared outpost providers list safe.
	wg.Add(1)
	go func() {
		defer wg.Done()
		d.runWorker(workerCtx)
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

	// Graceful shutdown. The socket watch has returned, so no new events arrive.
	// Flush the debouncer's pending coalesced changes onto the serial queue so a
	// settled change is reconciled rather than dropped, block further observes,
	// then close the queue so the worker drains the remaining jobs and exits. Order
	// matters: flushNow must run BEFORE close (a push to a closed queue is dropped).
	d.deb.flushNow()
	d.deb.stop()
	d.queue.close()

	// Wait for the worker (and the digest goroutine, already unwound by ctx) to
	// drain, but bound it with a PROGRESS-AWARE watchdog rather than one blind
	// whole-drain deadline. A healthy backlog that keeps completing jobs drains in
	// full, however long that takes; only a lack of progress or the absolute
	// ceiling cuts it short:
	//
	//   - The worker signals every completed job on d.jobDone, and each signal
	//     resets the stall timer, so a steady stream of completions never trips it.
	//   - The stall timer fires only when NO job completes for shutdownStall, the
	//     signature of a hung reconcile (a wedged Authentik REST call). Then the
	//     worker is cancelled and the hang is cut promptly, not after a fixed 10s a
	//     large healthy backlog would also have blown.
	//   - The ceiling timer is absolute and never reset, so a pathological stream
	//     that keeps completing trivial work forever (which would keep resetting the
	//     stall window) still cannot outlive shutdownCeiling. The drain always
	//     self-bounds below the service manager's stop timeout.
	drained := make(chan struct{})
	go func() {
		wg.Wait()
		close(drained)
	}()

	// Clear any completion left in the buffer from normal operation, so the first
	// stall window measures progress made DURING the drain, not before it.
	select {
	case <-d.jobDone:
	default:
	}

	stall := time.NewTimer(d.shutdownStall)
	defer stall.Stop()
	ceiling := time.NewTimer(d.shutdownCeiling)
	defer ceiling.Stop()

	for done := false; !done; {
		select {
		case <-drained:
			// The worker finished every pending job on its own: a clean drain.
			done = true
		case <-d.jobDone:
			// The worker completed a job: progress. Reset the stall window. The
			// Stop-then-drain guards the reset against a timer that just fired.
			if !stall.Stop() {
				select {
				case <-stall.C:
				default:
				}
			}
			stall.Reset(d.shutdownStall)
		case <-stall.C:
			d.log.Warn("shutdown drain stalled, cancelling in-flight reconcile",
				"stall", d.shutdownStall.String())
			cancelWorker()
			<-drained
			done = true
		case <-ceiling.C:
			d.log.Warn("shutdown drain hit absolute ceiling, cancelling in-flight reconcile",
				"ceiling", d.shutdownCeiling.String())
			cancelWorker()
			<-drained
			done = true
		}
	}

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

// setGroupsHeader records the latest forward-auth group-delivery scan: whether
// the shared middleware's authResponseHeaders carries X-authentik-groups.
func (d *Daemon) setGroupsHeader(state traefik.GroupsHeaderState) {
	d.mu.Lock()
	prev := d.groupsHeader
	d.groupsHeader = state
	d.mu.Unlock()
	if prev != state {
		d.log.Info("forward-auth groups header detection changed", "state", int(state))
	}
}

// groupsHeaderState reads the latest forward-auth group-delivery scan.
func (d *Daemon) groupsHeaderState() traefik.GroupsHeaderState {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.groupsHeader
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

// recordApplied stores the last-applied view for a slug. res.Attached is the
// go-live ground truth: after the go-live verification it is true only when the
// live outpost actually serves the host, not merely when the provider is in the
// DB list, so When is a genuine last-CONFIRMED-Authentik-write timestamp.
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

// rememberSlug records the slug last resolved for a debounce key, so a later
// removal event (which carries only the key, the container being gone) can clear
// exactly that slug's sticky state. Called whenever a container is processed as
// enabled.
func (d *Daemon) rememberSlug(key, slug string) {
	d.mu.Lock()
	d.slugByKey[key] = slug
	d.mu.Unlock()
}

// forgetSlug drops the key->slug mapping for a key whose container is gone or has
// opted out, so the index does not accumulate stale entries.
func (d *Daemon) forgetSlug(key string) {
	d.mu.Lock()
	delete(d.slugByKey, key)
	d.mu.Unlock()
}

// lookupSlug returns the slug last resolved for a debounce key and whether one
// was recorded.
func (d *Daemon) lookupSlug(key string) (string, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	slug, ok := d.slugByKey[key]
	return slug, ok
}

// snapshotApplied returns the last-applied views in a stable order (by slug), the
// CONFIRMED side of the digest: what aboard last actually wrote to Authentik and
// when, as opposed to what the labels merely DISCOVER.
func (d *Daemon) snapshotApplied() []appliedView {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := make([]appliedView, 0, len(d.applied))
	for _, v := range d.applied {
		out = append(out, v)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Slug < out[j].Slug })
	return out
}
