// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 the aboard authors

package daemon

import (
	"context"
	"time"

	"github.com/tagwright/core/runtime"
)

// watchReconnectDelay is the pause between socket-watch subscriptions when one
// ends (a dropped connection, a daemon restart). It mirrors berm's reconnect
// backoff: a long-lived companion daemon must re-subscribe rather than exit when
// the socket blips.
const watchReconnectDelay = 2 * time.Second

// runLoop runs the socket watch until the context is cancelled, re-subscribing
// with a short backoff whenever a subscription ends. This is the foreground of
// Run: it blocks the daemon alive. The actual event handling is thin (hand each
// event to the debouncer); all the reconcile and verify logic lives on the serial
// worker, off this goroutine.
func (d *Daemon) runLoop(ctx context.Context) {
	for {
		if ctx.Err() != nil {
			return
		}
		d.watchOnce(ctx)
		select {
		case <-ctx.Done():
			return
		case <-time.After(watchReconnectDelay):
		}
	}
}

// watchOnce runs one Watch subscription to completion: its end (both channels
// closed), a terminal error, or context cancellation. core's Watch returns an
// event channel and an error channel and closes both when the subscription ends.
func (d *Daemon) watchOnce(ctx context.Context) {
	events, errs := d.rt.Watch(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case err, ok := <-errs:
			if !ok {
				return
			}
			if err != nil {
				d.log.Warn("runtime watch error", "err", err.Error())
			}
		case ev, ok := <-events:
			if !ok {
				return
			}
			d.handleEvent(ev)
		}
	}
}

// handleEvent is the thin socket-to-loop glue. core emits start, stop, die, and
// destroy events (there is no create event; a new container surfaces as start).
// Every lifecycle event for a service feeds the debouncer keyed by the stable
// service identity, so a force-recreate's die-plus-start burst coalesces into one
// settled change before any Authentik work happens. The debouncer's flush
// enqueues a single serial sync (see New). Removal events (stop/die/destroy) go
// through the same path: the settled sync inspects the container and, finding it
// gone, recomputes orphans WITHOUT tearing anything down (Fork 8 KEEP).
func (d *Daemon) handleEvent(ev runtime.Event) {
	switch ev.Type {
	case runtime.EventStart, runtime.EventStop, runtime.EventDie, runtime.EventDestroy:
		d.deb.observe(serviceKeyFromEvent(ev), ev.ID)
	default:
		// Other actions are already filtered out by core, but guard anyway.
	}
}
