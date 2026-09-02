// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 the aboard authors

package daemon

import (
	"github.com/tagwright/beacon"

	"github.com/tagwright/aboard/internal/config"
	"github.com/tagwright/aboard/internal/secret"
)

// BuildNotifier constructs the beacon notifier the daemon and the CLI both alert
// through, with the structured-log floor ALWAYS on so a run's outcome is never
// silently unreported. This is the single shared notification path, mirroring
// ballast's daemon.BuildNotifier: the daemon and any ad-hoc command report
// through the same channels.
//
// aboard.yml carries no notification-channel block in v1 (unlike ballast's
// cfg.Notifications), so the beacon config here is exactly the log floor: a
// "log" channel at info level, beacon's built-in always-on backend. When
// aboard.yml grows a channels block, map each entry onto beacon.ChannelConfig
// here the way ballast does (parse the level, carry the settings), and keep the
// len==0 fallback to the log floor. The secret resolver is handed to beacon so a
// future channel that names a secret (a webhook token) resolves it by NAME the
// same inward-only way the rest of aboard does.
func BuildNotifier(cfg *config.Config, resolve secret.Resolver) (*beacon.Beacon, error) {
	channels := []beacon.ChannelConfig{
		{Type: "log", MinLevel: beacon.LevelInfo},
	}
	beaconCfg := beacon.Config{Channels: channels}
	return beacon.New(beaconCfg, beacon.SecretResolver(resolve))
}
