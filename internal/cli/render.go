// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 the aboard authors

package cli

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/tagwright/aboard/internal/config"
	"github.com/tagwright/aboard/internal/daemon"
	"github.com/tagwright/aboard/internal/discovery"
	"github.com/tagwright/aboard/internal/traefik"
)

// newRenderCmd wires "aboard render <service>" and "aboard render --setup". Both
// are PURE OUTPUT: they print the Traefik labels an operator should paste and
// write nothing, and neither calls Authentik. For a named service it prints that
// service's middleware line and, if the mixed-host rule needs one, its callback
// block. With --setup it prints the once-per-fleet shared middleware definition
// and the recommended fleet catch-all callback router.
func newRenderCmd() *cobra.Command {
	var setup bool

	cmd := &cobra.Command{
		Use:   "render [service]",
		Short: "Print the Traefik labels for a service, or --setup for the fleet pieces",
		Long: `render prints the Traefik labels aboard recommends. It writes nothing:
aboard never edits Traefik configuration, these are for you to paste.

  aboard render <service>   the middleware line and, on a mixed host, the
                            outpost callback router for one service
  aboard render --setup     the once-per-fleet shared forward-auth middleware
                            definition and the fleet catch-all callback router`,
		Args: cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if setup {
				if len(args) != 0 {
					return fmt.Errorf("render --setup takes no service argument")
				}
			} else if len(args) != 1 {
				return fmt.Errorf("render requires exactly one <service> argument, or --setup")
			}

			cfg, err := loadConfig()
			if err != nil {
				return err
			}
			u := newUI(cmd.OutOrStdout())

			if setup {
				runRenderSetup(cfg, u)
				return nil
			}

			rt := newRuntime()
			defer rt.Close()
			return runRenderService(cmd.Context(), cfg, rt, args[0], u)
		},
	}

	cmd.Flags().BoolVar(&setup, "setup", false, "print the once-per-fleet Traefik pieces instead of a single service")
	return cmd
}

// runRenderSetup prints the once-per-fleet Traefik pieces. Pure output.
func runRenderSetup(cfg *config.Config, u ui) {
	u.print(traefik.RenderSetup(cfg))
}

// runRenderService finds the named service among the running containers, discovers
// its Spec, audits its Traefik wiring, and prints the render output. It is the
// testable core: a fake lister and colour-off ui run it with no socket. It calls
// no Authentik.
func runRenderService(ctx context.Context, cfg *config.Config, lister containerLister, service string, u ui) error {
	containers, err := lister.List(ctx)
	if err != nil {
		return err
	}
	fleetCallback := daemon.DetectFleetCallback(containers)

	for _, c := range containers {
		if daemon.IsSelfExcluded(c) {
			continue
		}
		sp, issues := discovery.Discover(cfg, daemon.InputFrom(c))
		if sp.Name != service {
			continue
		}

		if !sp.Enable {
			u.printf("# aboard: %s is not aboard-enabled (aboard.enable is absent or false), nothing to render.\n", service)
			return nil
		}

		// Surface discovery errors as leading comments so the operator knows the
		// render is built on labels that will be skipped by the daemon.
		if discovery.HasError(issues) {
			u.printf("# aboard: %s has label errors (run \"aboard validate\"), the render below may be incomplete:\n", service)
			for _, is := range issues {
				if is.Severity == discovery.SeverityError {
					u.printf("#   %s: %s\n", is.Code, is.Message)
				}
			}
		}

		vr := traefik.Verify(cfg, &sp, c.Labels, fleetCallback)
		u.print(traefik.RenderService(cfg, &sp, vr))
		return nil
	}

	return fmt.Errorf("render: no aboard-enabled container found for service %q", service)
}
