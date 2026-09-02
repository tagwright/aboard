// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 the aboard authors

package cli

import (
	"context"
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/tagwright/aboard/internal/blueprint"
	"github.com/tagwright/aboard/internal/config"
	"github.com/tagwright/aboard/internal/daemon"
	"github.com/tagwright/aboard/internal/discovery"
	"github.com/tagwright/aboard/internal/spec"
	"github.com/tagwright/aboard/internal/traefik"
)

// newRenderCmd wires "aboard render <service>" and "aboard render --setup". Both
// are PURE OUTPUT: they print the Traefik labels an operator should paste and
// write nothing, and neither calls Authentik. For a named service it prints that
// service's middleware line and, if the mixed-host rule needs one, its callback
// block. With --setup it prints the once-per-fleet shared middleware definition
// and the recommended fleet catch-all callback router.
func newRenderCmd() *cobra.Command {
	var setup, blueprintFlag, serviceAccountFlag bool

	cmd := &cobra.Command{
		Use:   "render [service]",
		Short: "Print the Traefik labels for a service, --setup for the fleet pieces, --blueprint for the identity IaC, or --service-account for aboard's own least-privilege identity",
		Long: `render prints the config aboard recommends. It writes nothing: aboard never
edits Traefik configuration or Authentik identity objects, these are for you.

  aboard render <service>          the middleware line and, on a mixed host, the
                                   outpost callback router for one service
  aboard render --setup            the once-per-fleet shared forward-auth
                                   middleware definition and the catch-all router
  aboard render --blueprint        an Authentik blueprint defining the groups your
                                   labels bind and the OIDC groups scope mapping,
                                   the identity objects aboard references by name
  aboard render --service-account  an Authentik blueprint declaring aboard's OWN
                                   least-privilege identity: a non-superuser
                                   service-account user, an RBAC role with exactly
                                   aboard's minimal permissions, the role-to-user
                                   binding, and an intent=api token (Authentik
                                   generates the key, it is NOT in the output)`,
		Args: cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			modes := 0
			for _, on := range []bool{setup, blueprintFlag, serviceAccountFlag} {
				if on {
					modes++
				}
			}
			if modes > 1 {
				return fmt.Errorf("render takes at most one of --setup, --blueprint, or --service-account")
			}
			if modes == 1 {
				if len(args) != 0 {
					return fmt.Errorf("render --setup / --blueprint / --service-account takes no service argument")
				}
			} else if len(args) != 1 {
				return fmt.Errorf("render requires exactly one <service> argument, or --setup / --blueprint / --service-account")
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
			if serviceAccountFlag {
				runRenderServiceAccount(cfg, u)
				return nil
			}

			rt := newRuntime()
			defer rt.Close()
			if blueprintFlag {
				return runRenderBlueprint(cmd.Context(), cfg, rt, u)
			}
			return runRenderService(cmd.Context(), cfg, rt, args[0], u)
		},
	}

	cmd.Flags().BoolVar(&setup, "setup", false, "print the once-per-fleet Traefik pieces instead of a single service")
	cmd.Flags().BoolVar(&blueprintFlag, "blueprint", false, "print the Authentik identity blueprint (groups + the OIDC groups scope mapping)")
	cmd.Flags().BoolVar(&serviceAccountFlag, "service-account", false, "print the Authentik blueprint for aboard's own least-privilege service account, role, and API token")
	return cmd
}

// runRenderBlueprint collects every distinct group the enabled fleet binds (the
// explicit aboard.groups labels plus the fleet default defaults.groups) and emits
// the Authentik blueprint that defines those groups and the OIDC groups scope
// mapping. It is the identity-layer analog of runRenderService: it lists
// containers and discovers each, but touches no Authentik and writes nothing.
func runRenderBlueprint(ctx context.Context, cfg *config.Config, lister containerLister, u ui) error {
	containers, err := lister.List(ctx)
	if err != nil {
		return err
	}

	var groups []string
	groups = append(groups, cfg.Defaults.Groups...)
	for _, c := range containers {
		if daemon.IsSelfExcluded(c) {
			continue
		}
		sp, _ := discovery.Discover(cfg, daemon.InputFrom(c))
		if !sp.Enable {
			continue
		}
		groups = append(groups, sp.Groups...)
	}

	scope := cfg.OIDC.GroupsScope
	if scope == "" {
		scope = config.DefaultGroupsScope
	}
	u.print(blueprint.Render(groups, scope))
	return nil
}

// runRenderSetup prints the once-per-fleet Traefik pieces. Pure output.
func runRenderSetup(cfg *config.Config, u ui) {
	u.print(traefik.RenderSetup(cfg))
}

// runRenderServiceAccount prints the Authentik blueprint for aboard's OWN
// least-privilege identity: the service-account user, the RBAC role with exactly
// aboard's minimal permissions, the role-to-user binding, and an intent=api
// token. The token's Authentik identifier defaults to the aboard.yml token NAME
// so the emitted object and the secret aboard reads line up. Pure output: it
// touches no Docker and no Authentik, and the emitted blueprint contains NO key
// value (Authentik generates the token key at reconcile).
func runRenderServiceAccount(cfg *config.Config, u ui) {
	u.print(blueprint.RenderServiceAccount(cfg.Authentik.Token))
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

		// SAML is server-served and has no Traefik half, so there is nothing to
		// paste. What the operator needs is the IdP metadata URL to hand to the SP,
		// the analog of the OIDC discovery URL. aboard automates the Authentik side
		// only: the ACS URL and entity ID still get configured on the SP by hand.
		if sp.Provider == spec.ProviderSAML {
			u.print(renderSAML(cfg, &sp))
			return nil
		}

		vr := traefik.Verify(cfg, &sp, c.Labels, fleetCallback)
		u.print(traefik.RenderService(cfg, &sp, vr))
		return nil
	}

	return fmt.Errorf("render: no aboard-enabled container found for service %q", service)
}

// samlMetadataURL composes the IdP SAML metadata URL for a slug from the fleet
// public_url: {public_url}/application/saml/{slug}/metadata/. This is the stable
// application-slug metadata endpoint Authentik serves once the provider is linked
// to its application (verified against authentik/providers/saml/urls.py at tag
// version/2025.6.4). It is composed statically, with no Authentik call, so render
// stays pure output. An empty public_url yields a relative path the caller notes.
func samlMetadataURL(cfg *config.Config, slug string) string {
	base := strings.TrimRight(cfg.Authentik.PublicURL, "/")
	return base + "/application/saml/" + slug + "/metadata/"
}

// renderSAML returns the SAML render output for a service: the IdP metadata URL
// to hand to the SP, and the reminder that the ACS URL and entity ID are plumbed
// into the SP by hand. It writes nothing, it returns a string.
func renderSAML(cfg *config.Config, sp *spec.Spec) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# aboard render %s: SAML has no Traefik half, nothing to paste.\n", sp.Name)
	b.WriteString("# aboard automates the Authentik side. Hand this IdP metadata URL to the SP:\n")
	b.WriteString("#\n")
	if cfg.Authentik.PublicURL == "" {
		b.WriteString("#   (set authentik.public_url in aboard.yml to compose the absolute URL)\n")
		b.WriteString("#   " + samlMetadataURL(cfg, sp.Slug) + "\n")
	} else {
		b.WriteString("#   " + samlMetadataURL(cfg, sp.Slug) + "\n")
	}
	b.WriteString("#\n")
	b.WriteString("# The ACS URL and entity ID still get configured on the SP by hand:\n")
	b.WriteString("#   ACS URL:   " + sp.SAML.ACSUrl + "\n")
	if sp.SAML.Audience != "" {
		b.WriteString("#   Entity ID: " + sp.SAML.Audience + "\n")
	}
	return b.String()
}
