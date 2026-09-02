// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 the aboard authors

// Package secret resolves the named-secret references that aboard.yml and the
// aboard.* labels carry: the Authentik API token (the crown jewel) and the
// OIDC client secrets. Nothing in this package ever holds a secret value longer
// than it has to, and no secret value is ever logged. Secrets flow one way,
// from the operator's store (berm-provisioned files) into Authentik, never out.
//
// The resolver is file-first, matching the grammar's "Secret reference syntax":
// a name resolves from a file under ABOARD_SECRETS_DIR, then falls back to an
// environment variable. Whichever source supplies the value, it is trimmed the
// same way, so a file with a trailing newline and an env var without one
// resolve to the identical secret. That file-vs-env trim consistency is
// load-bearing: an OIDC client secret pushed into Authentik must be byte-for-
// byte what the downstream app reads from its own store.
package secret

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf8"
)

// DefaultSecretsDir is used when a caller does not set ABOARD_SECRETS_DIR or
// otherwise configure a directory. It matches config.DefaultSecretsDir and the
// grammar's Globals section.
const DefaultSecretsDir = "/run/aboard/secrets"

// MinOIDCSecretLength is the minimum length aboard accepts for an OIDC client
// secret before pushing it into Authentik. Pushing a weak operator-chosen
// secret into an IdP is a footgun worth one check (Fork 7).
const MinOIDCSecretLength = 32

// Resolver resolves a named secret to its value. It is the single seam through
// which every named-secret reference in aboard.yml or a label gets its value:
// names live in config and labels, values live in files.
//
// The signature matches beacon.SecretResolver and ballast's, so the same
// Resolver can be handed to any suite module that consumes secrets by name.
type Resolver func(name string) (string, error)

// FileEnvResolver returns a Resolver that looks up name first as a file under
// secretsDir, then as an environment variable.
//
// Resolution order, matching the grammar's "Secret reference syntax":
//  1. File filepath.Join(secretsDir, name).
//  2. Env var ABOARD_SECRET_<NAME>, where NAME is name uppercased with "-"
//     replaced by "_".
//  3. Neither found: an error naming the secret, so the caller can skip and
//     alert on the owning container rather than fail silently.
//
// Whichever source a value comes from, it is trimmed the same way: leading and
// trailing whitespace (spaces, tabs, CR, LF) is stripped before it is returned.
// This keeps a secret's resolved value identical regardless of source, so an
// OIDC client secret read from a file with a trailing newline matches the same
// secret pasted into an env var without one. The file-vs-env trim inconsistency
// this guards against was a real bug once, and it is exactly the kind a secrets
// path must not carry.
//
// secretsDir defaults to DefaultSecretsDir when empty.
func FileEnvResolver(secretsDir string) Resolver {
	if secretsDir == "" {
		secretsDir = DefaultSecretsDir
	}

	return func(name string) (string, error) {
		if name == "" {
			return "", fmt.Errorf("secret: empty secret name")
		}

		path := filepath.Join(secretsDir, name)
		if data, err := os.ReadFile(path); err == nil {
			return trimSecret(string(data)), nil
		} else if !os.IsNotExist(err) {
			return "", fmt.Errorf("secret: read %s: %w", path, err)
		}

		envName := envVarName(name)
		if v, ok := os.LookupEnv(envName); ok {
			return trimSecret(v), nil
		}

		return "", fmt.Errorf("secret: %q not found in %s or %s", name, path, envName)
	}
}

// CheckOIDCLength validates a resolved OIDC client secret's length against
// MinOIDCSecretLength. It names the secret by NAME, never by value, so the
// error is safe to log and alert on. Length is counted in characters (runes),
// matching the grammar's "minimum 32 characters" (Fork 7).
func CheckOIDCLength(name, value string) error {
	if n := utf8.RuneCountInString(value); n < MinOIDCSecretLength {
		return fmt.Errorf("secret: %q is too short for an OIDC client secret: %d characters, minimum %d", name, n, MinOIDCSecretLength)
	}
	return nil
}

// trimSecret strips leading and trailing whitespace (spaces, tabs, CR, LF) from
// a resolved secret value. It is applied uniformly to every source a Resolver
// can pull from, so the resolved value never depends on which source supplied
// it.
func trimSecret(v string) string {
	return strings.Trim(v, "\r\n \t")
}

// envVarName maps a secret name to the ABOARD_SECRET_<NAME> env var aboard
// falls back to when no secrets-directory file exists for it.
func envVarName(name string) string {
	upper := strings.ToUpper(strings.ReplaceAll(name, "-", "_"))
	return "ABOARD_SECRET_" + upper
}
