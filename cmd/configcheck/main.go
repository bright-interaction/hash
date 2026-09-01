// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

// Command configcheck validates the complete Hash environment without opening
// a listener, connecting to a dependency, or applying database migrations. The
// production release workflow runs this binary from the exact candidate image
// before it quiesces writers or permits any lifecycle mutation.
package main

import (
	"fmt"
	"os"

	"github.com/bright-interaction/hash/internal/config"
)

func main() {
	if _, err := config.Load(); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "hash-config-check:", err)
		os.Exit(1)
	}
}
