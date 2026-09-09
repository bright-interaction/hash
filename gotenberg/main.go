// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package main

import (
	gotenbergcmd "github.com/gotenberg/gotenberg/v8/cmd"
	_ "github.com/gotenberg/gotenberg/v8/pkg/modules/api"
	_ "github.com/gotenberg/gotenberg/v8/pkg/modules/chromium"
)

func main() {
	gotenbergcmd.Run()
}
