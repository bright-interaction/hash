// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package main

import (
	"bytes"
	"context"
	"log/slog"
	"os"
	"reflect"
	"strings"
	"testing"
)

func TestSuperviseWorkerTerminatesOnUnexpectedReturn(t *testing.T) {
	calls := 0
	code := 0
	var sequence []string
	superviseWorker(context.Background(), "returns", func() {}, func(loop string, panicked bool) {
		if loop != "returns" || panicked {
			t.Fatalf("fatal report = %q/%v, want returns/false", loop, panicked)
		}
		sequence = append(sequence, "report")
	}, func(got int) {
		calls++
		code = got
		sequence = append(sequence, "terminate")
	})
	if calls != 1 || code != 1 {
		t.Fatalf("terminator calls/code = %d/%d, want 1/1", calls, code)
	}
	if !reflect.DeepEqual(sequence, []string{"report", "terminate"}) {
		t.Fatalf("fatal sequence = %v, want synchronous report before terminate", sequence)
	}
}

func TestWorkerUsesConfiguredOperatorForQueuedCeremonyMail(t *testing.T) {
	raw, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	src := string(raw)
	if got := strings.Count(src, "cfg.OperatorName"); got < 3 {
		t.Fatalf("worker operator identity wiring count = %d, want sign/send/reminder mail paths", got)
	}
	if strings.Contains(src, `OrgName: "Bright Interaction"`) || strings.Contains(src, `orgName:           "Bright Interaction"`) {
		t.Fatal("worker retains vendor-specific sender identity in a self-host path")
	}
}

func TestWorkerObservabilityUsesDistinctFailSafeIdentityBeforeDependencies(t *testing.T) {
	t.Setenv("FLARE_DSN", "")
	if initWorkerObservability("release", "production") {
		t.Fatal("worker observability should be a no-op when no DSN is configured")
	}
	raw, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	src := string(raw)
	if !strings.Contains(src, `flarereport.InitFlare("hash-worker", release, environment)`) {
		t.Fatal("worker observability is not isolated under the hash-worker service identity")
	}
	logging := strings.Index(src, "slog.SetDefault")
	observability := strings.Index(src, "initWorkerObservability(cfg.Release, cfg.Environment)")
	dependency := strings.Index(src, "pgxpool.New(ctx, cfg.DBURL)")
	if logging < 0 || observability <= logging || dependency <= observability {
		t.Fatal("worker observability must initialize after structured logging and before runtime dependencies")
	}
}

func TestSuperviseWorkerTerminatesOnPanic(t *testing.T) {
	var logs bytes.Buffer
	previousLogger := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&logs, nil)))
	t.Cleanup(func() { slog.SetDefault(previousLogger) })

	calls := 0
	code := 0
	var sequence []string
	superviseWorker(context.Background(), "panics", func() { panic("do-not-export-panic-payload") }, func(loop string, panicked bool) {
		if loop != "panics" || !panicked {
			t.Fatalf("fatal report = %q/%v, want panics/true", loop, panicked)
		}
		sequence = append(sequence, "report")
	}, func(got int) {
		calls++
		code = got
		sequence = append(sequence, "terminate")
	})
	if calls != 1 || code != 1 {
		t.Fatalf("terminator calls/code = %d/%d, want 1/1", calls, code)
	}
	if !reflect.DeepEqual(sequence, []string{"report", "terminate"}) {
		t.Fatalf("fatal sequence = %v, want synchronous report before terminate", sequence)
	}
	if strings.Contains(logs.String(), "do-not-export-panic-payload") {
		t.Fatalf("recovered panic payload crossed the slog/Flare boundary: %s", logs.String())
	}
}

func TestOptionalWorkerConfigurationGatesLaunch(t *testing.T) {
	launched := false
	if optionalWorkerConfigured("disabled", false) {
		launched = true
	}
	if launched {
		t.Fatal("disabled optional loop was launched")
	}
	if !optionalWorkerConfigured("enabled", true) {
		t.Fatal("configured optional loop was not enabled")
	}
}

func TestSuperviseWorkerAllowsContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	terminations := 0
	superviseWorker(ctx, "canceled", cancel, func(string, bool) {
		t.Fatal("normal context cancellation emitted a fatal report")
	}, func(int) {
		terminations++
	})
	if terminations != 0 {
		t.Fatalf("terminations = %d, want 0", terminations)
	}
}
