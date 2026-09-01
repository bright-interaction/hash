// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package db

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"sort"
	"strings"
	"testing"
)

func TestDollarQuotedMigrationStatementsAreGooseDelimited(t *testing.T) {
	entries, err := os.ReadDir("migrations")
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".sql") {
			continue
		}
		file, err := os.Open("migrations/" + entry.Name())
		if err != nil {
			t.Fatal(err)
		}
		insideStatement := false
		lineNumber := 0
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			lineNumber++
			line := scanner.Text()
			switch {
			case strings.Contains(line, "+goose StatementBegin"):
				if insideStatement {
					t.Errorf("%s:%d nests StatementBegin", entry.Name(), lineNumber)
				}
				insideStatement = true
			case strings.Contains(line, "+goose StatementEnd"):
				if !insideStatement {
					t.Errorf("%s:%d has StatementEnd without StatementBegin", entry.Name(), lineNumber)
				}
				insideStatement = false
			case strings.Contains(line, "$$") && !insideStatement:
				t.Errorf("%s:%d contains a dollar-quoted SQL body outside Goose StatementBegin/StatementEnd", entry.Name(), lineNumber)
			}
		}
		if err := scanner.Err(); err != nil {
			t.Errorf("scan %s: %v", entry.Name(), err)
		}
		if err := file.Close(); err != nil {
			t.Errorf("close %s: %v", entry.Name(), err)
		}
		if insideStatement {
			t.Errorf("%s ends inside StatementBegin", entry.Name())
		}
	}
}

func TestEmbeddedMigrationsIdentityMatchesReleaseTreeEncoding(t *testing.T) {
	digest, versions, err := EmbeddedMigrationsIdentity()
	if err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir("migrations")
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".sql") {
			names = append(names, entry.Name())
		}
	}
	sort.Strings(names)
	h := sha256.New()
	for _, name := range names {
		raw, err := os.ReadFile("migrations/" + name)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = h.Write([]byte(name))
		_, _ = h.Write([]byte{0})
		_, _ = h.Write(raw)
		_, _ = h.Write([]byte{0})
	}
	if want := hex.EncodeToString(h.Sum(nil)); digest != want {
		t.Fatalf("embedded migration digest %s does not match release-tree digest %s", digest, want)
	}
	if len(versions) != len(names) {
		t.Fatalf("got %d embedded versions for %d migration files", len(versions), len(names))
	}
	for i := 1; i < len(versions); i++ {
		if versions[i] <= versions[i-1] {
			t.Fatalf("migration versions are not strictly increasing: %v", versions)
		}
	}
}
