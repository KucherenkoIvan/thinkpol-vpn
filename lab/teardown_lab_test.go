//go:build lab

package lab

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Tear-down never touches what isn't the lab's: a project with the lab's
// prefix but without its label, and a lab that someone else's container
// joined, are both refused, and both survive.
func TestDownRefusesUnlabelledResources(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	root, err := Root()
	if err != nil {
		t.Fatal(err)
	}
	checkout, err := CheckoutProject(root)
	if err != nil {
		t.Fatal(err)
	}
	img, err := prepare(ctx, root)
	if err != nil {
		t.Fatal(err)
	}

	// A throwaway project of our own that only looks like a lab.
	foreign := testProject(checkout, "foreign", t.Name())
	file := filepath.Join(t.TempDir(), "compose.json")
	compose, _ := json.Marshal(map[string]any{
		"name": foreign,
		"services": map[string]any{"x": map[string]any{
			"image": img.ref, "platform": img.platform, "init": true, "command": []string{"sleep", "infinity"},
		}},
	})
	if err := os.WriteFile(file, compose, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := docker(ctx, "compose", "-f", file, "-p", foreign, "up", "-d", "--wait"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = docker(context.Background(), "compose", "-f", file, "-p", foreign, "down", "--timeout", "0")
	})

	if err := downProject(ctx, foreign); err == nil || !strings.Contains(err.Error(), "refusing") {
		t.Errorf("down of an unlabelled project: %v", err)
	}
	// Listing finds labs by label, so the look-alike isn't even a candidate.
	if removed, err := downWhere(ctx, func(p, _ string) bool { return p == foreign }); err != nil || len(removed) > 0 {
		t.Errorf("down by label removed %v: %v", removed, err)
	}
	if res, err := docker(ctx, "compose", "-p", foreign, "ps", "-q"); err != nil || strings.TrimSpace(res.Stdout) == "" {
		t.Fatalf("the unlabelled project is gone: %v", err)
	}

	// A real lab, joined by a container without the label.
	l := Start(t, GoTestTopology())
	res, err := docker(ctx, "run", "-d", "--rm", "--label", "com.docker.compose.project="+l.Project,
		"--network", "none", "--platform", img.platform, img.ref, "sleep", "infinity")
	if err != nil {
		t.Fatal(err)
	}
	intruder := strings.TrimSpace(res.Stdout)
	t.Cleanup(func() { _, _ = docker(context.Background(), "rm", "-f", intruder) })
	if err := l.Down(ctx); err == nil || !strings.Contains(err.Error(), "refusing") {
		t.Errorf("down of a lab with a foreign container: %v", err)
	}
	if _, err := docker(ctx, "inspect", intruder); err != nil {
		t.Errorf("the foreign container is gone: %v", err)
	}
	if _, err := docker(ctx, "rm", "-f", intruder); err != nil {
		t.Fatal(err)
	}
	// with the intruder gone the lab's own cleanup goes through
}
