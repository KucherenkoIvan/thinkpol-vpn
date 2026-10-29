package lab

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// downProject removes a lab's containers and networks, from the project
// name alone, so it also cleans up after a killed run. It refuses unless the
// name starts with ProjectPrefix and every container and network of the
// project carries LabelLab and, as LabelRoot, exactly root: whatever isn't
// this checkout's lab is never touched, not even another checkout's lab under
// the same name. Volumes are left alone; the lab creates none. A project
// that doesn't exist is fine.
func downProject(ctx context.Context, project, root string) error {
	if !strings.HasPrefix(project, ProjectPrefix) {
		return fmt.Errorf("lab: refusing to tear down %q: not a lab project (no %q prefix)", project, ProjectPrefix)
	}
	var problems []string
	for _, list := range []struct{ cmd, name string }{
		{"ps -a", "{{.Names}}"},
		{"network ls", "{{.Name}}"},
	} {
		args := append(strings.Fields(list.cmd), "--filter", "label=com.docker.compose.project="+project,
			"--format", list.name+"\t"+`{{.Label "`+LabelLab+`"}}`+"\t"+`{{.Label "`+LabelRoot+`"}}`)
		res, err := docker(ctx, args...)
		if err != nil {
			return err
		}
		for _, line := range strings.Split(strings.TrimSpace(res.Stdout), "\n") {
			if line == "" {
				continue
			}
			f := strings.SplitN(line, "\t", 3)
			for len(f) < 3 {
				f = append(f, "")
			}
			switch {
			case f[1] != "1":
				problems = append(problems, f[0]+" is not labelled "+LabelLab+"=1")
			case f[2] != root:
				problems = append(problems, f[0]+" belongs to the checkout at "+f[2])
			}
		}
	}
	if len(problems) > 0 {
		return fmt.Errorf("lab: refusing to tear down %q: %s", project, strings.Join(problems, "; "))
	}
	// An empty project directory and no COMPOSE_* variables: Compose loads
	// nothing but the project name.
	dir, err := os.MkdirTemp("", "tplab-down-")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(dir) }()
	_, err = runEnv(ctx, nil, environWithoutCompose(), "docker", "compose", "--project-directory", dir,
		"-p", project, "down", "--remove-orphans", "--timeout", "0")
	return err
}

// labProjects lists the labs on the daemon, found by LabelLab only, with the
// checkout each was started from.
func labProjects(ctx context.Context) (map[string]string, error) {
	projects := map[string]string{}
	for _, kind := range [][]string{{"ps", "-a"}, {"network", "ls"}} {
		args := append(kind, "--filter", "label="+LabelLab+"=1",
			"--format", `{{.Label "com.docker.compose.project"}}`+"\t"+`{{.Label "`+LabelRoot+`"}}`)
		res, err := docker(ctx, args...)
		if err != nil {
			return nil, err
		}
		for _, line := range strings.Split(strings.TrimSpace(res.Stdout), "\n") {
			project, root, _ := strings.Cut(line, "\t")
			if strings.HasPrefix(project, ProjectPrefix) {
				projects[project] = root
			}
		}
	}
	return projects, nil
}

// DownCheckout removes every lab started from the checkout at root (by its
// LabelRoot, exactly), or with onlyTests just the labs tests and labctl
// gotest started. Then it sweeps the checkout's run directories: an ended
// run's goes, a kept lab's only once no lab its .kept lists is on the
// daemon (all stay if Docker can't list them). It returns the projects it
// removed.
func DownCheckout(ctx context.Context, root string, onlyTests bool) ([]string, error) {
	checkout, err := CheckoutProject(root)
	if err != nil {
		return nil, err
	}
	removed, err := downWhere(ctx, func(project, labRoot string) bool {
		if labRoot != root {
			return false
		}
		return !onlyTests || startedByTests(project, checkout)
	})
	return removed, errors.Join(err, removeStaleBinaries(ctx, root, labProjects))
}

// DownStale removes the labs, from any checkout, whose checkout no longer
// exists: a deleted worktree's leftovers.
func DownStale(ctx context.Context) ([]string, error) {
	return downWhere(ctx, func(_, root string) bool {
		if root == "" {
			return false
		}
		_, err := os.Stat(filepath.Join(root, "go.mod"))
		return os.IsNotExist(err)
	})
}

func downWhere(ctx context.Context, match func(project, root string) bool) ([]string, error) {
	projects, err := labProjects(ctx)
	if err != nil {
		return nil, err
	}
	var removed []string
	for project, root := range projects {
		if !match(project, root) {
			continue
		}
		if err := downProject(ctx, project, root); err != nil {
			return removed, err
		}
		if root != "" {
			_ = os.RemoveAll(filepath.Join(root, "lab", ".run", project))
		}
		removed = append(removed, project)
	}
	sort.Strings(removed)
	return removed, nil
}
