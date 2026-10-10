package lab

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// downProject removes a lab's containers and networks, from the project
// name alone, so it also cleans up after a killed run. It refuses unless the
// name starts with ProjectPrefix and every container and network of the
// project carries LabelLab: whatever isn't the lab's is never touched.
// Volumes are left alone; the lab creates none.
func downProject(ctx context.Context, project string) error {
	if !strings.HasPrefix(project, ProjectPrefix) {
		return fmt.Errorf("lab: refusing to tear down %q: not a lab project (no %q prefix)", project, ProjectPrefix)
	}
	var foreign []string
	for _, list := range []struct{ cmd, name string }{
		{"ps -a", "{{.Names}}"},
		{"network ls", "{{.Name}}"},
	} {
		args := append(strings.Fields(list.cmd), "--filter", "label=com.docker.compose.project="+project,
			"--format", list.name+` {{.Label "`+LabelLab+`"}}`)
		res, err := docker(ctx, args...)
		if err != nil {
			return err
		}
		for _, line := range strings.Split(strings.TrimSpace(res.Stdout), "\n") {
			name, marker, _ := strings.Cut(line, " ")
			if name != "" && marker != "1" {
				foreign = append(foreign, name)
			}
		}
	}
	if len(foreign) > 0 {
		return fmt.Errorf("lab: refusing to tear down %q: %s not labelled %s=1", project, strings.Join(foreign, ", "), LabelLab)
	}
	_, err := docker(ctx, "compose", "-p", project, "down", "--remove-orphans", "--timeout", "0")
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

// DownCheckout removes every lab started from the checkout at root, or with
// onlyTests just the labs tests and labctl gotest started. It returns the
// projects it removed.
func DownCheckout(ctx context.Context, root string, onlyTests bool) ([]string, error) {
	checkout, err := CheckoutProject(root)
	if err != nil {
		return nil, err
	}
	return downWhere(ctx, func(project, _ string) bool {
		if !belongsTo(project, checkout) {
			return false
		}
		return !onlyTests || startedByTests(project, checkout)
	})
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
		if err := downProject(ctx, project); err != nil {
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
