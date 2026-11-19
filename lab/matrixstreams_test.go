//go:build lab

package lab_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/KucherenkoIvan/thinkpol-vpn/lab"
)

// matrixShare is one stream's cells of the censor matrix, as the stream
// writes them for make lab-test to assemble RESULTS.md from.
type matrixShare struct {
	Stream   string
	Commit   string // lab.CommitEnv: what the run tested
	Expected int    // how many cells are the stream's (streamCells)
	Failed   bool   // the matrix test failed in the stream
	Cells    []shareCell
}

type shareCell struct{ Transport, Censor, Result, Detail string }

func shareFile(dir, stream string) string {
	return filepath.Join(dir, "censor-matrix-"+stream+".json")
}

// matrixShareOf is the stream's own share of cells: in the long stream, a
// held row's off cell is the default stream's, run again only as its held
// cell's gate.
func matrixShareOf(stream, commit string, failed bool, cells []matrixCell) matrixShare {
	share := matrixShare{Stream: stream, Commit: commit, Expected: streamCells(stream), Failed: failed}
	for _, c := range cells {
		if stream == lab.StreamLong && c.censor == censorCases[0].name {
			continue
		}
		share.Cells = append(share.Cells, shareCell{c.transport, c.censor, c.result, c.detail})
	}
	return share
}

// writeMatrixShare writes the stream's share of cells to
// lab.ResultsDirEnv's directory. Without the directory nothing assembles
// them, and RESULTS.md isn't written.
func writeMatrixShare(t *testing.T, stream string, cells []matrixCell) {
	t.Helper()
	dir := os.Getenv(lab.ResultsDirEnv)
	if dir == "" {
		t.Logf("the %s stream's share of the matrix, without %s: RESULTS.md not written", stream, lab.ResultsDirEnv)
		return
	}
	b, err := json.Marshal(matrixShareOf(stream, os.Getenv(lab.CommitEnv), t.Failed(), cells))
	if err == nil {
		err = os.WriteFile(shareFile(dir, stream), b, 0o644)
	}
	if err != nil {
		t.Errorf("the %s stream's share of the matrix: %v", stream, err)
	}
}

// readMatrixShares reads the streams' shares in dir: a share missing is
// left out (assembleMatrix says so); one that doesn't decode, names
// another stream than its file's, or another commit than commit is an
// error.
func readMatrixShares(dir, commit string) (map[string]*matrixShare, error) {
	shares := map[string]*matrixShare{}
	for _, s := range []string{lab.StreamDefault, lab.StreamLong} {
		b, err := os.ReadFile(shareFile(dir, s))
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, err
		}
		var share matrixShare
		if err := json.Unmarshal(b, &share); err != nil {
			return nil, fmt.Errorf("the %s stream's share of the matrix: %w", s, err)
		}
		if share.Stream != s {
			return nil, fmt.Errorf("the %s stream's share of the matrix says it is the %q stream's", s, share.Stream)
		}
		if share.Commit != commit {
			return nil, fmt.Errorf("the %s stream's share of the matrix tested commit %q, this run %q", s, share.Commit, commit)
		}
		shares[s] = &share
	}
	return shares, nil
}

// TestAssembleCensorMatrix writes RESULTS.md from both streams' shares of
// the censor matrix in lab.ResultsDirEnv's directory: make lab-test runs it
// once both streams have ended, from the test binary both streams ran. A
// share missing, short of its cells, of another commit, or from a stream
// whose matrix failed is an error, never a partial RESULTS.md. It runs
// only outside a stream, with the directory set.
func TestAssembleCensorMatrix(t *testing.T) {
	stream, err := lab.Stream()
	if err != nil {
		t.Fatal(err)
	}
	dir := os.Getenv(lab.ResultsDirEnv)
	if dir == "" || stream != "" {
		t.Skip("make lab-test runs it, after both streams")
	}
	shares, err := readMatrixShares(dir, os.Getenv(lab.CommitEnv))
	if err != nil {
		t.Fatalf("RESULTS.md not written: %v", err)
	}
	cells, err := assembleMatrix(shares)
	if err != nil {
		t.Fatalf("RESULTS.md not written: %v", err)
	}
	writeResults(t, cells, len(transports)*len(censorCases))
}

// assembleMatrix is the matrix from both streams' shares: every cell once,
// or an error saying which share is missing or wrong.
func assembleMatrix(shares map[string]*matrixShare) ([]matrixCell, error) {
	var errs []error
	var cells []matrixCell
	seen := map[[2]string]bool{}
	for _, stream := range []string{lab.StreamDefault, lab.StreamLong} {
		share := shares[stream]
		switch {
		case share == nil:
			errs = append(errs, fmt.Errorf("the %s stream's share of the matrix is missing", stream))
			continue
		case share.Failed:
			errs = append(errs, fmt.Errorf("the %s stream's matrix failed", stream))
			continue
		case share.Expected != streamCells(stream) || len(share.Cells) != share.Expected:
			errs = append(errs, fmt.Errorf("the %s stream's share has %d of %d cells (expected %d)", stream, len(share.Cells), streamCells(stream), share.Expected))
			continue
		}
		for _, c := range share.Cells {
			key := [2]string{c.Transport, c.Censor}
			if seen[key] {
				errs = append(errs, fmt.Errorf("cell %s / %s is in both streams' shares", c.Transport, c.Censor))
			}
			seen[key] = true
			if c.Result == "error" {
				errs = append(errs, fmt.Errorf("the %s stream's cell %s / %s errored: %s", stream, c.Transport, c.Censor, c.Detail))
			}
			cells = append(cells, matrixCell{c.Transport, c.Censor, c.Result, c.Detail})
		}
	}
	for _, tr := range transports {
		for _, cc := range censorCases {
			if len(errs) == 0 && !seen[[2]string{tr.name, cc.name}] {
				errs = append(errs, fmt.Errorf("cell %s / %s is in neither stream's share", tr.name, cc.name))
			}
		}
	}
	return cells, errors.Join(errs...)
}

// TestAssembleMatrix: shares that cover the matrix assemble into every
// cell once; a share missing, failed, short or stale, a cell in both, and
// an errored cell each keep RESULTS.md from being written.
func TestAssembleMatrix(t *testing.T) {
	whole := func() map[string]*matrixShare {
		shares := map[string]*matrixShare{
			lab.StreamDefault: {Stream: lab.StreamDefault, Expected: streamCells(lab.StreamDefault)},
			lab.StreamLong:    {Stream: lab.StreamLong, Expected: streamCells(lab.StreamLong)},
		}
		for _, tr := range transports {
			for i, cc := range censorCases {
				s := lab.StreamDefault
				if i > 0 && heldCell(tr, cc) {
					s = lab.StreamLong
				}
				shares[s].Cells = append(shares[s].Cells, shareCell{tr.name, cc.name, "pass", ""})
			}
		}
		return shares
	}
	cells, err := assembleMatrix(whole())
	if err != nil || len(cells) != len(transports)*len(censorCases) {
		t.Fatalf("both shares: %d cells, %v; want %d", len(cells), err, len(transports)*len(censorCases))
	}
	if streamCells(lab.StreamLong) == 0 || streamCells(lab.StreamDefault)+streamCells(lab.StreamLong) != len(cells) {
		t.Fatalf("the streams' cells: default %d, long %d, of %d", streamCells(lab.StreamDefault), streamCells(lab.StreamLong), len(cells))
	}
	for _, tc := range []struct {
		name  string
		spoil func(map[string]*matrixShare)
		want  string
	}{
		{"long share missing", func(s map[string]*matrixShare) { delete(s, lab.StreamLong) }, "the long stream's share of the matrix is missing"},
		{"default share missing", func(s map[string]*matrixShare) { delete(s, lab.StreamDefault) }, "the default stream's share of the matrix is missing"},
		{"long matrix failed", func(s map[string]*matrixShare) { s[lab.StreamLong].Failed = true }, "the long stream's matrix failed"},
		{"a cell short", func(s map[string]*matrixShare) {
			s[lab.StreamLong].Cells = s[lab.StreamLong].Cells[1:]
		}, "the long stream's share has"},
		{"stale count", func(s map[string]*matrixShare) {
			s[lab.StreamLong].Expected++
			s[lab.StreamLong].Cells = append(s[lab.StreamLong].Cells, s[lab.StreamLong].Cells[0])
		}, "the long stream's share has"},
		{"a cell in both", func(s map[string]*matrixShare) {
			d := s[lab.StreamDefault]
			d.Cells[0] = s[lab.StreamLong].Cells[0]
		}, "is in both streams' shares"},
		{"an errored cell", func(s map[string]*matrixShare) { s[lab.StreamLong].Cells[0].Result = "error" }, "errored"},
		{"a cell renamed", func(s map[string]*matrixShare) {
			s[lab.StreamDefault].Cells[0].Transport = "no-such-row"
		}, "is in neither stream's share"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			shares := whole()
			tc.spoil(shares)
			_, err := assembleMatrix(shares)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want an error saying %q", err, tc.want)
			}
		})
	}
}

// TestMatrixShareOf: a stream's share says whether its matrix failed, and
// the long stream's leaves out the off cells it ran only as gates.
func TestMatrixShareOf(t *testing.T) {
	var cells []matrixCell
	for _, tr := range transports {
		for i, cc := range censorCases {
			if (i == 0 && slices.ContainsFunc(censorCases, func(c censorCase) bool { return heldCell(tr, c) })) || (i > 0 && heldCell(tr, cc)) {
				cells = append(cells, matrixCell{tr.name, cc.name, "pass", ""})
			}
		}
	}
	share := matrixShareOf(lab.StreamLong, "c0ffee", true, cells)
	if !share.Failed || share.Commit != "c0ffee" || share.Stream != lab.StreamLong {
		t.Errorf("share %+v: want failed, commit c0ffee, the long stream", share)
	}
	if len(share.Cells) != streamCells(lab.StreamLong) || len(share.Cells) == len(cells) {
		t.Fatalf("the long stream's share has %d of the %d cells it ran, want %d", len(share.Cells), len(cells), streamCells(lab.StreamLong))
	}
	for _, c := range share.Cells {
		if c.Censor == censorCases[0].name {
			t.Errorf("the long stream's share has the off cell of %s", c.Transport)
		}
	}
	if matrixShareOf(lab.StreamDefault, "", false, cells).Failed {
		t.Error("a passing stream's share says failed")
	}
}

// TestReadMatrixShares: shares are read back as written; one under
// another stream's file, or of another commit, is refused.
func TestReadMatrixShares(t *testing.T) {
	write := func(dir, file string, share matrixShare) {
		b, err := json.Marshal(share)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(shareFile(dir, file), b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	dir := t.TempDir()
	write(dir, lab.StreamDefault, matrixShare{Stream: lab.StreamDefault, Commit: "abc", Expected: 1})
	shares, err := readMatrixShares(dir, "abc")
	if err != nil || len(shares) != 1 || shares[lab.StreamDefault].Expected != 1 {
		t.Fatalf("read %v, %v", shares, err)
	}
	if _, err := readMatrixShares(dir, "abc-dirty"); err == nil || !strings.Contains(err.Error(), "tested commit") {
		t.Errorf("another commit: %v", err)
	}
	write(dir, lab.StreamLong, matrixShare{Stream: lab.StreamDefault, Commit: "abc"})
	if _, err := readMatrixShares(dir, "abc"); err == nil || !strings.Contains(err.Error(), "says it is") {
		t.Errorf("a share under another stream's file: %v", err)
	}
}
