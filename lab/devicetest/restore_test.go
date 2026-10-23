//go:build darwin || linux

package main

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

// What `devicetest restore` tells the owner: CLEAN, nothing pending,
// RESET-BY-REBOOT and FORGOTTEN let the next run start, each said for
// what it is; a verdict that keeps the run pending is an error.
func TestTheRestoreSaysWhetherTheNextRunMayStart(t *testing.T) {
	for _, tc := range []struct {
		name, out, says string
		ok              bool
	}{
		{"clean", `{"id":0,"ok":true,"result":{"verdict":"CLEAN","by":"x","run":"r1"}}`, "CLEAN, run r1 restored", true},
		{"nothing pending", `{"id":0,"ok":true,"result":{"verdict":"NOTHING-TO-RESTORE","by":"x"}}`, "nothing was compared", true},
		{"reset by a reboot", `{"id":0,"ok":true,"result":{"verdict":"RESET-BY-REBOOT","by":"x","run":"r1"}}`, "RESET-BY-REBOOT, run r1 closed", true},
		{"forgotten", `{"id":0,"ok":true,"result":{"verdict":"FORGOTTEN","by":"x","run":"r1"}}`, "FORGOTTEN, run r1 closed at your request; nothing was proven", true},
		{"left", `{"id":0,"ok":true,"result":{"verdict":"LEFT","by":"x","run":"r1"}}`, "THE MAC ISN'T AS IT WAS (LEFT)", false},
		{"left, its ways out", `{"id":0,"ok":true,"result":{"verdict":"LEFT","by":"x","run":"r1"}}`, "RESET-BY-REBOOT when run after a reboot; if it still says LEFT or REBOOT after a reboot, devicetest restore -forget r1 closes it", false},
		{"reboot", `{"id":0,"ok":true,"result":{"verdict":"REBOOT","by":"x","run":"r1"}}`, "THE MAC ISN'T AS IT WAS (REBOOT)", false},
		{"an error", `{"id":0,"ok":false,"err":"left: is a directory","result":{"verdict":"","by":""}}`, "failed: left: is a directory", false},
		{"a failed restore of a run", `{"id":0,"ok":false,"err":"journal: line 3: cut","result":{"verdict":"","by":"x","run":"r1"}}`,
			"run r1 stays pending; if a restore after a reboot fails like this again, devicetest restore -forget r1 closes it (FORGOTTEN, never CLEAN)", false},
		{"no answer", ``, "", false},
	} {
		var w bytes.Buffer
		err := reportRestore(&w, []byte(tc.out), nil)
		if (err == nil) != tc.ok || !strings.Contains(w.String(), tc.says) {
			t.Errorf("%s: %v\n%s", tc.name, err, w.String())
		}
		if strings.Contains(w.String(), `"verdict": ""`) {
			t.Errorf("%s: a result with no verdict printed:\n%s", tc.name, w.String())
		}
		if tc.out != "" && !tc.ok && !errors.Is(err, errReported) {
			t.Errorf("%s: printed, yet main would print %v again", tc.name, err)
		}
	}
	var w bytes.Buffer
	_ = reportRestore(&w, []byte(`{"id":0,"ok":true,"result":{"verdict":"CLEAN","by":"x"}}`), nil)
	if !strings.Contains(w.String(), `"verdict": "CLEAN"`) {
		t.Errorf("the result isn't printed as the checklist reads it:\n%s", w.String())
	}
}
