// Package scripts holds the testbed scripts; its tests run them with bash
// against stand-ins for kubectl and go.
package scripts

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

// answers the one request the scripts make before they check the number of
// relays, the list of relay deployments, and records every call
const kubectlStandIn = `#!/usr/bin/env bash
echo "$*" >>"$KUBECTL_CALLS"
case "$*" in
  *"get deployment -l app=relay"*)
    for i in $(seq 1 "$RELAY_COUNT"); do echo "relay-$i"; done ;;
esac
`

// enroll.sh builds cmd/jimichi before it looks at the relays
const goStandIn = `#!/usr/bin/env bash
exit 0
`

func bash(t *testing.T) string {
	t.Helper()
	path, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("no bash to run the scripts with")
	}
	// on a Windows host the bash of WSL shares neither the paths nor the
	// environment of this process
	if runtime.GOOS == "windows" {
		kernel, err := exec.Command(path, "-c", "uname -s").Output()
		if err != nil || !strings.HasPrefix(string(kernel), "MINGW") && !strings.HasPrefix(string(kernel), "MSYS") {
			t.Skip("the bash found is not Git Bash")
		}
	}
	return path
}

func script(t *testing.T, name string) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	return filepath.ToSlash(filepath.Join(dir, name))
}

// runs bash in an empty directory with the stand-ins first in PATH and the
// testbed holding the given number of relays
func run(t *testing.T, relays int, args ...string) (status int, stderr, calls string) {
	t.Helper()
	shell := bash(t)
	bin, work := t.TempDir(), t.TempDir()
	for name, text := range map[string]string{"kubectl": kubectlStandIn, "go": goStandIn} {
		if err := os.WriteFile(filepath.Join(bin, name), []byte(text), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	log := filepath.Join(bin, "calls")
	cmd := exec.Command(shell, args...)
	cmd.Dir = work
	cmd.Env = append(os.Environ(),
		"PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"),
		"KUBECTL_CALLS="+filepath.ToSlash(log),
		"RELAY_COUNT="+strconv.Itoa(relays),
	)
	var errOut bytes.Buffer
	cmd.Stderr = &errOut
	err := cmd.Run()
	var exit *exec.ExitError
	if err != nil && !errors.As(err, &exit) {
		t.Fatal(err)
	}
	recorded, err := os.ReadFile(log)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	return cmd.ProcessState.ExitCode(), errOut.String(), string(recorded)
}

// relay 100 would be forwarded to the base + 100, the first port of the next
// base: 19100 + 100 for the counters, 19200 + 100 for enrollment. Both scripts
// refuse after listing the relays and before they forward anything
func TestScriptsRefuseMoreRelaysThanTheirPortsHold(t *testing.T) {
	for _, name := range []string{"stats.sh", "enroll.sh"} {
		status, stderr, calls := run(t, 100, script(t, name))
		if status != 1 || !strings.Contains(stderr, "more than 99 relays") {
			t.Errorf("%s with 100 relays: status %d, stderr %q; want 1 and the refusal", name, status, stderr)
		}
		if !strings.Contains(calls, "get deployment -l app=relay") || strings.Count(calls, "\n") != 1 {
			t.Errorf("%s with 100 relays asked the cluster for more than the list of relays:\n%s", name, calls)
		}
	}
}

func TestPortsFitUpToNinetyNineRelays(t *testing.T) {
	check := `. "$1"; ports_fit "$(relays)"`
	for _, c := range []struct{ relays, status int }{{1, 0}, {99, 0}, {100, 1}, {250, 1}} {
		status, stderr, _ := run(t, c.relays, "-c", check, "bash", script(t, "lib.sh"))
		if status != c.status || (c.status != 0) != strings.Contains(stderr, "more than 99 relays") {
			t.Errorf("%d relays: status %d, stderr %q; want status %d", c.relays, status, stderr, c.status)
		}
	}
}
