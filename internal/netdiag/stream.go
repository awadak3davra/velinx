package netdiag

import (
	"bufio"
	"context"
	"io"
	"os/exec"
	"regexp"
	"runtime"
	"strconv"
)

// streamCmd runs name+args and calls emit once per output line as the process
// produces it (merged stdout+stderr, line-buffered), so a slow tool like
// traceroute surfaces each hop live instead of dumping everything on completion.
// It returns when the process exits or ctx is cancelled. emit must be safe to
// call from this goroutine only (it is called serially).
func streamCmd(ctx context.Context, emit func(string), name string, args ...string) {
	cmd := exec.CommandContext(ctx, name, args...)
	pr, pw := io.Pipe()
	// Same writer for both streams: os/exec serializes the writes, so hop/reply
	// lines never interleave mid-line.
	cmd.Stdout = pw
	cmd.Stderr = pw
	if err := cmd.Start(); err != nil {
		emit(name + " unavailable: " + err.Error())
		_ = pw.Close()
		return
	}
	go func() { _ = cmd.Wait(); _ = pw.Close() }()
	sc := bufio.NewScanner(pr)
	sc.Buffer(make([]byte, 0, 4096), 64*1024)
	for sc.Scan() {
		emit(sc.Text())
	}
}

// validIfaceRe guards the interface name passed to `ping -I` / `traceroute -i`
// (same argument-injection concern as ValidTarget). Real iface names (awg0, eth0,
// br-lan, tun-keen) fit; max 15 chars (IFNAMSIZ-1).
var validIfaceRe = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,14}$`)

// ValidIface reports whether s is a safe interface name to bind a probe to.
func ValidIface(s string) bool { return s != "" && validIfaceRe.MatchString(s) }

// StreamPing emits each ping reply line as it arrives (count echo requests). When
// iface is a valid interface name, the probe is bound to it (`ping -I <iface>`),
// so ICMP can be sent through a specific tunnel/link instead of only the WAN.
func StreamPing(ctx context.Context, emit func(string), host, iface string, count int) {
	if !ValidTarget(host) {
		emit("invalid target")
		return
	}
	if count < 1 || count > 20 {
		count = 5
	}
	if runtime.GOOS == "windows" {
		streamCmd(ctx, emit, "ping", "-n", strconv.Itoa(count), "-w", "1500", host)
		return
	}
	args := []string{"-c", strconv.Itoa(count), "-W", "2"}
	if ValidIface(iface) {
		args = append(args, "-I", iface)
	}
	streamCmd(ctx, emit, "ping", append(args, host)...)
}

// StreamTraceroute emits each hop line as it completes (up to maxHops). When iface
// is valid the trace is bound to it (`traceroute -i <iface>`).
func StreamTraceroute(ctx context.Context, emit func(string), host, iface string, maxHops int) {
	if !ValidTarget(host) {
		emit("invalid target")
		return
	}
	if maxHops < 1 || maxHops > 30 {
		maxHops = 20
	}
	if runtime.GOOS == "windows" {
		streamCmd(ctx, emit, "tracert", "-d", "-h", strconv.Itoa(maxHops), "-w", "1000", host)
		return
	}
	args := []string{"-n", "-m", strconv.Itoa(maxHops), "-w", "2"}
	if ValidIface(iface) {
		args = append(args, "-i", iface)
	}
	streamCmd(ctx, emit, "traceroute", append(args, host)...)
}
