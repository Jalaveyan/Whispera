package commands

import (
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/nekoskin/whispera/core/apiserver"
	"github.com/nekoskin/whispera/core/config"
)

func listeningInodes(port int) map[string]bool {
	inodes := make(map[string]bool)
	for _, path := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(data), "\n")[1:] {
			f := strings.Fields(line)
			if len(f) < 10 || f[3] != "0A" {
				continue
			}
			local := strings.Split(f[1], ":")
			if len(local) != 2 {
				continue
			}
			p, err := strconv.ParseInt(local[1], 16, 32)
			if err != nil || int(p) != port {
				continue
			}
			inodes[f[9]] = true
		}
	}
	return inodes
}

func portOwner(port int) (pid int, exe string, found bool) {
	inodes := listeningInodes(port)
	if len(inodes) == 0 {
		return 0, "", false
	}

	procs, err := filepath.Glob("/proc/[0-9]*")
	if err != nil {
		return 0, "", false
	}
	for _, proc := range procs {
		fds, err := filepath.Glob(proc + "/fd/*")
		if err != nil {
			continue
		}
		for _, fd := range fds {
			link, err := os.Readlink(fd)
			if err != nil || !strings.HasPrefix(link, "socket:[") {
				continue
			}
			if !inodes[strings.TrimSuffix(strings.TrimPrefix(link, "socket:["), "]")] {
				continue
			}
			p, _ := strconv.Atoi(filepath.Base(proc))
			target, _ := os.Readlink(proc + "/exe")
			return p, target, true
		}
	}
	return 0, "", true
}

func warnListenPortConflict(sc *config.ServerConfig) {
	_, portStr, err := net.SplitHostPort(sc.Whispera.ListenAddr)
	if err != nil {
		return
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return
	}

	pid, exe, listening := portOwner(port)
	if !listening {
		return
	}
	if self, err := os.Executable(); err == nil && exe == self {
		return
	}
	if exe == "" {
		return
	}

	fmt.Fprintf(os.Stderr, "\nWarning: port %d (whispera.listen_addr) is held by %s (pid %d), not by whispera.\n", port, exe, pid)
	fmt.Fprintln(os.Stderr, "The main listener cannot bind it, so every key that points at this port will fail to connect.")
	fmt.Fprintf(os.Stderr, "Move the main listener to a free port — this rewrites the config, reseals the checksum and restarts the service:\n")
	fmt.Fprintf(os.Stderr, "    whispera set-multilistener-port %d\n\n", suggestFreePort(port))
}

func suggestFreePort(taken int) int {
	for _, p := range []int{8443, 9443, 2053, 2083, 2087, 2096} {
		if p == taken {
			continue
		}
		if _, _, listening := portOwner(p); !listening {
			return p
		}
	}
	return 8443
}

func keysPointingAt(port int) []string {
	var names []string
	for _, u := range apiserver.CLIListUsers() {
		if u.ConnectionURI == "" {
			continue
		}
		ck, err := config.ParseConnectionKey(u.ConnectionURI)
		if err != nil || ck.WhisperaAddr == "" {
			continue
		}
		if _, p, err := net.SplitHostPort(ck.WhisperaAddr); err == nil && p == strconv.Itoa(port) {
			names = append(names, u.Username)
		}
	}
	return names
}

func restartWhispera() error {
	if _, err := exec.LookPath("systemctl"); err != nil {
		return fmt.Errorf("systemctl not found — restart whispera by hand")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := exec.CommandContext(ctx, "systemctl", "reset-failed", "whispera").Run(); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: systemctl reset-failed whispera: %v\n", err)
	}
	out, err := exec.CommandContext(ctx, "systemctl", "restart", "whispera").CombinedOutput()
	if err != nil {
		return fmt.Errorf("systemctl restart whispera: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func multilistenerUsage() {
	fmt.Fprintln(os.Stderr, "whispera set-multilistener-port <port>        change the main listener port")
	fmt.Fprintln(os.Stderr, "                              -add <port>     add an extra listener port")
	fmt.Fprintln(os.Stderr, "                              -remove <port>  drop an extra listener port")
	fmt.Fprintln(os.Stderr, "                              -list           show every port in use")
	fmt.Fprintln(os.Stderr, "  [-config <path>] [-no-restart]")
}

func portLabel(port int) string {
	keys := keysPointingAt(port)
	if len(keys) == 0 {
		return "no keys"
	}
	if len(keys) <= 4 {
		return fmt.Sprintf("%d key(s): %s", len(keys), strings.Join(keys, ", "))
	}
	return fmt.Sprintf("%d key(s): %s, …", len(keys), strings.Join(keys[:4], ", "))
}

func listMultilistenerPorts(sc *config.ServerConfig) {
	_, mainPort, err := net.SplitHostPort(sc.Whispera.ListenAddr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: whispera.listen_addr %q is not host:port\n", sc.Whispera.ListenAddr)
		os.Exit(1)
	}
	p, _ := strconv.Atoi(mainPort)

	fmt.Printf("main      tcp %-6s %s\n", mainPort, portLabel(p))
	for _, extra := range sc.Whispera.ExtraPorts {
		fmt.Printf("extra     tcp %-6d %s\n", extra, portLabel(extra))
	}
	if sc.Whispera.QUICListenAddr != "" {
		_, quicPort, err := net.SplitHostPort(sc.Whispera.QUICListenAddr)
		if err == nil {
			fmt.Printf("quic      udp %-6s\n", quicPort)
		}
	}
	for _, extra := range sc.Whispera.QUICExtraPorts {
		fmt.Printf("quic-extra udp %-5d\n", extra)
	}
	os.Exit(0)
}

func applyMultilistenerChange(cfgProvider *config.Provider, cfgPath string, mutate func(*config.ServerConfig), noRestart bool) {
	if err := cfgProvider.Update(mutate); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to update %s: %v\n", cfgPath, err)
		os.Exit(1)
	}
	if err := cfgProvider.UpdateChecksum(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: could not reseal the config checksum: %v\n", err)
		fmt.Fprintf(os.Stderr, "Run 'whispera update-checksum %s' before restarting, or the integrity check will refuse to start.\n", cfgPath)
		os.Exit(1)
	}
	fmt.Println("Config checksum resealed")

	if noRestart {
		fmt.Println("Not restarting (-no-restart). Apply with: systemctl restart whispera")
		os.Exit(0)
	}
	if err := restartWhispera(); err != nil {
		fmt.Fprintf(os.Stderr, "Config is written and sealed, but the service was not restarted: %v\n", err)
		fmt.Fprintln(os.Stderr, "Apply it with: systemctl restart whispera")
		os.Exit(0)
	}
	fmt.Println("whispera restarted")
	os.Exit(0)
}

func requireFreePort(port int) {
	pid, exe, listening := portOwner(port)
	if !listening {
		return
	}
	if self, err := os.Executable(); err == nil && exe == self {
		return
	}
	if exe == "" {
		return
	}
	fmt.Fprintf(os.Stderr, "Error: port %d is already held by %s (pid %d) — pick another one\n", port, exe, pid)
	os.Exit(1)
}

func setMainListenerPort(cfgProvider *config.Provider, sc *config.ServerConfig, cfgPath string, port int, noRestart bool) {
	host, oldPortStr, err := net.SplitHostPort(sc.Whispera.ListenAddr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: whispera.listen_addr %q is not host:port: %v\n", sc.Whispera.ListenAddr, err)
		os.Exit(1)
	}
	if oldPortStr == strconv.Itoa(port) {
		fmt.Printf("whispera.listen_addr already uses port %d — nothing to do\n", port)
		os.Exit(0)
	}
	requireFreePort(port)

	oldPort, _ := strconv.Atoi(oldPortStr)
	stale := keysPointingAt(oldPort)
	newAddr := net.JoinHostPort(host, strconv.Itoa(port))

	fmt.Printf("whispera.listen_addr: %s -> %s\n", net.JoinHostPort(host, oldPortStr), newAddr)
	if len(stale) > 0 {
		fmt.Fprintf(os.Stderr, "Warning: %d key(s) still point at port %d and will stop connecting: %s\n",
			len(stale), oldPort, strings.Join(stale, ", "))
		fmt.Fprintf(os.Stderr, "Reissue them with: whispera create-key -user <name> -port %d -sni <domain>\n", port)
	}
	applyMultilistenerChange(cfgProvider, cfgPath, func(sc *config.ServerConfig) {
		sc.Whispera.ListenAddr = newAddr
	}, noRestart)
}

func addExtraListenerPort(cfgProvider *config.Provider, sc *config.ServerConfig, cfgPath string, port int, noRestart bool) {
	if _, mainPort, err := net.SplitHostPort(sc.Whispera.ListenAddr); err == nil && mainPort == strconv.Itoa(port) {
		fmt.Printf("Port %d is already the main listener — nothing to do\n", port)
		os.Exit(0)
	}
	if slices.Contains(sc.Whispera.ExtraPorts, port) {
		fmt.Printf("Port %d is already an extra listener — nothing to do\n", port)
		os.Exit(0)
	}
	if portInUse(port, sc) {
		fmt.Fprintf(os.Stderr, "Error: port %d is already bound by another listener in this config\n", port)
		os.Exit(1)
	}
	requireFreePort(port)

	fmt.Printf("whispera.extra_ports: + %d\n", port)
	applyMultilistenerChange(cfgProvider, cfgPath, func(sc *config.ServerConfig) {
		sc.Whispera.ExtraPorts = append(sc.Whispera.ExtraPorts, port)
	}, noRestart)
}

func removeExtraListenerPort(cfgProvider *config.Provider, sc *config.ServerConfig, cfgPath string, port int, noRestart bool) {
	if _, mainPort, err := net.SplitHostPort(sc.Whispera.ListenAddr); err == nil && mainPort == strconv.Itoa(port) {
		fmt.Fprintf(os.Stderr, "Error: port %d is the main listener — move it with: whispera set-multilistener-port <other-port>\n", port)
		os.Exit(1)
	}
	if !slices.Contains(sc.Whispera.ExtraPorts, port) {
		fmt.Fprintf(os.Stderr, "Error: port %d is not an extra listener\n", port)
		os.Exit(1)
	}

	stale := keysPointingAt(port)
	fmt.Printf("whispera.extra_ports: - %d\n", port)
	if len(stale) > 0 {
		fmt.Fprintf(os.Stderr, "Warning: %d key(s) point at port %d and will stop connecting: %s\n",
			len(stale), port, strings.Join(stale, ", "))
	}
	applyMultilistenerChange(cfgProvider, cfgPath, func(sc *config.ServerConfig) {
		sc.Whispera.ExtraPorts = slices.DeleteFunc(sc.Whispera.ExtraPorts, func(p int) bool { return p == port })
	}, noRestart)
}

func RunSetMultilistenerPortCmd() {
	fs := flag.NewFlagSet("set-multilistener-port", flag.ExitOnError)
	cfgPath := fs.String("config", config.ConfigFile, "Path to config.yaml")
	noRestart := fs.Bool("no-restart", false, "Write the config but do not restart the service")
	addPort := fs.Int("add", 0, "Add an extra listener port")
	removePort := fs.Int("remove", 0, "Drop an extra listener port")
	showList := fs.Bool("list", false, "Show every listener port and the keys pointing at it")

	args := os.Args[2:]
	portArg := ""
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		portArg, args = args[0], args[1:]
	}
	fs.Parse(args)
	if portArg == "" && fs.NArg() > 0 {
		portArg = fs.Arg(0)
	}

	if portArg == "" && *addPort == 0 && *removePort == 0 && !*showList {
		multilistenerUsage()
		os.Exit(1)
	}

	cfgProvider, err := config.New(*cfgPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	if err := cfgProvider.Load(*cfgPath); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load %s: %v\n", *cfgPath, err)
		os.Exit(1)
	}
	sc := cfgProvider.GetConfig()

	if *showList {
		listMultilistenerPorts(sc)
	}

	target := portArg
	action := setMainListenerPort
	switch {
	case *addPort != 0:
		target, action = strconv.Itoa(*addPort), addExtraListenerPort
	case *removePort != 0:
		target, action = strconv.Itoa(*removePort), removeExtraListenerPort
	}

	port, err := strconv.Atoi(target)
	if err != nil || port < 1 || port > 65535 {
		fmt.Fprintf(os.Stderr, "Error: invalid port %q\n", target)
		os.Exit(1)
	}
	action(cfgProvider, sc, *cfgPath, port, *noRestart)
}
