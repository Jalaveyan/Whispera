package commands

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"flag"
	"fmt"
	"github.com/nekoskin/whispera/common/fsown"
	"github.com/nekoskin/whispera/common/ipdetect"
	"github.com/nekoskin/whispera/core/apiserver"
	"github.com/nekoskin/whispera/core/config"
	"github.com/nekoskin/whispera/core/protocol"
	"github.com/nekoskin/whispera/core/protocol/fingerprint"
	"net"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/curve25519"
)

const decoyCertDir = config.DecoyCertDir

func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", b), nil
}

var hostnameLabel = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$`)

func validateHostnameFlag(flag, value string) error {
	if value == "" {
		return nil
	}
	if i := strings.Index(value, "://"); i >= 0 {
		return fmt.Errorf("%s must be a bare hostname, not a URL: use %q instead of %q", flag, config.HostFromPublicURL(value), value)
	}
	if i := strings.IndexAny(value, "/?#"); i >= 0 {
		return fmt.Errorf("%s must be a bare hostname without a path: use %q instead of %q", flag, strings.SplitN(value, string(value[i]), 2)[0], value)
	}
	if strings.Contains(value, ":") {
		return fmt.Errorf("%s must not carry a port: use %q instead of %q", flag, strings.SplitN(value, ":", 2)[0], value)
	}
	if net.ParseIP(value) != nil {
		return fmt.Errorf("%s must be a domain name, not an IP address: got %q", flag, value)
	}
	if len(value) > 253 {
		return fmt.Errorf("%s is %d characters, a hostname may not exceed 253: %q", flag, len(value), value)
	}
	for _, label := range strings.Split(strings.TrimSuffix(value, "."), ".") {
		if !hostnameLabel.MatchString(label) {
			return fmt.Errorf("%s %q is not a valid hostname: %q is not a usable label", flag, value, label)
		}
	}
	return nil
}

func RunX25519Cmd() {
	private := make([]byte, 32)
	if _, err := rand.Read(private); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	public, err := curve25519.X25519(private, curve25519.Basepoint)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Private Key: %s\n", base64.StdEncoding.EncodeToString(private))
	fmt.Printf("Public Key:  %s\n", base64.StdEncoding.EncodeToString(public))
	os.Exit(0)
}

func RunPubkeyCmd() {
	if len(os.Args) < 3 {
		fmt.Fprintln(os.Stderr, "whispera pubkey <private_key>")
		os.Exit(1)
	}
	privateKeyString := strings.TrimSpace(os.Args[2])

	private, err := base64.StdEncoding.DecodeString(privateKeyString)

	if err != nil || len(private) != 32 {
		fmt.Fprintf(os.Stderr, "Error: invalid private key (must be 32 bytes Base64)\n")
		os.Exit(1)
	}
	pub, _ := curve25519.X25519(private, curve25519.Basepoint)
	fmt.Println(base64.StdEncoding.EncodeToString(pub))
	os.Exit(0)
}

func RunDeleteKeyCmd() {
	deleteKeyCmd := flag.NewFlagSet("delete-key", flag.ExitOnError)
	user := deleteKeyCmd.String("user", "", "User identifier to delete")
	deleteKeyCmd.Parse(os.Args[2:])

	if *user == "" && deleteKeyCmd.NArg() > 0 {
		*user = deleteKeyCmd.Arg(0)
	}
	if *user == "" {
		fmt.Fprintln(os.Stderr, "whispera delete-key <user>   (or: whispera delete-key -user <name>)")
		os.Exit(1)
	}

	deleted, err := apiserver.CLIDeleteUser(*user)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to delete key for %q: %v\n", *user, err)
		os.Exit(1)
	}
	if !deleted {
		fmt.Fprintf(os.Stderr, "No key found for user %q\n", *user)
		os.Exit(1)
	}
	fmt.Printf("Deleted key/user %q. Restart to drop any active session: systemctl restart whispera\n", *user)
	os.Exit(0)
}

func resolveWhisperaQUICAddr(enableQUIC bool, sc *config.ServerConfig, cfgProvider *config.Provider, cfgPath string, quicPort int, serverHost string) string {
	if !enableQUIC {
		return ""
	}
	if sc.Whispera.QUICListenAddr == "" {
		fmt.Fprintln(os.Stderr, "Warning: -quic=enable requested but whispera.quic_listen_addr is not configured on this server — key generated without QUIC")
		return ""
	}
	quicHost, quicListenPortStr, err := net.SplitHostPort(sc.Whispera.QUICListenAddr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: invalid whispera.quic_listen_addr %q: %v — key generated without QUIC\n", sc.Whispera.QUICListenAddr, err)
		return ""
	}
	if ip := net.ParseIP(quicHost); quicHost == "" || (ip != nil && (ip.IsUnspecified() || ip.IsLoopback())) {
		if ip != nil && ip.IsLoopback() {
			fmt.Fprintf(os.Stderr, "Warning: whispera.quic_listen_addr is bound to %s, which no client can reach — the key points at %s instead, but the server still listens only on loopback\n", quicHost, serverHost)
		}
		quicHost = serverHost
	}
	effectiveQUICPortStr := quicListenPortStr
	if quicPort == 0 || strconv.Itoa(quicPort) == quicListenPortStr {
		return net.JoinHostPort(quicHost, effectiveQUICPortStr)
	}
	effectiveQUICPortStr = strconv.Itoa(quicPort)

	quicPortTaken := false
	for _, p := range sc.Whispera.QUICExtraPorts {
		if p == quicPort {
			quicPortTaken = true
		}
	}
	if quicPortTaken {
		fmt.Printf("QUIC port %d is already a listener — reusing it\n", quicPort)
	} else {
		if err := cfgProvider.Update(func(sc *config.ServerConfig) {
			sc.Whispera.QUICExtraPorts = append(sc.Whispera.QUICExtraPorts, quicPort)
		}); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to update %s: %v\n", cfgPath, err)
			os.Exit(1)
		}
		fmt.Printf("QUIC will also listen on port %d (restart server to activate)\n", quicPort)
	}
	return net.JoinHostPort(quicHost, effectiveQUICPortStr)
}

func loadCertIdentity() (idPub, selPub string) {
	id, err := protocol.LoadOrCreateCertIdentity(config.IdentityFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: cert identity unavailable: %v; the cert will carry no identity binding, so keys fall back to a cert pin\n", err)
		return "", ""
	}
	protocol.SetCertIdentity(id)
	if raw := id.SelectorPub(); len(raw) == 32 {
		selPub = base64.StdEncoding.EncodeToString(raw)
	}
	return id.PubB64(), selPub
}

type whisperaKeyPlan struct {
	domainMode bool
	sni        string
	idPub      string
	selPub     string
	certPin    string
	fpName     string
	fpRaw      string
}

func planWhisperaKey(sc *config.ServerConfig, sniFlag, domainFlag, selfCertFlag, ownDomainFlag, fingerprintFlag string) (whisperaKeyPlan, error) {
	plan := whisperaKeyPlan{domainMode: sc.Whispera.BackendH2CAddr != ""}
	switch strings.ToLower(ownDomainFlag) {
	case "enable":
		plan.domainMode = true
	case "disable":
		plan.domainMode = false
	}
	useSelfCert := !plan.domainMode
	switch strings.ToLower(selfCertFlag) {
	case "enable":
		useSelfCert = true
	case "disable":
		useSelfCert = false
	}

	source := "-sni"
	plan.sni = sniFlag
	if plan.domainMode {
		source, plan.sni = "-domain", domainFlag
	}
	if plan.sni == "" {
		source, plan.sni = "whispera.domain in the config", sc.Whispera.Domain
	}
	if plan.sni == "" {
		if plan.domainMode {
			return plan, fmt.Errorf("domain/Caddy mode needs a domain: pass -domain <real-domain>, or set whispera.domain in the config")
		}
		return plan, fmt.Errorf("-sni <real-domain> is required: no whispera.domain in the config to fall back to")
	}
	if err := validateHostnameFlag(source, plan.sni); err != nil {
		return plan, err
	}

	plan.fpName, plan.fpRaw = resolveFingerprint(fingerprintFlag)
	if !useSelfCert {
		return plan, nil
	}

	plan.idPub, plan.selPub = loadCertIdentity()

	certPath, keyPath, ok := protocol.SNICertPaths(decoyCertDir, plan.sni)
	if !ok {
		return plan, fmt.Errorf("%s %q cannot be used as a certificate file name", source, plan.sni)
	}
	if err := os.MkdirAll(decoyCertDir, 0755); err != nil {
		return plan, fmt.Errorf("create %s: %w", decoyCertDir, err)
	}
	if err := fsown.MatchParentTree(decoyCertDir); err != nil {
		return plan, fmt.Errorf("the service will not be able to read %s: %w", decoyCertDir, err)
	}
	if err := fsown.InheritGroup(decoyCertDir); err != nil {
		return plan, err
	}

	info, err := protocol.CloneCertToFiles(plan.sni, certPath, keyPath)
	if err != nil {
		return plan, fmt.Errorf("clone the TLS certificate of %q: %w", plan.sni, err)
	}
	fmt.Printf("Cloned TLS certificate for SNI %s (subject=%s, valid %s -> %s)\n",
		plan.sni, info.Subject, info.NotBefore.Format(time.RFC3339), info.NotAfter.Format(time.RFC3339))

	if plan.idPub == "" {
		pin, err := apiserver.ComputeWhisperaCertPin(certPath)
		if err != nil {
			return plan, fmt.Errorf("compute the cert pin of %s: %w", certPath, err)
		}
		plan.certPin = pin
	}
	return plan, nil
}

func resolveFingerprint(name string) (string, string) {
	if name != "auto" {
		return name, ""
	}
	raw, ok := fingerprint.FreshestRaw(apiserver.FingerprintStoreDir, "chrome")
	if !ok {
		fmt.Printf("No collected fingerprint in %s — using named uTLS chrome\n", apiserver.FingerprintStoreDir)
		return "chrome", ""
	}
	fmt.Printf("Embedded freshest collected chrome fingerprint (%d bytes) from %s\n", len(raw), apiserver.FingerprintStoreDir)
	return "chrome", base64.StdEncoding.EncodeToString(raw)
}

func portInUse(port int, sc *config.ServerConfig) bool {
	if slices.Contains(sc.Whispera.ExtraPorts, port) {
		return true
	}
	if slices.ContainsFunc(sc.Inbounds, func(in config.InboundConfig) bool { return in.Port == port }) {
		return true
	}
	_, chmPortStr, _ := net.SplitHostPort(sc.Whispera.ListenAddr)
	chmPort, _ := strconv.Atoi(chmPortStr)
	return port == chmPort
}

func reservePort(transport string, port int, sc *config.ServerConfig, cfgProvider *config.Provider, cfgPath string) error {
	switch transport {
	case "yadisk":
		return nil

	case "grpc":
		_, grpcPortStr, _ := net.SplitHostPort(sc.GRPC.ListenAddr)
		grpcPort, _ := strconv.Atoi(grpcPortStr)
		if port == grpcPort || slices.Contains(sc.GRPC.ExtraPorts, port) {
			fmt.Printf("Port %d is already a gRPC listener — reusing it\n", port)
			return nil
		}
		if portInUse(port, sc) {
			return fmt.Errorf("port %d is already bound by another listener — gRPC can't also bind it; pick a different -port, or use %d (grpc.listen_addr) directly", port, grpcPort)
		}
		if err := cfgProvider.Update(func(sc *config.ServerConfig) {
			sc.GRPC.ExtraPorts = append(sc.GRPC.ExtraPorts, port)
		}); err != nil {
			return fmt.Errorf("update %s: %w", cfgPath, err)
		}
		fmt.Printf("gRPC will also listen on port %d (restart server to activate)\n", port)
		return nil

	default:
		if portInUse(port, sc) {
			fmt.Printf("Port %d is already a whispera listener — reusing it\n", port)
			return nil
		}
		if err := cfgProvider.Update(func(sc *config.ServerConfig) {
			sc.Whispera.ExtraPorts = append(sc.Whispera.ExtraPorts, port)
		}); err != nil {
			return fmt.Errorf("update %s: %w", cfgPath, err)
		}
		fmt.Printf("Whispera will also listen on port %d (restart server to activate)\n", port)
		return nil
	}
}

type createKeyFlags struct {
	user          string
	port          int
	quicPort      int
	cfgPath       string
	quic          string
	transport     string
	yadiskToken   string
	yadiskSession string
	sni           string
	fingerprint   string
	selfCert      string
	ownDomain     string
	domain        string
}

func parseCreateKeyFlags(args []string) *createKeyFlags {
	f := &createKeyFlags{}
	fs := flag.NewFlagSet("create-key", flag.ExitOnError)
	fs.StringVar(&f.user, "user", "", "User identifier (used as the whispera auth username)")
	fs.IntVar(&f.port, "port", 0, "Dedicated listen port for this user (whispera TCP, or grpc, depending on -transport)")
	fs.IntVar(&f.quicPort, "quic-port", 0, "Dedicated QUIC port for this user (only with -quic enable; 0 = reuse whispera.quic_listen_addr's port)")
	fs.StringVar(&f.cfgPath, "config", config.ConfigFile, "Path to config.yaml")
	fs.StringVar(&f.quic, "quic", "disable", "Carry the whispera tunnel over QUIC instead of TCP (enable/disable, only applies to -transport whispera)")
	fs.StringVar(&f.transport, "transport", "whispera", "Base transport for this key: whispera, grpc, or yadisk")
	fs.StringVar(&f.yadiskToken, "yadisk-token", "", "Yandex.Disk OAuth token (only with -transport yadisk; saved to server config if not already set there)")
	fs.StringVar(&f.yadiskSession, "yadisk-session", "", "Yandex.Disk session/folder id (only with -transport yadisk; auto-generated if empty)")
	fs.StringVar(&f.sni, "sni", "", "Clone this real domain's TLS certificate and present it via SNI for this key (only with -transport whispera; required unless whispera.domain is set in the server config)")
	fs.StringVar(&f.fingerprint, "fingerprint", "auto", "TLS fingerprint for the tunnel ClientHello: auto (embed freshest collected chrome), or a named uTLS profile: chrome, chrome_120, chrome_115, firefox, firefox_120, safari, ios, android, edge, random")
	fs.StringVar(&f.selfCert, "self-cert", "", "Clone a self-signed cert for the SNI and pin it in the key (enable/disable; default: auto from server config)")
	fs.StringVar(&f.ownDomain, "own-domain", "", "Key targets a Caddy + real-domain front: SNI/addr = the domain, no cert pin (enable/disable; default: auto from server config)")
	fs.StringVar(&f.domain, "domain", "", "Real domain for -own-domain mode (Caddy front); addr and SNI of the key are set to this. Empty = whispera.domain from config")
	fs.Parse(args)
	return f
}

func (f *createKeyFlags) validate() error {
	if f.user == "" || f.port == 0 {
		return fmt.Errorf("whispera create-key -user <name> -port <port> [-config <path>] [-quic enable|disable] [-quic-port <port>] [-transport whispera|grpc|yadisk] [-yadisk-token <token>] [-yadisk-session <id>] [-sni <real-domain>] [-fingerprint <name>] [-self-cert enable|disable] [-own-domain enable|disable]")
	}
	if f.fingerprint != "auto" && !fingerprint.IsKnown(f.fingerprint) {
		return fmt.Errorf("unknown -fingerprint %q (auto, chrome, chrome_120, chrome_115, firefox, firefox_120, safari, ios, android, edge, random)", f.fingerprint)
	}
	if f.port < 1 || f.port > 65535 {
		return fmt.Errorf("invalid port %d", f.port)
	}
	if f.quicPort != 0 && (f.quicPort < 1 || f.quicPort > 65535) {
		return fmt.Errorf("invalid quic-port %d", f.quicPort)
	}
	if !strings.EqualFold(f.quic, "enable") && !strings.EqualFold(f.quic, "disable") {
		return fmt.Errorf("-quic must be \"enable\" or \"disable\", got %q", f.quic)
	}
	switch strings.ToLower(f.transport) {
	case "whispera", "grpc", "yadisk":
	default:
		return fmt.Errorf("-transport must be \"whispera\", \"grpc\" or \"yadisk\", got %q", f.transport)
	}
	if err := validateHostnameFlag("-sni", f.sni); err != nil {
		return err
	}
	return validateHostnameFlag("-domain", f.domain)
}

func (f *createKeyFlags) quicEnabled() bool { return strings.EqualFold(f.quic, "enable") }

func saveYaDiskSettings(f *createKeyFlags, sc *config.ServerConfig, cfgProvider *config.Provider) error {
	if strings.ToLower(f.transport) != "yadisk" {
		return nil
	}
	oauth, session, enabled := sc.YaDisk.OAuthToken, sc.YaDisk.SessionID, sc.YaDisk.Enabled
	changed := false

	if f.yadiskToken != "" && f.yadiskToken != oauth {
		oauth, enabled, changed = f.yadiskToken, true, true
	}
	if f.yadiskSession != "" && f.yadiskSession != session {
		session, changed = f.yadiskSession, true
	} else if session == "" && oauth != "" {
		if gen, err := randomHex(8); err == nil {
			session, changed = gen, true
		}
	}
	if !changed {
		return nil
	}

	if err := cfgProvider.Update(func(sc *config.ServerConfig) {
		sc.YaDisk.OAuthToken = oauth
		sc.YaDisk.SessionID = session
		sc.YaDisk.Enabled = enabled
	}); err != nil {
		return fmt.Errorf("update %s: %w", f.cfgPath, err)
	}
	fmt.Println("Saved yadisk.oauth_token/session_id to server config (restart server to activate)")
	return nil
}

func effectiveTransportFor(requested string, sc *config.ServerConfig) string {
	switch requested {
	case "grpc":
		if !sc.GRPC.Enabled || sc.GRPC.ListenAddr == "" {
			fmt.Fprintln(os.Stderr, "Warning: -transport=grpc requested but grpc.enabled/listen_addr is not configured on this server — key generated with whispera transport instead")
			return "whispera"
		}
	case "yadisk":
		if !sc.YaDisk.Enabled || sc.YaDisk.OAuthToken == "" {
			fmt.Fprintln(os.Stderr, "Warning: -transport=yadisk requested but yadisk.enabled/oauth_token is not configured on this server (pass -yadisk-token to set it) — key generated with whispera transport instead")
			return "whispera"
		}
	}
	return requested
}

func detectServerHost(sc *config.ServerConfig) string {
	if host := config.HostFromPublicURL(sc.Server.PublicURL); host != "" {
		return host
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if host, _ := ipdetect.DetectServerIP(ctx); host != "" {
		return host
	}
	return "<server_ip>"
}

func printClientConfig(user, serverAddr, privateKey, publicKey, transport, uri string,
	whisperaOpts apiserver.WhisperaKeyOptions, altOpts apiserver.AltTransportKeyOptions) {
	fmt.Println()
	fmt.Println("=== Client config ===")
	fmt.Printf("User:        %s\n", user)
	fmt.Printf("Server:      %s\n", serverAddr)
	fmt.Printf("Private Key: %s\n", privateKey)
	fmt.Printf("Public Key:  %s\n", publicKey)

	switch transport {
	case "grpc":
		fmt.Printf("Transport:   grpc (%s)\n", altOpts.GRPCAddr)
	case "yadisk":
		fmt.Println("Transport:   yadisk")
	default:
		switch {
		case whisperaOpts.CertPin != "":
			fmt.Printf("Cert Pin:    %s (embedded in key — protects against TLS MITM)\n", whisperaOpts.CertPin)
		case whisperaOpts.IDPub != "":
			fmt.Println("Cert Pin:    none (the key carries the server's cert identity key instead, so the cert can rotate)")
		default:
			fmt.Println("Cert Pin:    none (a real cert is served on the front — nothing to pin)")
		}
		if whisperaOpts.QUICAddr != "" {
			fmt.Printf("Transport:   whispera over QUIC (%s)\n", whisperaOpts.QUICAddr)
		} else {
			fmt.Println("Transport:   whispera over TCP")
		}
	}
	fmt.Printf("Key:         %s\n", uri)
	fmt.Println()
}

func altTransportOptions(transport, serverHost string, port int, sc *config.ServerConfig) apiserver.AltTransportKeyOptions {
	opts := apiserver.AltTransportKeyOptions{}
	switch transport {
	case "grpc":
		opts.GRPCAddr = net.JoinHostPort(serverHost, strconv.Itoa(port))
		opts.GRPCServerName = sc.GRPC.ServerName
		opts.GRPCUseTLS = sc.GRPC.TLSCert != ""
	case "yadisk":
		opts.YaDiskOAuthToken = sc.YaDisk.OAuthToken
		opts.YaDiskSessionID = sc.YaDisk.SessionID
	}
	return opts
}

func fatalKeyNotCreated(user string, err error) {
	fmt.Fprintf(os.Stderr, "Error: %v\n", err)
	fmt.Fprintf(os.Stderr, "Key for %q was not created.\n", user)
	os.Exit(1)
}

func RunCreateKeyCmd() {
	f := parseCreateKeyFlags(os.Args[2:])
	if err := f.validate(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	cfgProvider, err := config.New(f.cfgPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	if err := cfgProvider.Load(f.cfgPath); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load %s: %v\n", f.cfgPath, err)
		os.Exit(1)
	}
	sc := cfgProvider.GetConfig()

	if err := saveYaDiskSettings(f, sc, cfgProvider); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	sc = cfgProvider.GetConfig()

	transport := effectiveTransportFor(strings.ToLower(f.transport), sc)

	whisperaOpts := apiserver.WhisperaKeyOptions{}
	plan := whisperaKeyPlan{}
	if transport == "whispera" {
		plan, err = planWhisperaKey(sc, f.sni, f.domain, f.selfCert, f.ownDomain, f.fingerprint)
		if err != nil {
			fatalKeyNotCreated(f.user, err)
		}
		whisperaOpts = apiserver.WhisperaKeyOptions{
			SNI:         plan.sni,
			CertPin:     plan.certPin,
			IDPub:       plan.idPub,
			SelPub:      plan.selPub,
			Fingerprint: plan.fpName,
			FPRaw:       plan.fpRaw,
		}
	}

	if err := reservePort(transport, f.port, sc, cfgProvider, f.cfgPath); err != nil {
		fatalKeyNotCreated(f.user, err)
	}

	privateKeyB64, publicKeyB64, err := apiserver.CLIUpsertUser(f.user)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create user: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("User %s registered for live auth (/etc/whispera/users.json)\n", f.user)

	serverHost := detectServerHost(sc)
	serverAddr := net.JoinHostPort(serverHost, strconv.Itoa(f.port))
	serverPubKeyB64 := ""
	if sc.Server.PrivateKey != "" {
		serverPubKeyB64 = apiserver.DerivePublicKeyB64(sc.Server.PrivateKey)
	}
	altOpts := altTransportOptions(transport, serverHost, f.port, sc)

	if transport == "whispera" {
		addrHost, addrPort := serverHost, strconv.Itoa(f.port)
		if plan.domainMode {
			_, frontPort, _ := net.SplitHostPort(sc.Whispera.ListenAddr)
			addrHost, addrPort = plan.sni, frontPort
			serverAddr = net.JoinHostPort(addrHost, addrPort)
			fmt.Printf("Domain/Caddy mode: key SNI/addr = %s, no cert pin (real cert expected on the front)\n", plan.sni)
		}
		whisperaOpts.Addr = net.JoinHostPort(addrHost, addrPort)
		whisperaOpts.QUICAddr = resolveWhisperaQUICAddr(f.quicEnabled(), sc, cfgProvider, f.cfgPath, f.quicPort, serverHost)
		warnListenPortConflict(sc)
	}

	connectionURI, err := apiserver.CLIBuildConnectionKey(f.user, serverAddr, serverPubKeyB64, "whispera", whisperaOpts, altOpts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to build connection key: %v\n", err)
		os.Exit(1)
	}

	printClientConfig(f.user, serverAddr, privateKeyB64, publicKeyB64, transport, connectionURI, whisperaOpts, altOpts)

	if err := cfgProvider.UpdateChecksum(); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: could not update the config checksum: %v\n", err)
		fmt.Fprintln(os.Stderr, "Run 'whispera update-checksum "+f.cfgPath+"' before restarting, or the integrity check will refuse to start the server.")
	}

	fmt.Println("Restart the whispera server for the new user/inbound to take effect.")
	os.Exit(0)
}

func RunGenerateSubCmd() {
	genSubCmd := flag.NewFlagSet("generate-sub", flag.ExitOnError)
	name := genSubCmd.String("name", "", "Subscription name")
	usersCSV := genSubCmd.String("users", "", "Comma-separated list of usernames created via create-key")
	cfgPath := genSubCmd.String("config", config.ConfigFile, "Path to config.yaml")

	genSubCmd.Parse(os.Args[2:])

	if *usersCSV == "" {
		fmt.Fprintln(os.Stderr, "whispera generate-sub -users <user1,user2,...> [-name <name>] [-config <path>]")
		os.Exit(1)
	}
	if *name == "" {
		*name = fmt.Sprintf("Sub-%d", time.Now().Unix())
	}

	usernames := strings.Split(*usersCSV, ",")
	for i := range usernames {
		usernames[i] = strings.TrimSpace(usernames[i])
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

	token, err := apiserver.CLICreateSubscription(*name, usernames)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create subscription: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Subscription %q created for %d user(s)\n", *name, len(usernames))

	serverHost := strings.TrimRight(sc.Server.PublicURL, "/")
	if serverHost == "" {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		ip, _ := ipdetect.DetectServerIP(ctx)
		cancel()
		if ip == "" {
			ip = "<server_ip>"
		}
		serverHost = fmt.Sprintf("http://%s:8081", ip)
	}

	fmt.Println()
	fmt.Println("=== Subscription URL ===")
	fmt.Printf("%s/sub/%s\n", serverHost, token)
	fmt.Println()
	fmt.Println("Restart the whispera server for the new subscription to take effect.")
	os.Exit(0)
}

func RunViewKeysCmd() {
	viewKeysCmd := flag.NewFlagSet("view-keys", flag.ExitOnError)
	filterUser := viewKeysCmd.String("user", "", "Show only this user")
	full := viewKeysCmd.Bool("full", false, "Print the full whispera:// connection key")

	viewKeysCmd.Parse(os.Args[2:])

	users := apiserver.CLIListUsers()
	if len(users) == 0 {
		fmt.Println("No users found in /etc/whispera/users.json")
		os.Exit(0)
	}

	printed := 0
	for _, u := range users {
		if *filterUser != "" && u.Username != *filterUser {
			continue
		}
		printed++

		fmt.Printf("ID:      %d\n", u.ID)
		fmt.Printf("User:    %s\n", u.Username)
		fmt.Printf("Status:  %s\n", u.Status)
		fmt.Printf("Created: %s\n", u.CreatedAt.Format(time.RFC3339))
		if u.ExpiryDate != "" {
			fmt.Printf("Expires: %s\n", u.ExpiryDate)
		}
		switch {
		case u.ConnectionURI == "":
			fmt.Println("Key:     (none — run create-key again to generate one)")
		case *full:
			fmt.Printf("Key:     %s\n", u.ConnectionURI)
		default:
			fmt.Printf("Key:     %s... (%d chars total, use -full to print)\n",
				u.ConnectionURI[:min(40, len(u.ConnectionURI))], len(u.ConnectionURI))
		}
		fmt.Println()
	}

	if *filterUser != "" && printed == 0 {
		fmt.Fprintf(os.Stderr, "User %q not found\n", *filterUser)
		os.Exit(1)
	}
	os.Exit(0)
}

func RunUpdateChecksumCmd() {
	cfgPath := config.ConfigFile
	if len(os.Args) >= 3 {
		cfgPath = os.Args[2]
	}
	p, err := config.New(cfgPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	if err := p.UpdateChecksum(); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to update checksum: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("Checksum updated successfully")
	os.Exit(0)
}
