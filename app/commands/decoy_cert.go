package commands

import (
	"flag"
	"fmt"
	"github.com/nekoskin/whispera/common/fsown"
	"github.com/nekoskin/whispera/core/config"
	"github.com/nekoskin/whispera/core/protocol"
	"os"
	"time"
)

func RunGenDecoyCertCmd() {
	genCmd := flag.NewFlagSet("gen-decoy-cert", flag.ExitOnError)
	domain := genCmd.String("domain", "", "Real-world domain to clone the certificate fields from (e.g. example.com)")
	outCert := genCmd.String("out-cert", config.ServerCert, "Output path for the generated certificate (PEM)")
	outKey := genCmd.String("out-key", config.ServerKey, "Output path for the generated private key (PEM)")

	genCmd.Parse(os.Args[2:])

	if *domain == "" {
		fmt.Fprintln(os.Stderr, "whispera gen-decoy-cert -domain <real-domain> [-out-cert <path>] [-out-key <path>]")
		os.Exit(1)
	}

	loadCertIdentity()

	info, err := protocol.CloneCertToFiles(*domain, *outCert, *outKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to generate decoy certificate: %v\n", err)
		os.Exit(1)
	}
	for _, path := range []string{*outCert, *outKey} {
		if err := fsown.MatchParent(path); err != nil {
			fmt.Fprintf(os.Stderr, "Error: the service will not be able to read %s: %v\n", path, err)
			os.Exit(1)
		}
	}

	fmt.Printf("Cloned certificate fields from %s\n", *domain)
	fmt.Printf("Subject:     %s\n", info.Subject)
	if len(info.DNSNames) > 0 {
		fmt.Printf("SAN (DNS):   %v\n", info.DNSNames)
	}
	fmt.Printf("Valid:       %s -> %s\n", info.NotBefore.Format(time.RFC3339), info.NotAfter.Format(time.RFC3339))
	fmt.Printf("Cert:        %s\n", *outCert)
	fmt.Printf("Key:         %s\n", *outKey)
	fmt.Println()
	fmt.Println("Set whispera.tls_cert / whispera.tls_key to these paths and restart the server.")
	os.Exit(0)
}
