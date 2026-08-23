package config

const (
	Dir = "/etc/whispera"

	ConfigFile   = Dir + "/config.yaml"
	IdentityFile = Dir + "/identity_ed25519.key"
	DecoyCertDir = Dir + "/decoy_certs"
	ServerCert   = Dir + "/whispera.crt"
	ServerKey    = Dir + "/whispera.key"
	BackupDir    = Dir + "/backups"
)
