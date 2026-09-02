<img width="5189" height="640" alt="logo2" src="https://github.com/user-attachments/assets/dbace4f7-b2f7-42d7-aec0-edacdf6688e2" />

### It is a fast, easy-to-use and easy-to-install censorship-bypassing proxy server disguised as a regular HTTPS connection, written in Go.

## Install and Update

### How to install? (Ubuntu/Debian/Arch) ( only root )

```bash
bash <(curl -sL https://raw.githubusercontent.com/nekoskin/whispera/main/install.sh)
```

### How to update?

```bash
bash menu
```

Select item 16

### Create keys, subscriptions, and view all keys

This is for creating a key

```bash
whispera create-key -user <your_username> -port <your_port> -sni <realdomain>
```

This is for creating a sub

```bash
whispera generate-sub -name "" -users <john, ...> 
```

This is for delete key

```bash
whispera delete-key <your user>
```

This allows you to view all keys

```bash
whispera view-keys
```

```bash
whispera view-keys -full 
whispera view-keys -user <your user> -full
```

This manages the listener ports

```bash
whispera set-multilistener-port <port>          # change the main listener port
whispera set-multilistener-port -add <port>     # add an extra listener port
whispera set-multilistener-port -remove <port>  # drop an extra listener port
whispera set-multilistener-port -list           # show every port and the keys using it
```

Every change rewrites the config, reseals the integrity checksum and restarts the service.
Add `-no-restart` to write the config without restarting.

Available options

```
-user <name> required — username used as the whispera auth identity

-port <port> required — dedicated listening port for this key

-sni <domain> real domain whose TLS certificate is cloned and presented for this key
              (required unless whispera.domain is set in the config)

-fingerprint auto|chrome|chrome_120|chrome_115|firefox|firefox_120|safari|ios|android|edge|random
             default is auto: it embeds the freshest collected chrome fingerprint

-transport whispera|grpc|yadisk (default: whispera)

-dropech disable Encrypted Client Hello

-quic enable/disable tunneling over QUIC instead of TCP

-quic-port <port> dedicated QUIC port (0 = reuse shared port)

-self-cert enable/disable clone a self-signed cert for the SNI and pin it in the key

-own-domain enable/disable the key targets a Caddy front on a real domain

-domain <domain> real domain for -own-domain mode

-yadisk-token <token> Yandex.Disk OAuth token (YADISK transport only)

-yadisk-session <id> Yandex.Disk session/folder ID (automatically generated if empty)

-config <path> path to config.yaml
```

## Build from source

Requires Go 1.26+. Pure-Go cross-compile:

```bash
# Server (linux only)
CGO_ENABLED=0 go build -o whispera-server ./app/server

# Go client (windows/linux/macos/android)
CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 \
  go build -o whispera-go-client ./app/goclient
```

## If you need a cascade, I recommend using this instruction

Install a whispera on each relay

```bash
curl -sSL https://raw.githubusercontent.com/nekoskin/whispera/main/install.sh | bash -s -- relay
```

Whispera secret (copy to master):

```bash
a1b2c3...== # this is an example
```

Open the config

```bash
nano /etc/whispera/config.yaml
```

Add outbounds on the master - /etc/whispera/config.yaml

```bash
outbounds:
  - tag: relay1
    protocol: whispera
    address: IP_RELAY1:443
    settings:
      whispera_secret: "SECRET_RELAY1"

  - tag: relay2
    protocol: whispera
    address: IP_RELAY2:443
    settings:
      whispera_secret: "SECRET_RELAY2"

  - tag: exit
    protocol: whispera
    address: IP_EXIT:443
    settings:
      whispera_secret: "SECRET_EXIT"
    chain: ["relay1", "relay2"]
```

Next command data

```bash
update checksum and restart
whispera update-checksum /etc/whispera/config.yaml
systemctl restart whispera
```

Check

```bash
journalctl -u whispera -n 50 --no-pager
```

There should be something in the logs

```bash
Started outbound tunnel: relay1 (1.2.3.4:443)
Started outbound tunnel: relay2 (5.6.7.8:443)
Started outbound tunnel: exit (9.10.11.12:443)
```

## Supported platforms - windows, android, linux

## License

Licensed under GNU AGPL v3.0.
