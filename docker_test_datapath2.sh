#!/bin/bash
set -e
cd /src

mkdir -p /etc/whispera
rm -f /etc/whispera/users.json /etc/whispera/config.yaml

echo "=== generating self-signed TLS cert ==="
command -v openssl >/dev/null 2>&1 || (apt-get update >/dev/null 2>&1 && apt-get install -y openssl >/dev/null 2>&1)
openssl req -x509 -newkey rsa:2048 -keyout /etc/whispera/test.key -out /etc/whispera/test.crt \
    -days 1 -nodes -subj "/CN=localhost" >/dev/null 2>&1

cat > /tmp/genkey.go <<'GOEOF'
package main
import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"golang.org/x/crypto/curve25519"
)
func main() {
	priv := make([]byte, 32)
	rand.Read(priv)
	pub, _ := curve25519.X25519(priv, curve25519.Basepoint)
	fmt.Println(base64.StdEncoding.EncodeToString(priv))
	fmt.Println(base64.StdEncoding.EncodeToString(pub))
}
GOEOF
KEYPAIR=$(go run /tmp/genkey.go)
SRV_PRIV=$(echo "$KEYPAIR" | sed -n 1p)

cat > /etc/whispera/config.yaml <<EOF
server:
  name: test-server
  listen_addr: "0.0.0.0:443"
  private_key: "$SRV_PRIV"
  public_url: "127.0.0.1"
  mtu: 1420
  workers: 4
whispera:
  enabled: true
  listen_addr: ":443"
  tls_cert: "/etc/whispera/test.crt"
  tls_key: "/etc/whispera/test.key"
  domain: ""
  decoy_origin: "https://ria.ru/"
api:
  enabled: true
  listen_addr: "127.0.0.1:8080"
logging:
  level: "debug"
  format: "text"
  output: "stdout"
EOF

echo "=== building server + client (with -debug) ==="
CGO_ENABLED=0 go build -o /tmp/whispera-server ./app/server
CGO_ENABLED=0 go build -o /tmp/whispera-client ./app/client

echo "=== starting server (debug) ==="
/tmp/whispera-server -config /etc/whispera/config.yaml -debug > /tmp/server.log 2>&1 &
SERVER_PID=$!
sleep 2

echo "=== creating test user on port 443 ==="
/tmp/whispera-server create-key -user testuser -port 443 -config /etc/whispera/config.yaml > /tmp/createkey.out 2>&1
CONN_KEY=$(grep -oE "whispera://\S+" /tmp/createkey.out | head -1)
echo "connection key: $CONN_KEY"

echo "=== starting client with -log-file (forces real logging) ==="
/tmp/whispera-client -key "$CONN_KEY" -socks 127.0.0.1:10800 -no-tun=true -control-port 10801 -log-file /tmp/client.log &
CLIENT_PID=$!
sleep 3

echo "=== trying to load through SOCKS5 ==="
set +e
curl -x socks5h://127.0.0.1:10800 -m 12 -v http://example.com/ -o /tmp/curl_body.html 2> /tmp/curl_stderr.log
echo "curl exit: $?"
set -e
cat /tmp/curl_stderr.log

sleep 1
echo
echo "=== /logs from client control API (backup, should be empty since -log-file used) ==="
curl -s http://127.0.0.1:10801/logs || true

echo
echo "=== FULL server.log ==="
cat /tmp/server.log

echo
echo "=== FULL client.log ==="
cat /tmp/client.log

kill $CLIENT_PID $SERVER_PID 2>/dev/null || true
wait 2>/dev/null || true
