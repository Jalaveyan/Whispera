#!/bin/bash
set -e
cd /src

echo "=== building server + client ==="
CGO_ENABLED=0 go build -o /tmp/whispera-server ./app/server
CGO_ENABLED=0 go build -o /tmp/whispera-client ./app/client

mkdir -p /etc/whispera
rm -f /etc/whispera/users.json /etc/whispera/config.yaml

echo "=== generating self-signed TLS cert ==="
command -v openssl >/dev/null 2>&1 || (apt-get update >/dev/null 2>&1 && apt-get install -y openssl >/dev/null 2>&1)
openssl req -x509 -newkey rsa:2048 -keyout /etc/whispera/test.key -out /etc/whispera/test.crt \
    -days 1 -nodes -subj "/CN=localhost" >/dev/null 2>&1

echo "=== generating server keypair ==="
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
cd /src
KEYPAIR=$(go run /tmp/genkey.go)
SRV_PRIV=$(echo "$KEYPAIR" | sed -n 1p)
SRV_PUB=$(echo "$KEYPAIR" | sed -n 2p)
echo "server private: $SRV_PRIV"
echo "server public:  $SRV_PUB"

cat > /etc/whispera/config.yaml <<EOF
server:
  name: test-server
  listen_addr: "0.0.0.0:443"
  private_key: "$SRV_PRIV"
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
  level: "info"
  format: "text"
  output: "stdout"
EOF

echo
echo "=== starting server ==="
/tmp/whispera-server -config /etc/whispera/config.yaml > /tmp/server.log 2>&1 &
SERVER_PID=$!
sleep 2
echo "server pid: $SERVER_PID"
echo "--- server.log so far ---"
cat /tmp/server.log

echo
echo "=== creating test user on port 443 (reuse main listener) ==="
/tmp/whispera-server create-key -user testuser -port 443 -config /etc/whispera/config.yaml > /tmp/createkey.out 2>&1
cat /tmp/createkey.out
CONN_KEY=$(grep -oE "whispera://\S+" /tmp/createkey.out | head -1)
echo
echo "connection key: $CONN_KEY"

if [[ -z "$CONN_KEY" ]]; then
  echo "FAIL: no connection key produced"
  cat /tmp/server.log
  kill $SERVER_PID 2>/dev/null || true
  exit 1
fi

echo
echo "=== starting client ==="
/tmp/whispera-client -key "$CONN_KEY" -socks 127.0.0.1:10800 -no-tun=true -control-port 10801 > /tmp/client.log 2>&1 &
CLIENT_PID=$!

echo "waiting for client to report connected..."
for i in $(seq 1 15); do
  sleep 1
  if grep -qiE "connected|established|ready" /tmp/client.log 2>/dev/null; then
    echo "client looks connected after ${i}s"
    break
  fi
done

echo "--- client.log ---"
cat /tmp/client.log

echo
echo "=== trying to load something through the SOCKS5 proxy ==="
set +e
curl -x socks5h://127.0.0.1:10800 -m 12 -v http://example.com/ -o /tmp/curl_body.html 2> /tmp/curl_stderr.log
CURL_RC=$?
set -e
echo "curl exit code: $CURL_RC"
echo "--- curl stderr (connection trace) ---"
cat /tmp/curl_stderr.log
echo "--- response body size ---"
wc -c /tmp/curl_body.html 2>/dev/null || echo "(no body file)"

sleep 1
echo
echo "=== server.log (full, after load attempt) ==="
cat /tmp/server.log

echo
echo "=== client.log (full, after load attempt) ==="
cat /tmp/client.log

kill $CLIENT_PID 2>/dev/null || true
kill $SERVER_PID 2>/dev/null || true
wait 2>/dev/null || true
