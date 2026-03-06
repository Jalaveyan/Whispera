package yatelemost

// yatelemost.go — VPN transport over Yandex Telemost TURN servers.
//
// Uses Yandex TURN (turn.webrtc.yandex.net) with credentials obtained from
// the Telemost API.  The Telemost conference WebSocket is reused for WebRTC
// SDP/ICE signaling between client and server.
//
// Both VPN peers (client and server) must have a valid Yandex Session_id.
// They meet in the same Telemost conference identified by ConferenceURL.
// The server creates the conference and shares the URL with the client
// out-of-band (e.g. via config file or QR code).

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pion/interceptor"
	"github.com/pion/webrtc/v3"
	"nhooyr.io/websocket"

	"whispera/internal/core/base"
	"whispera/internal/core/interfaces"
	"whispera/internal/core/registry"
	"whispera/internal/logger"
)

func init() {
	registry.GlobalFactoryRegistry.RegisterFactory(ModuleName, Factory)
}

var log = logger.Module("yatelemost")

const (
	ModuleName    = "transport.yatelemost"
	ModuleVersion = "1.0.0"

	// Signaling message types (sent through Telemost conference WS).
	sigOffer     = "vpn_offer"
	sigAnswer    = "vpn_answer"
	sigCandidate = "vpn_ice"
)

// Config for the Yandex Telemost transport.
type Config struct {
	// ServerMode: true on the VPN server, false on the VPN client.
	ServerMode bool

	// SessionID is the Yandex Session_id cookie.
	// Obtain: log in at yandex.ru → DevTools → Cookies → Session_id.
	SessionID string

	// ConferenceURL is the Telemost join URL shared between peers.
	// Server: leave empty — a new conference is created on Start().
	// Client: set to the URL the server advertised.
	ConferenceURL string

	// ICEPolicy: "relay" (default, required for CIDR bypass) or "all".
	ICEPolicy string

	BufferSize int
}

func DefaultConfig() *Config {
	return &Config{
		ICEPolicy:  "relay",
		BufferSize: 32 * 1024,
	}
}

// sigMsg is the envelope for VPN signaling messages sent over Telemost WS.
type sigMsg struct {
	Type      string `json:"type"`
	SDP       string `json:"sdp,omitempty"`
	Candidate string `json:"candidate,omitempty"`
}

// Transport implements VPN tunneling through Yandex Telemost TURN.
type Transport struct {
	*base.Module
	config *Config

	conf      *TeleMostConference
	sigWS     *websocket.Conn
	api       *webrtc.API
	pc        *webrtc.PeerConnection
	dc        *webrtc.DataChannel

	connCh   chan net.Conn
	ready    chan struct{}
	readyOnce sync.Once
	stopCh   chan struct{}
	stopOnce sync.Once

	remoteCandidatesDone int32 // atomic
}

func Factory(cfg interface{}) (interfaces.Module, error) {
	c, ok := cfg.(*Config)
	if !ok {
		c = DefaultConfig()
	}
	return New(c)
}

func New(cfg *Config) (*Transport, error) {
	if cfg == nil {
		cfg = DefaultConfig()
	}
	if cfg.BufferSize == 0 {
		cfg.BufferSize = 32 * 1024
	}
	if cfg.ICEPolicy == "" {
		cfg.ICEPolicy = "relay"
	}
	return &Transport{
		Module: base.NewModule(ModuleName, ModuleVersion, nil),
		config: cfg,
		connCh: make(chan net.Conn, 1),
		ready:  make(chan struct{}),
		stopCh: make(chan struct{}),
	}, nil
}

// Start initialises the Telemost conference connection and prepares WebRTC.
// On the server side it creates a new conference and logs the join URL.
func (t *Transport) Start() error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if t.config.SessionID == "" {
		return fmt.Errorf("yatelemost: SessionID is required")
	}

	// Step 1: create or reuse conference.
	if t.config.ServerMode || t.config.ConferenceURL == "" {
		log.Printf("yatelemost: creating Telemost conference...")
		conf, err := CreateConference(ctx, t.config.SessionID)
		if err != nil {
			return fmt.Errorf("create conference: %w", err)
		}
		t.conf = conf
		log.Printf("yatelemost: conference created — share this URL with client: %s", conf.WssURL)
	} else {
		// Client mode: ConferenceURL is the WssURL the server shared.
		t.conf = &TeleMostConference{WssURL: t.config.ConferenceURL}
	}

	// Step 2: fetch TURN credentials and connect signaling WS.
	log.Printf("yatelemost: fetching TURN credentials from Telemost...")
	iceServers, err := FetchICEServers(ctx, t.config.SessionID, t.conf)
	if err != nil {
		return fmt.Errorf("fetch ICE servers: %w", err)
	}
	log.Printf("yatelemost: got %d TURN server(s) from Telemost", len(iceServers))

	// Step 3: open signaling WS to Telemost conference.
	headers := http.Header{
		"Origin":  []string{teleMostOrigin},
		"Cookie":  []string{"Session_id=" + t.config.SessionID},
	}
	ws, _, err := websocket.Dial(ctx, t.conf.WssURL, &websocket.DialOptions{HTTPHeader: headers})
	if err != nil {
		return fmt.Errorf("signaling dial: %w", err)
	}
	ws.SetReadLimit(512 * 1024)
	t.sigWS = ws

	// Step 4: build WebRTC API with collected TURN servers.
	if err := t.buildWebRTC(iceServers); err != nil {
		return fmt.Errorf("build webrtc: %w", err)
	}

	// Step 5: start signaling goroutine.
	go t.signalingLoop(context.Background())

	// Step 6: initiate offer (server) or wait for offer (client).
	if t.config.ServerMode {
		if err := t.createOffer(); err != nil {
			return fmt.Errorf("create offer: %w", err)
		}
	}

	return nil
}

func (t *Transport) Stop() error {
	t.stopOnce.Do(func() {
		close(t.stopCh)
		if t.sigWS != nil {
			t.sigWS.Close(websocket.StatusGoingAway, "stopped")
		}
		if t.pc != nil {
			t.pc.Close()
		}
	})
	return nil
}

// Dial waits for the WebRTC DataChannel to open and returns it as net.Conn.
func (t *Transport) Dial(ctx context.Context, _ string) (net.Conn, error) {
	select {
	case conn := <-t.connCh:
		return conn, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-t.stopCh:
		return nil, fmt.Errorf("yatelemost: stopped")
	}
}

func (t *Transport) Accept() (net.Conn, error) {
	select {
	case conn := <-t.connCh:
		return conn, nil
	case <-t.stopCh:
		return nil, fmt.Errorf("yatelemost: stopped")
	}
}

// buildWebRTC creates the pion WebRTC API and PeerConnection.
func (t *Transport) buildWebRTC(iceServers []ICEServerConfig) error {
	me := &webrtc.MediaEngine{}
	ir := &interceptor.Registry{}
	if err := webrtc.RegisterDefaultInterceptors(me, ir); err != nil {
		return err
	}
	t.api = webrtc.NewAPI(
		webrtc.WithMediaEngine(me),
		webrtc.WithInterceptorRegistry(ir),
	)

	policy := webrtc.ICETransportPolicyAll
	if t.config.ICEPolicy == "relay" {
		policy = webrtc.ICETransportPolicyRelay
	}

	var servers []webrtc.ICEServer
	for _, s := range iceServers {
		servers = append(servers, webrtc.ICEServer{
			URLs:       s.URLs,
			Username:   s.Username,
			Credential: s.Credential,
		})
	}

	pc, err := t.api.NewPeerConnection(webrtc.Configuration{
		ICEServers:         servers,
		ICETransportPolicy: policy,
	})
	if err != nil {
		return err
	}
	t.pc = pc

	// ICE candidates — send via signaling WS.
	pc.OnICECandidate(func(c *webrtc.ICECandidate) {
		if c == nil {
			return
		}
		msg := sigMsg{Type: sigCandidate, Candidate: c.ToJSON().Candidate}
		SendSignal(context.Background(), t.sigWS, msg)
	})

	// DataChannel (server creates, client receives).
	if t.config.ServerMode {
		dc, err := pc.CreateDataChannel("vpn", nil)
		if err != nil {
			return err
		}
		t.dc = dc
		t.hookDataChannel(dc)
	} else {
		pc.OnDataChannel(func(dc *webrtc.DataChannel) {
			t.dc = dc
			t.hookDataChannel(dc)
		})
	}

	return nil
}

// hookDataChannel wires the DataChannel to our net.Conn.
func (t *Transport) hookDataChannel(dc *webrtc.DataChannel) {
	dc.OnOpen(func() {
		conn := newDCConn(dc, t.config.BufferSize)
		select {
		case t.connCh <- conn:
		default:
		}
	})
}

// createOffer builds and sends the WebRTC SDP offer (server side).
func (t *Transport) createOffer() error {
	offer, err := t.pc.CreateOffer(nil)
	if err != nil {
		return err
	}
	if err := t.pc.SetLocalDescription(offer); err != nil {
		return err
	}
	return SendSignal(context.Background(), t.sigWS, sigMsg{
		Type: sigOffer,
		SDP:  offer.SDP,
	})
}

// signalingLoop reads signaling messages from the Telemost WS and drives the
// WebRTC handshake.  All non-VPN messages (Telemost protocol frames) are
// silently discarded.
func (t *Transport) signalingLoop(ctx context.Context) {
	for {
		data, err := ReadSignal(ctx, t.sigWS)
		if err != nil {
			select {
			case <-t.stopCh:
			default:
				log.Printf("yatelemost: signaling read error: %v", err)
			}
			return
		}

		var msg sigMsg
		if err := json.Unmarshal(data, &msg); err != nil {
			continue // Telemost protocol frame — ignore
		}

		switch msg.Type {
		case sigOffer: // client receives
			if err := t.pc.SetRemoteDescription(webrtc.SessionDescription{
				Type: webrtc.SDPTypeOffer, SDP: msg.SDP,
			}); err != nil {
				log.Printf("yatelemost: set remote offer: %v", err)
				continue
			}
			answer, err := t.pc.CreateAnswer(nil)
			if err != nil {
				log.Printf("yatelemost: create answer: %v", err)
				continue
			}
			if err := t.pc.SetLocalDescription(answer); err != nil {
				log.Printf("yatelemost: set local answer: %v", err)
				continue
			}
			SendSignal(ctx, t.sigWS, sigMsg{Type: sigAnswer, SDP: answer.SDP})

		case sigAnswer: // server receives
			if err := t.pc.SetRemoteDescription(webrtc.SessionDescription{
				Type: webrtc.SDPTypeAnswer, SDP: msg.SDP,
			}); err != nil {
				log.Printf("yatelemost: set remote answer: %v", err)
			}

		case sigCandidate:
			if atomic.LoadInt32(&t.remoteCandidatesDone) == 0 {
				t.pc.AddICECandidate(webrtc.ICECandidateInit{Candidate: msg.Candidate})
			}
		}
	}
}

// dcConn wraps a WebRTC DataChannel as a net.Conn.
type dcConn struct {
	dc      *webrtc.DataChannel
	readCh  chan []byte
	buf     []byte
	bufMu   sync.Mutex
}

func newDCConn(dc *webrtc.DataChannel, _ int) *dcConn {
	c := &dcConn{
		dc:     dc,
		readCh: make(chan []byte, 64),
	}
	dc.OnMessage(func(msg webrtc.DataChannelMessage) {
		cp := make([]byte, len(msg.Data))
		copy(cp, msg.Data)
		select {
		case c.readCh <- cp:
		default:
		}
	})
	return c
}

func (c *dcConn) Read(p []byte) (int, error) {
	c.bufMu.Lock()
	if len(c.buf) > 0 {
		n := copy(p, c.buf)
		c.buf = c.buf[n:]
		c.bufMu.Unlock()
		return n, nil
	}
	c.bufMu.Unlock()

	data, ok := <-c.readCh
	if !ok {
		return 0, fmt.Errorf("data channel closed")
	}
	n := copy(p, data)
	if n < len(data) {
		c.bufMu.Lock()
		c.buf = append(c.buf, data[n:]...)
		c.bufMu.Unlock()
	}
	return n, nil
}

func (c *dcConn) Write(p []byte) (int, error) {
	err := c.dc.Send(p)
	if err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *dcConn) Close() error                       { return c.dc.Close() }
func (c *dcConn) SetDeadline(t time.Time) error      { return nil }
func (c *dcConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *dcConn) SetWriteDeadline(t time.Time) error { return nil }
func (c *dcConn) LocalAddr() net.Addr                { return &net.TCPAddr{} }
func (c *dcConn) RemoteAddr() net.Addr               { return &net.TCPAddr{} }
