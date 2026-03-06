// Package tgbot provides a VPN tunnel transport over Telegram Bot API messages.
//
// Architecture (two-bot + shared group):
//
//   Both sides each own one Telegram bot.  Both bots are added to a shared private
//   supergroup.  Privacy mode MUST be disabled for both bots in @BotFather
//   (/setprivacy → Disabled), or both bots must be promoted to group admins.
//
//   Client bot (MyBotToken) posts WRP messages tagged "C<session>:" to the group.
//   Server bot (MyBotToken) posts WRP messages tagged "S<session>:" to the group.
//   Each side polls its OWN bot's getUpdates independently — no competing offsets.
//   Each side ignores messages it sent itself (prefix mismatch).
//
//   All traffic goes to api.telegram.org (globally reachable, not blocked in Russia).
//   No own IP required on the client side.
//
// Setup:
//   1. Create two Telegram bots via @BotFather, get their tokens.
//   2. Create a private supergroup, add both bots, disable their privacy mode.
//   3. Note the group chat_id (e.g. send /start to the group, inspect getUpdates).
//   4. Configure both VPN sides with their own MyBotToken and the shared GroupChatID.
//   5. Set a shared SessionID (any random string; identifies this tunnel in the group).
//
// WRP message format:
//   "WRP:<dir><sessionID>:<base64url(4B_seq_BE | 1B_total | 1B_chunk | payload)>"
//   dir = "C" (client→server) or "S" (server→client)
//
// Throughput: ~30 msg/s × 2000 B/msg ≈ 60 KB/s sustained.
package tgbot

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"whispera/internal/core/base"
	"whispera/internal/core/interfaces"
	"whispera/internal/core/registry"
	"whispera/internal/logger"
)

func init() {
	registry.GlobalFactoryRegistry.RegisterFactory(ModuleName, Factory)
}

var log = logger.Module("tgbot")

const (
	ModuleName    = "transport.tgbot"
	ModuleVersion = "1.0.0"

	tgAPIBase = "https://api.telegram.org/bot"

	msgPrefix = "WRP:"
	maxChunk  = 2000 // bytes before encoding
)

// Config holds Telegram Bot relay settings.
type Config struct {
	// MyBotToken is this side's Telegram bot token (required).
	// Used to send messages to the group AND to poll getUpdates for incoming messages.
	MyBotToken string

	// GroupChatID is the shared Telegram supergroup where both bots communicate.
	GroupChatID int64

	// SessionID uniquely identifies this tunnel within the shared group.
	// Multiple concurrent tunnels can share the same group with different SessionIDs.
	// If empty, a random ID is generated at startup.
	SessionID string

	// ServerMode: true = server (listens for incoming connections from the group).
	//             false = client (dials outbound connection through the group).
	ServerMode bool
}

func (c *Config) Validate() error {
	if c.MyBotToken == "" {
		return fmt.Errorf("tgbot: MyBotToken required")
	}
	if c.GroupChatID == 0 {
		return fmt.Errorf("tgbot: GroupChatID required")
	}
	return nil
}

// dirPrefix returns the message direction prefix for this side.
// Server sends "S", client sends "C".  Each side accepts only the opposite direction.
func (c *Config) dirPrefix() string {
	if c.ServerMode {
		return "S"
	}
	return "C"
}

// acceptPrefix is the direction prefix this side expects to receive.
func (c *Config) acceptPrefix() string {
	if c.ServerMode {
		return "C"
	}
	return "S"
}

// Transport implements interfaces.Transport over Telegram Bot messages.
type Transport struct {
	*base.Module
	cfg       *Config
	sessionID string // resolved (generated if cfg.SessionID was empty)
	hc        *http.Client
	offset    atomic.Int64 // next getUpdates offset
	stopChan  chan struct{}
	accept    chan net.Conn
	stopped   atomic.Bool
}

func New(cfg *Config) (*Transport, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	sid := cfg.SessionID
	if sid == "" {
		b := make([]byte, 6)
		rand.Read(b) //nolint:errcheck
		sid = base64.RawURLEncoding.EncodeToString(b)
	}
	t := &Transport{
		Module:    base.NewModule(ModuleName, ModuleVersion, nil),
		cfg:       cfg,
		sessionID: sid,
		hc:        &http.Client{Timeout: 35 * time.Second},
		stopChan:  make(chan struct{}),
		accept:    make(chan net.Conn, 32),
	}
	return t, nil
}

func (t *Transport) Type() interfaces.TransportType { return interfaces.TransportTGBot }
func (t *Transport) Listen(addr string) error        { return nil }

func (t *Transport) Start() error {
	if err := t.Module.Start(); err != nil {
		return err
	}
	if t.cfg.ServerMode {
		go t.listenLoop()
	}
	t.SetHealthy(true, fmt.Sprintf("session=%s group=%d", t.sessionID, t.cfg.GroupChatID))
	return nil
}

func (t *Transport) Stop() error {
	if t.stopped.CompareAndSwap(false, true) {
		close(t.stopChan)
	}
	return t.Module.Stop()
}

func (t *Transport) Close() error { return t.Stop() }

func (t *Transport) Accept() (net.Conn, error) {
	select {
	case conn, ok := <-t.accept:
		if !ok {
			return nil, io.EOF
		}
		return conn, nil
	case <-t.stopChan:
		return nil, io.EOF
	}
}

// Dial opens a client-side connection through the shared Telegram group.
func (t *Transport) Dial(ctx context.Context, addr string) (net.Conn, error) {
	conn := newBotConn(t)
	ctx2, cancel := context.WithCancel(ctx)
	go func() {
		select {
		case <-t.stopChan:
			cancel()
		case <-ctx2.Done():
		}
	}()
	go conn.pollLoop(ctx2, cancel)
	return conn, nil
}

// ─── Server listen loop ──────────────────────────────────────────────────────

func (t *Transport) listenLoop() {
	// conns maps a stable sender key (senderID:sessionID) to its botConn.
	conns := make(map[string]*botConn)

	for {
		select {
		case <-t.stopChan:
			return
		default:
		}

		msgs, err := t.getUpdates(25)
		if err != nil {
			log.Warn("[tgbot] getUpdates error: %v", err)
			time.Sleep(2 * time.Second)
			continue
		}

		for _, m := range msgs {
			key := strconv.FormatInt(m.senderID, 10) + ":" + m.sessionID
			conn, exists := conns[key]
			if !exists {
				conn = newBotConn(t)
				conns[key] = conn
				select {
				case t.accept <- conn:
					log.Info("[tgbot] new client connection key=%s", key)
				case <-t.stopChan:
					return
				}
			}
			conn.deliver(m.text)
		}
	}
}

// ─── Telegram API ────────────────────────────────────────────────────────────

type incomingMsg struct {
	senderID  int64
	sessionID string
	text      string // full WRP message text
}

// getUpdates polls Telegram long-poll, advances offset, returns WRP messages
// from the shared group chat that match this side's accept direction.
func (t *Transport) getUpdates(timeout int) ([]incomingMsg, error) {
	offset := t.offset.Load()
	reqURL := fmt.Sprintf("%s%s/getUpdates?timeout=%d&offset=%d&allowed_updates=[\"message\"]",
		tgAPIBase, url.PathEscape(t.cfg.MyBotToken), timeout, offset)

	resp, err := t.hc.Get(reqURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result struct {
		OK     bool `json:"ok"`
		Result []struct {
			UpdateID int64 `json:"update_id"`
			Message  *struct {
				MessageID int64 `json:"message_id"`
				From      struct {
					ID    int64 `json:"id"`
					IsBot bool  `json:"is_bot"`
				} `json:"from"`
				Chat struct {
					ID int64 `json:"id"`
				} `json:"chat"`
				Text string `json:"text"`
			} `json:"message"`
		} `json:"result"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	if !result.OK {
		return nil, fmt.Errorf("tgbot: getUpdates returned ok=false")
	}

	acceptDir := t.cfg.acceptPrefix()
	fullPrefix := msgPrefix + acceptDir

	var msgs []incomingMsg
	for _, upd := range result.Result {
		// Always advance offset past processed updates.
		if upd.UpdateID >= t.offset.Load() {
			t.offset.Store(upd.UpdateID + 1)
		}

		m := upd.Message
		if m == nil {
			continue
		}
		if m.Chat.ID != t.cfg.GroupChatID {
			continue // not from our group
		}
		if !strings.HasPrefix(m.Text, fullPrefix) {
			continue // wrong direction or not WRP
		}

		// Extract sessionID from prefix: WRP:<dir><sessionID>:<data>
		rest := m.Text[len(fullPrefix):] // "<sessionID>:<data>"
		colonIdx := strings.IndexByte(rest, ':')
		if colonIdx < 0 {
			continue
		}
		sid := rest[:colonIdx]
		if sid != t.sessionID {
			continue // different tunnel session in the same group
		}

		msgs = append(msgs, incomingMsg{
			senderID:  m.From.ID,
			sessionID: sid,
			text:      m.Text,
		})
	}
	return msgs, nil
}

// sendMessage sends a WRP message to the shared group chat.
func (t *Transport) sendMessage(text string) error {
	params := url.Values{
		"chat_id":              {strconv.FormatInt(t.cfg.GroupChatID, 10)},
		"text":                 {text},
		"disable_notification": {"true"},
	}
	resp, err := t.hc.PostForm(tgAPIBase+url.PathEscape(t.cfg.MyBotToken)+"/sendMessage", params)
	if err != nil {
		return fmt.Errorf("tgbot send: %w", err)
	}
	defer resp.Body.Close()

	var result struct {
		OK          bool   `json:"ok"`
		Description string `json:"description"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fmt.Errorf("tgbot send decode: %w", err)
	}
	if !result.OK {
		return fmt.Errorf("tgbot API error: %s", result.Description)
	}
	return nil
}

// ─── WRP encoding ────────────────────────────────────────────────────────────

// encodeMsg builds: "WRP:<dir><sessionID>:<base64url(seq|total|chunk|payload)>"
func (t *Transport) encodeMsg(seq uint32, total, chunk int, payload []byte) string {
	hdr := make([]byte, 6+len(payload))
	binary.BigEndian.PutUint32(hdr[0:4], seq)
	hdr[4] = byte(total)
	hdr[5] = byte(chunk)
	copy(hdr[6:], payload)
	return msgPrefix + t.cfg.dirPrefix() + t.sessionID + ":" +
		base64.RawURLEncoding.EncodeToString(hdr)
}

// decodeMsg parses a WRP message (after direction+sessionID prefix).
// Caller must pass the text with the full WRP prefix still intact.
func decodeMsg(text string) (seq uint32, total, chunk int, payload []byte, err error) {
	// Find the second ':' (after WRP:<dir><sid>:)
	colonIdx := strings.IndexByte(text[len(msgPrefix)+1:], ':') // skip "WRP:X"
	if colonIdx < 0 {
		return 0, 0, 0, nil, fmt.Errorf("malformed WRP message")
	}
	dataB64 := text[len(msgPrefix)+1+colonIdx+1:] // everything after second ':'

	raw, err := base64.RawURLEncoding.DecodeString(dataB64)
	if err != nil {
		return 0, 0, 0, nil, fmt.Errorf("base64: %w", err)
	}
	if len(raw) < 6 {
		return 0, 0, 0, nil, fmt.Errorf("too short")
	}
	seq = binary.BigEndian.Uint32(raw[0:4])
	total = int(raw[4])
	chunk = int(raw[5])
	payload = raw[6:]
	return seq, total, chunk, payload, nil
}

// ─── botConn: net.Conn over Telegram messages ────────────────────────────────

type botConn struct {
	transport *Transport
	recvMu    sync.Mutex
	recvBuf   []byte
	recvCond  *sync.Cond

	asmMu  sync.Mutex
	frames map[uint32]*frameAsm

	sendSeq   atomic.Uint32
	closed    atomic.Bool
	closeOnce sync.Once
	done      chan struct{}

	readDeadline  atomic.Value
	writeDeadline atomic.Value
}

type frameAsm struct {
	total  int
	chunks map[int][]byte
}

func newBotConn(t *Transport) *botConn {
	c := &botConn{
		transport: t,
		frames:    make(map[uint32]*frameAsm),
		done:      make(chan struct{}),
	}
	c.recvCond = sync.NewCond(&c.recvMu)
	return c
}

func (c *botConn) Write(data []byte) (int, error) {
	if c.closed.Load() {
		return 0, net.ErrClosed
	}
	total := len(data)
	seq := c.sendSeq.Add(1)

	var chunks [][]byte
	for len(data) > 0 {
		n := maxChunk
		if n > len(data) {
			n = len(data)
		}
		chunks = append(chunks, data[:n])
		data = data[n:]
	}
	if len(chunks) == 0 {
		chunks = [][]byte{{}}
	}
	if len(chunks) > 255 {
		return 0, fmt.Errorf("tgbot: write too large (%d bytes)", total)
	}

	if dl, ok := c.writeDeadline.Load().(time.Time); ok && !dl.IsZero() && time.Now().After(dl) {
		return 0, &net.OpError{Op: "write", Net: "tgbot", Err: fmt.Errorf("i/o timeout")}
	}

	for i, chunk := range chunks {
		msg := c.transport.encodeMsg(seq, len(chunks), i, chunk)
		if err := c.transport.sendMessage(msg); err != nil {
			return 0, err
		}
	}
	return total, nil
}

func (c *botConn) Read(buf []byte) (int, error) {
	c.recvMu.Lock()
	defer c.recvMu.Unlock()

	for len(c.recvBuf) == 0 {
		if c.closed.Load() {
			return 0, net.ErrClosed
		}
		if dl, ok := c.readDeadline.Load().(time.Time); ok && !dl.IsZero() {
			remaining := time.Until(dl)
			if remaining <= 0 {
				return 0, &net.OpError{Op: "read", Net: "tgbot", Err: fmt.Errorf("i/o timeout")}
			}
			go func() { time.Sleep(remaining); c.recvCond.Broadcast() }()
		}
		c.recvCond.Wait()
		if dl, ok := c.readDeadline.Load().(time.Time); ok && !dl.IsZero() && time.Now().After(dl) {
			return 0, &net.OpError{Op: "read", Net: "tgbot", Err: fmt.Errorf("i/o timeout")}
		}
	}
	n := copy(buf, c.recvBuf)
	c.recvBuf = c.recvBuf[n:]
	return n, nil
}

func (c *botConn) Close() error {
	c.closeOnce.Do(func() {
		c.closed.Store(true)
		c.recvCond.Broadcast()
		close(c.done)
	})
	return nil
}

func (c *botConn) deliver(text string) {
	seq, total, chunkIdx, payload, err := decodeMsg(text)
	if err != nil {
		log.Warn("[tgbot] decode: %v", err)
		return
	}

	c.asmMu.Lock()
	asm, exists := c.frames[seq]
	if !exists {
		asm = &frameAsm{total: total, chunks: make(map[int][]byte)}
		c.frames[seq] = asm
	}
	asm.chunks[chunkIdx] = payload
	if len(asm.chunks) < asm.total {
		c.asmMu.Unlock()
		return
	}
	frame := make([]byte, 0, asm.total*maxChunk)
	for i := 0; i < asm.total; i++ {
		frame = append(frame, asm.chunks[i]...)
	}
	delete(c.frames, seq)
	c.asmMu.Unlock()

	c.recvMu.Lock()
	c.recvBuf = append(c.recvBuf, frame...)
	c.recvCond.Signal()
	c.recvMu.Unlock()
}

// pollLoop runs on the client side, receiving messages via getUpdates.
func (c *botConn) pollLoop(ctx context.Context, cancel context.CancelFunc) {
	defer func() {
		cancel()
		c.Close()
	}()
	for {
		select {
		case <-ctx.Done():
			return
		case <-c.done:
			return
		case <-c.transport.stopChan:
			return
		default:
		}

		msgs, err := c.transport.getUpdates(25)
		if err != nil {
			log.Warn("[tgbot] client poll error: %v", err)
			time.Sleep(2 * time.Second)
			continue
		}
		for _, m := range msgs {
			c.deliver(m.text)
		}
	}
}

func (c *botConn) LocalAddr() net.Addr  { return &tgAddr{"local"} }
func (c *botConn) RemoteAddr() net.Addr { return &tgAddr{fmt.Sprintf("tg:group:%d", c.transport.cfg.GroupChatID)} }

func (c *botConn) SetDeadline(t time.Time) error {
	c.readDeadline.Store(t)
	c.writeDeadline.Store(t)
	c.recvCond.Broadcast()
	return nil
}
func (c *botConn) SetReadDeadline(t time.Time) error {
	c.readDeadline.Store(t)
	c.recvCond.Broadcast()
	return nil
}
func (c *botConn) SetWriteDeadline(t time.Time) error { c.writeDeadline.Store(t); return nil }

type tgAddr struct{ id string }

func (a *tgAddr) Network() string { return "tgbot" }
func (a *tgAddr) String() string  { return a.id }

// ─── Factory ─────────────────────────────────────────────────────────────────

func Factory(cfg interface{}) (interfaces.Module, error) {
	if c, ok := cfg.(*Config); ok {
		return New(c)
	}
	return nil, fmt.Errorf("tgbot: invalid config type")
}

var _ interfaces.Transport = (*Transport)(nil)
