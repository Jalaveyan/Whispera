package grpc

import (
	"context"
	"fmt"
	"github.com/nekoskin/whispera/common/log"
	"github.com/nekoskin/whispera/common/runtime/base"
	"github.com/nekoskin/whispera/common/runtime/events"
	"github.com/nekoskin/whispera/common/runtime/interfaces"
	"io"
	"net"
	"runtime/debug"
	"sync"
	"sync/atomic"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

var log = logger.Module("transport_grpc")

func recoveryStreamInterceptor(srv interface{}, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) (err error) {
	defer func() {
		if r := recover(); r != nil {
			log.Error("PANIC in gRPC stream handler %s: %v\n%s", info.FullMethod, r, debug.Stack())
			err = fmt.Errorf("internal error")
		}
	}()
	return handler(srv, ss)
}

const (
	ModuleName    = "transport.grpc"
	ModuleVersion = "1.0.0"
)

type Config struct {
	ListenAddr       string
	ExtraListenAddrs []string
	ServiceName      string
	UseTLS           bool
	CertFile         string
	KeyFile          string
	ServerName       string
	MaxConns         int
	MaxStreams       int
}

func DefaultConfig() *Config {
	return &Config{
		ListenAddr:  ":8443",
		ServiceName: "TunnelService",
		UseTLS:      true,
		MaxConns:    10000,
		MaxStreams:  100,
	}
}

func (c *Config) Validate() error {
	if c.ListenAddr == "" {
		return fmt.Errorf("listen address is required")
	}
	if c.ServiceName == "" {
		c.ServiceName = "TunnelService"
	}
	return nil
}

type Transport struct {
	*base.Module
	config     *Config
	server     *grpc.Server
	mu         sync.RWMutex
	acceptChan chan net.Conn
	stopChan   chan struct{}
	stopOnce   sync.Once

	connCount   int64
	bytesRx     uint64
	bytesTx     uint64
	activeConns int64
}

func New(cfg *Config) (*Transport, error) {
	if cfg == nil {
		cfg = DefaultConfig()
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	t := &Transport{
		Module:     base.NewModule(ModuleName, ModuleVersion, nil),
		config:     cfg,
		acceptChan: make(chan net.Conn, 1000),
		stopChan:   make(chan struct{}),
	}

	return t, nil
}

func (t *Transport) Init(ctx context.Context, cfg interfaces.ModuleConfig) error {
	if err := t.Module.Init(ctx, cfg); err != nil {
		return err
	}

	if grpcCfg, ok := cfg.(*Config); ok {
		t.config = grpcCfg
	}

	return nil
}

func (t *Transport) Start() error {
	if err := t.Module.Start(); err != nil {
		return err
	}

	var opts []grpc.ServerOption

	if t.config.UseTLS && t.config.CertFile != "" && t.config.KeyFile != "" {
		creds, err := credentials.NewServerTLSFromFile(t.config.CertFile, t.config.KeyFile)
		if err != nil {
			return fmt.Errorf("failed to load TLS credentials: %w", err)
		}
		opts = append(opts, grpc.Creds(creds))
	}

	opts = append(opts, grpc.MaxConcurrentStreams(uint32(t.config.MaxStreams)))
	opts = append(opts, grpc.StreamInterceptor(recoveryStreamInterceptor))

	t.server = grpc.NewServer(opts...)

	RegisterTunnelServiceServer(t.server, &tunnelServer{transport: t})

	listener, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", t.config.ListenAddr)
	if err != nil {
		return fmt.Errorf("failed to listen: %w", err)
	}

	go func() {
		defer func() {
			if r := recover(); r != nil {
				log.Error("PANIC in gRPC Serve: %v\n%s", r, debug.Stack())
			}
		}()
		if err := t.server.Serve(listener); err != nil {
			t.SetHealthy(false, fmt.Sprintf("server error: %v", err))
		}
	}()

	for _, extraAddr := range t.config.ExtraListenAddrs {
		extraAddr := extraAddr
		extraListener, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", extraAddr)
		if err != nil {
			log.Error("gRPC: failed to listen on extra addr %s: %v", extraAddr, err)
			continue
		}
		go func() {
			defer func() {
				if r := recover(); r != nil {
					log.Error("PANIC in gRPC extra Serve(%s): %v\n%s", extraAddr, r, debug.Stack())
				}
			}()
			t.server.Serve(extraListener)
		}()
	}

	t.SetHealthy(true, fmt.Sprintf("listening on %s", t.config.ListenAddr))
	t.PublishEvent(events.EventTypeModuleStarted, map[string]interface{}{
		"listen_addr":  t.config.ListenAddr,
		"service_name": t.config.ServiceName,
	})

	return nil
}

func (t *Transport) Stop() error {
	t.mu.Lock()
	if t.server != nil {
		t.server.GracefulStop()
		t.server = nil
	}
	t.mu.Unlock()

	t.stopOnce.Do(func() { close(t.stopChan) })

	t.PublishEvent(events.EventTypeModuleStopped, nil)
	return t.Module.Stop()
}

func (t *Transport) Type() interfaces.TransportType {
	return interfaces.TransportType("grpc")
}

func (t *Transport) Dial(ctx context.Context, addr string) (net.Conn, error) {
	var opts []grpc.DialOption

	if t.config.UseTLS {
		creds := credentials.NewClientTLSFromCert(nil, t.config.ServerName)
		opts = append(opts, grpc.WithTransportCredentials(creds))
	} else {
		opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	}

	conn, err := grpc.NewClient(addr, opts...)
	if err != nil {
		return nil, err
	}

	client := NewTunnelServiceClient(conn)

	stream, err := client.Tunnel(ctx)
	if err != nil {
		conn.Close()
		return nil, err
	}

	atomic.AddInt64(&t.connCount, 1)
	atomic.AddInt64(&t.activeConns, 1)

	return &grpcConn{
		grpcStreamConn: grpcStreamConn{stream: stream, transport: t},
		client:         conn,
	}, nil
}

func (t *Transport) Accept() (net.Conn, error) {
	select {
	case conn := <-t.acceptChan:
		return conn, nil
	case <-t.stopChan:
		return nil, fmt.Errorf("transport stopped")
	}
}

func (t *Transport) Close() error {
	return t.Stop()
}

func (t *Transport) HealthCheck() interfaces.HealthStatus {
	status := t.Module.HealthCheck()
	status.Details["conn_count"] = atomic.LoadInt64(&t.connCount)
	status.Details["active_conns"] = atomic.LoadInt64(&t.activeConns)
	status.Details["bytes_rx"] = atomic.LoadUint64(&t.bytesRx)
	status.Details["bytes_tx"] = atomic.LoadUint64(&t.bytesTx)
	return status
}

type TunnelServiceServer interface {
	Tunnel(TunnelService_TunnelServer) error
}

type TunnelServiceClient interface {
	Tunnel(ctx context.Context, opts ...grpc.CallOption) (TunnelService_TunnelClient, error)
}

type TunnelService_TunnelServer interface {
	Send(*TunnelData) error
	Recv() (*TunnelData, error)
	grpc.ServerStream
}

type TunnelService_TunnelClient interface {
	Send(*TunnelData) error
	Recv() (*TunnelData, error)
	grpc.ClientStream
}

type TunnelData = wrapperspb.BytesValue

func RegisterTunnelServiceServer(s *grpc.Server, srv TunnelServiceServer) {
	s.RegisterService(&_TunnelService_serviceDesc, srv)
}

func NewTunnelServiceClient(cc grpc.ClientConnInterface) TunnelServiceClient {
	return &tunnelServiceClient{cc}
}

type tunnelServiceClient struct {
	cc grpc.ClientConnInterface
}

func (c *tunnelServiceClient) Tunnel(ctx context.Context, opts ...grpc.CallOption) (TunnelService_TunnelClient, error) {
	stream, err := c.cc.NewStream(ctx, &_TunnelService_serviceDesc.Streams[0], "/tunnel.TunnelService/Tunnel", opts...)
	if err != nil {
		return nil, err
	}
	return &tunnelServiceTunnelClient{stream}, nil
}

type tunnelServiceTunnelClient struct {
	grpc.ClientStream
}

func (x *tunnelServiceTunnelClient) Send(m *TunnelData) error {
	return x.ClientStream.SendMsg(m)
}

func (x *tunnelServiceTunnelClient) Recv() (*TunnelData, error) {
	m := new(TunnelData)
	if err := x.ClientStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

var _TunnelService_serviceDesc = grpc.ServiceDesc{
	ServiceName: "tunnel.TunnelService",
	HandlerType: (*TunnelServiceServer)(nil),
	Methods:     []grpc.MethodDesc{},
	Streams: []grpc.StreamDesc{
		{
			StreamName:    "Tunnel",
			Handler:       _TunnelService_Tunnel_Handler,
			ServerStreams: true,
			ClientStreams: true,
		},
	},
	Metadata: "tunnel.proto",
}

func _TunnelService_Tunnel_Handler(srv interface{}, stream grpc.ServerStream) error {
	return srv.(TunnelServiceServer).Tunnel(&tunnelServiceTunnelServer{stream})
}

type tunnelServiceTunnelServer struct {
	grpc.ServerStream
}

func (x *tunnelServiceTunnelServer) Send(m *TunnelData) error {
	return x.ServerStream.SendMsg(m)
}

func (x *tunnelServiceTunnelServer) Recv() (*TunnelData, error) {
	m := new(TunnelData)
	if err := x.ServerStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

type tunnelServer struct {
	transport *Transport
	UnimplementedTunnelServiceServer
}

type UnimplementedTunnelServiceServer struct{}

func (UnimplementedTunnelServiceServer) Tunnel(TunnelService_TunnelServer) error {
	return fmt.Errorf("Tunnel not implemented")
}

func (s *tunnelServer) Tunnel(stream TunnelService_TunnelServer) error {
	atomic.AddInt64(&s.transport.connCount, 1)
	atomic.AddInt64(&s.transport.activeConns, 1)

	conn := &grpcServerConn{
		grpcStreamConn: grpcStreamConn{stream: stream, transport: s.transport},
		closeChan:      make(chan struct{}),
	}

	select {
	case s.transport.acceptChan <- conn:
	case <-s.transport.stopChan:
		atomic.AddInt64(&s.transport.activeConns, -1)
		return fmt.Errorf("transport stopped")
	default:
		atomic.AddInt64(&s.transport.activeConns, -1)
		return fmt.Errorf("accept channel full")
	}

	<-conn.closeChan
	return nil
}

type grpcStream interface {
	Send(*TunnelData) error
	Recv() (*TunnelData, error)
}

type grpcStreamConn struct {
	stream    grpcStream
	transport *Transport
	readBuf   []byte
	closed    int32
	mu        sync.Mutex
}

func (c *grpcStreamConn) Read(b []byte) (n int, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if len(c.readBuf) > 0 {
		n = copy(b, c.readBuf)
		c.readBuf = c.readBuf[n:]
		atomic.AddUint64(&c.transport.bytesRx, uint64(n))
		return n, nil
	}

	data, err := c.stream.Recv()
	if err != nil {
		return 0, err
	}

	n = copy(b, data.Value)
	if n < len(data.Value) {
		c.readBuf = data.Value[n:]
	}
	atomic.AddUint64(&c.transport.bytesRx, uint64(n))
	return n, nil
}

func (c *grpcStreamConn) Write(b []byte) (n int, err error) {
	if err = c.stream.Send(&TunnelData{Value: b}); err != nil {
		return 0, err
	}
	atomic.AddUint64(&c.transport.bytesTx, uint64(len(b)))
	return len(b), nil
}

func (c *grpcStreamConn) closeOnce() bool {
	if !atomic.CompareAndSwapInt32(&c.closed, 0, 1) {
		return false
	}
	atomic.AddInt64(&c.transport.activeConns, -1)
	return true
}

func (c *grpcStreamConn) LocalAddr() net.Addr                { return &net.TCPAddr{} }
func (c *grpcStreamConn) RemoteAddr() net.Addr               { return &net.TCPAddr{} }
func (c *grpcStreamConn) SetDeadline(t time.Time) error      { return nil }
func (c *grpcStreamConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *grpcStreamConn) SetWriteDeadline(t time.Time) error { return nil }

type grpcConn struct {
	grpcStreamConn
	client *grpc.ClientConn
}

func (c *grpcConn) Close() error {
	if c.closeOnce() {
		c.client.Close()
	}
	return nil
}

type grpcServerConn struct {
	grpcStreamConn
	closeChan chan struct{}
}

func (c *grpcServerConn) Close() error {
	if c.closeOnce() && c.closeChan != nil {
		close(c.closeChan)
	}
	return nil
}

var _ = (metadata.MD)(nil)
var _ = (io.Reader)(nil)
