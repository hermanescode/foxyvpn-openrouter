package vpn

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/http2"
)

const (
	defaultTunnelWriteBufSize    = 1 << 20
	upstreamKeepAliveInterval    = 10 * time.Second
	upstreamKeepAlivePingTimeout = 5 * time.Second
)

var (
	ErrProxyHTTP2Unavailable = errors.New("upstream proxy did not negotiate HTTP/2")
	ErrNoUsableProxySession  = errors.New("no usable upstream proxy session")
)

type TunnelOpener interface {
	OpenTunnel(authority string) (net.Conn, error)
	Close() error
}

type H2ProxySession struct {
	raw           *tls.Conn
	cc            *http2.ClientConn
	proxyHost     string
	token         string
	timeout       time.Duration
	tokenMu       sync.RWMutex
	closeOnce     sync.Once
	closeErr      error
	alive         atomic.Bool
	stopKeepAlive context.CancelFunc
}

func NewH2ProxySession(proxyURL *url.URL, token string, timeout time.Duration) (*H2ProxySession, error) {
	proxyHost := proxyURL.Host
	if proxyURL.Port() == "" {
		proxyHost = proxyURL.Hostname() + ":443"
	}

	dialer := &net.Dialer{Timeout: timeout}
	proxyTLS, err := tls.DialWithDialer(dialer, "tcp", proxyHost, &tls.Config{
		ServerName: proxyURL.Hostname(),
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"h2"},
	})
	if err != nil {
		return nil, err
	}

	if proxyTLS.ConnectionState().NegotiatedProtocol != "h2" {
		_ = proxyTLS.Close()
		return nil, ErrProxyHTTP2Unavailable
	}

	transport := &http2.Transport{
		ReadIdleTimeout:  30 * time.Second,
		PingTimeout:      15 * time.Second,
		WriteByteTimeout: 30 * time.Second,
	}
	cc, err := transport.NewClientConn(proxyTLS)
	if err != nil {
		_ = proxyTLS.Close()
		return nil, err
	}

	ctx, cancel := context.WithCancel(context.Background())
	session := &H2ProxySession{
		raw:           proxyTLS,
		cc:            cc,
		proxyHost:     proxyHost,
		token:         token,
		timeout:       timeout,
		stopKeepAlive: cancel,
	}
	session.alive.Store(true)
	go session.runKeepAlive(ctx)

	return session, nil
}

func (s *H2ProxySession) runKeepAlive(ctx context.Context) {
	ticker := time.NewTicker(upstreamKeepAliveInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			pingCtx, cancel := context.WithTimeout(ctx, upstreamKeepAlivePingTimeout)
			err := s.cc.Ping(pingCtx)
			cancel()
			if err != nil {
				s.alive.Store(false)
				return
			}
		}
	}
}

func (s *H2ProxySession) IsAlive() bool {
	if !s.alive.Load() {
		return false
	}
	return s.cc.CanTakeNewRequest()
}

func (s *H2ProxySession) OpenTunnel(authority string) (net.Conn, error) {
	reqBody := newTunnelWriteBuffer(defaultTunnelWriteBufSize)
	ctx, cancel := context.WithTimeout(context.Background(), s.timeout)

	req, err := http.NewRequestWithContext(ctx, http.MethodConnect, "http://"+authority, reqBody)
	if err != nil {
		cancel()
		reqBody.failRead(io.ErrClosedPipe)
		return nil, err
	}
	req.Host = authority
	req.URL.Host = s.proxyHost
	req.Header.Set("Proxy-Authorization", "Bearer "+s.bearerToken())

	resp, err := s.cc.RoundTrip(req)
	if err != nil {
		cancel()
		reqBody.failRead(io.ErrClosedPipe)
		return nil, err
	}

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		cancel()
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		_ = resp.Body.Close()
		reqBody.failRead(io.ErrClosedPipe)
		return nil, fmt.Errorf("CONNECT rejected status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	return &TunnelConn{
		reader:  resp.Body,
		writer:  reqBody,
		reqBody: reqBody,
		cancel:  cancel,
	}, nil
}

func (s *H2ProxySession) bearerToken() string {
	s.tokenMu.RLock()
	defer s.tokenMu.RUnlock()
	return s.token
}

func (s *H2ProxySession) UpdateToken(token string) {
	s.tokenMu.Lock()
	s.token = token
	s.tokenMu.Unlock()
}

func (s *H2ProxySession) Close() error {
	s.closeOnce.Do(func() {
		s.alive.Store(false)
		if s.stopKeepAlive != nil {
			s.stopKeepAlive()
		}
		if s.cc != nil {
			s.closeErr = s.cc.Close()
		}
		if s.raw != nil {
			_ = s.raw.Close()
		}
	})
	return s.closeErr
}

type TunnelConn struct {
	reader    io.ReadCloser
	writer    *tunnelWriteBuffer
	reqBody   *tunnelWriteBuffer
	cancel    context.CancelFunc
	closeOnce sync.Once
}

func (c *TunnelConn) Read(p []byte) (int, error)  { return c.reader.Read(p) }
func (c *TunnelConn) Write(p []byte) (int, error) { return c.writer.Write(p) }

func (c *TunnelConn) Close() error {
	var err error
	c.closeOnce.Do(func() {
		if c.writer != nil {
			_ = c.writer.Close()
		}
		if c.reader != nil {
			err = c.reader.Close()
		}
		if c.reqBody != nil {
			c.reqBody.failRead(io.ErrClosedPipe)
		}
		if c.cancel != nil {
			c.cancel()
		}
	})
	return err
}

func (c *TunnelConn) LocalAddr() net.Addr                { return dummyAddr("local") }
func (c *TunnelConn) RemoteAddr() net.Addr               { return dummyAddr("remote") }
func (c *TunnelConn) SetDeadline(t time.Time) error      { return nil }
func (c *TunnelConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *TunnelConn) SetWriteDeadline(t time.Time) error { return nil }

type dummyAddr string

func (a dummyAddr) Network() string { return "tcp" }
func (a dummyAddr) String() string  { return string(a) }

type tunnelWriteBuffer struct {
	mu       sync.Mutex
	notEmpty *sync.Cond
	notFull  *sync.Cond
	buf      []byte
	n        int
	off      int
	closed   bool
	readErr  error
}

func newTunnelWriteBuffer(size int) *tunnelWriteBuffer {
	if size < 1 {
		size = defaultTunnelWriteBufSize
	}
	b := &tunnelWriteBuffer{buf: make([]byte, size)}
	b.notEmpty = sync.NewCond(&b.mu)
	b.notFull = sync.NewCond(&b.mu)
	return b
}

func (b *tunnelWriteBuffer) Read(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	for b.n == 0 && b.readErr == nil && !b.closed {
		b.notEmpty.Wait()
	}
	if b.n == 0 {
		if b.readErr != nil {
			return 0, b.readErr
		}
		return 0, io.EOF
	}

	end := b.off + b.n
	if end > len(b.buf) {
		end = len(b.buf)
	}
	n := copy(p, b.buf[b.off:end])
	b.off = (b.off + n) % len(b.buf)
	b.n -= n
	b.notFull.Broadcast()
	return n, nil
}

func (b *tunnelWriteBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	total := 0
	for len(p) > 0 {
		for b.n == len(b.buf) && b.readErr == nil && !b.closed {
			b.notFull.Wait()
		}
		if b.readErr != nil {
			return total, b.readErr
		}
		if b.closed {
			return total, io.ErrClosedPipe
		}

		space := len(b.buf) - b.n
		head := (b.off + b.n) % len(b.buf)
		writable := len(b.buf) - head
		if space < writable {
			writable = space
		}
		if writable > len(p) {
			writable = len(p)
		}
		copy(b.buf[head:], p[:writable])
		b.n += writable
		p = p[writable:]
		total += writable
		b.notEmpty.Broadcast()
	}
	return total, nil
}

func (b *tunnelWriteBuffer) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return nil
	}
	b.closed = true
	b.notEmpty.Broadcast()
	b.notFull.Broadcast()
	return nil
}

func (b *tunnelWriteBuffer) failRead(err error) {
	b.mu.Lock()
	if b.readErr == nil {
		b.readErr = err
	}
	b.closed = true
	b.notEmpty.Broadcast()
	b.notFull.Broadcast()
	b.mu.Unlock()
}
