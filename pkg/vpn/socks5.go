package vpn

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

const (
	socksVersion5       = 0x05
	socksCmdConnect     = 0x01
	socksAtypIPv4       = 0x01
	socksAtypDomain     = 0x03
	socksAtypIPv6       = 0x04
	socksAuthNoAuth     = 0x00
	socksAuthNoAccept   = 0xff
	socksReplySuccess   = 0x00
	socksReplyFailure   = 0x01
	socksReplyCmdUnsup  = 0x07
	socksReplyAtypUnsup = 0x08
	socksReplyHostUnrch = 0x04
)

var (
	copyBufferPool = sync.Pool{
		New: func() any {
			return make([]byte, 32*1024)
		},
	}
	errUnsupportedAddrType = errors.New("unsupported SOCKS address type")
)

type SocksServer struct {
	listenAddr string
	opener     TunnelOpener
	listener   net.Listener
	mu         sync.Mutex
	closed     bool
	onLog      func(string)
}

func NewSocksServer(listenAddr string, opener TunnelOpener, onLog func(string)) *SocksServer {
	return &SocksServer{
		listenAddr: listenAddr,
		opener:     opener,
		onLog:      onLog,
	}
}

func (s *SocksServer) log(msg string) {
	if s.onLog != nil {
		s.onLog(msg)
	}
}

func (s *SocksServer) Start() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	ln, err := net.Listen("tcp", s.listenAddr)
	if err != nil {
		return err
	}
	s.listener = ln
	s.closed = false

	go s.acceptLoop(ln)
	return nil
}

func (s *SocksServer) UpdateOpener(opener TunnelOpener) {
	s.mu.Lock()
	s.opener = opener
	s.mu.Unlock()
}

func (s *SocksServer) Stop() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.closed = true
	if s.listener != nil {
		err := s.listener.Close()
		s.listener = nil
		return err
	}
	return nil
}

func (s *SocksServer) acceptLoop(ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			s.mu.Lock()
			closed := s.closed
			s.mu.Unlock()
			if closed {
				return
			}
			time.Sleep(50 * time.Millisecond)
			continue
		}
		go s.handleClient(conn)
	}
}

func (s *SocksServer) handleClient(conn net.Conn) {
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	target, replyCode, err := handshakeSOCKS5(conn)
	if err != nil {
		if replyCode != 0 {
			_ = writeSOCKSReply(conn, replyCode, nil)
		}
		return
	}
	_ = conn.SetDeadline(time.Time{})

	s.mu.Lock()
	opener := s.opener
	s.mu.Unlock()

	if opener == nil {
		_ = writeSOCKSReply(conn, socksReplyHostUnrch, nil)
		return
	}

	upstream, err := opener.OpenTunnel(target)
	if err != nil {
		s.log(fmt.Sprintf("[SOCKS5] Connect to %s failed: %v", target, err))
		_ = writeSOCKSReply(conn, socksReplyHostUnrch, nil)
		return
	}
	defer upstream.Close()

	if err := writeSOCKSReply(conn, socksReplySuccess, conn.LocalAddr()); err != nil {
		return
	}

	relayBidirectional(conn, upstream)
}

func handshakeSOCKS5(conn net.Conn) (string, byte, error) {
	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		return "", 0, err
	}
	if header[0] != socksVersion5 {
		return "", 0, fmt.Errorf("invalid SOCKS version %d", header[0])
	}

	methods := make([]byte, int(header[1]))
	if _, err := io.ReadFull(conn, methods); err != nil {
		return "", 0, err
	}

	method := byte(socksAuthNoAccept)
	for _, m := range methods {
		if m == socksAuthNoAuth {
			method = socksAuthNoAuth
			break
		}
	}
	if _, err := conn.Write([]byte{socksVersion5, method}); err != nil {
		return "", 0, err
	}
	if method == socksAuthNoAccept {
		return "", 0, fmt.Errorf("no acceptable SOCKS auth")
	}

	reqHeader := make([]byte, 4)
	if _, err := io.ReadFull(conn, reqHeader); err != nil {
		return "", 0, err
	}
	if reqHeader[0] != socksVersion5 {
		return "", socksReplyFailure, fmt.Errorf("invalid request version %d", reqHeader[0])
	}
	if reqHeader[1] != socksCmdConnect {
		return "", socksReplyCmdUnsup, fmt.Errorf("unsupported command %d", reqHeader[1])
	}

	host, err := readSOCKSAddr(conn, reqHeader[3])
	if err != nil {
		if errors.Is(err, errUnsupportedAddrType) {
			return "", socksReplyAtypUnsup, err
		}
		return "", socksReplyFailure, err
	}

	portBytes := make([]byte, 2)
	if _, err := io.ReadFull(conn, portBytes); err != nil {
		return "", socksReplyFailure, err
	}
	port := binary.BigEndian.Uint16(portBytes)
	return net.JoinHostPort(host, fmt.Sprintf("%d", port)), socksReplySuccess, nil
}

func readSOCKSAddr(r io.Reader, atyp byte) (string, error) {
	switch atyp {
	case socksAtypIPv4:
		buf := make([]byte, net.IPv4len)
		if _, err := io.ReadFull(r, buf); err != nil {
			return "", err
		}
		return net.IP(buf).String(), nil
	case socksAtypIPv6:
		buf := make([]byte, net.IPv6len)
		if _, err := io.ReadFull(r, buf); err != nil {
			return "", err
		}
		return net.IP(buf).String(), nil
	case socksAtypDomain:
		var size [1]byte
		if _, err := io.ReadFull(r, size[:]); err != nil {
			return "", err
		}
		buf := make([]byte, int(size[0]))
		if _, err := io.ReadFull(r, buf); err != nil {
			return "", err
		}
		return string(buf), nil
	default:
		return "", errUnsupportedAddrType
	}
}

func writeSOCKSReply(w io.Writer, rep byte, addr net.Addr) error {
	host := "0.0.0.0"
	port := 0
	if addr != nil {
		if tcpAddr, ok := addr.(*net.TCPAddr); ok {
			host = tcpAddr.IP.String()
			port = tcpAddr.Port
		}
	}

	ip := net.ParseIP(host)
	atyp := byte(socksAtypIPv4)
	addrBytes := []byte{0, 0, 0, 0}
	if ip != nil && ip.To4() != nil {
		addrBytes = ip.To4()
	} else if ip != nil && ip.To16() != nil {
		atyp = socksAtypIPv6
		addrBytes = ip.To16()
	}

	reply := make([]byte, 0, 6+len(addrBytes))
	reply = append(reply, socksVersion5, rep, 0x00, atyp)
	reply = append(reply, addrBytes...)
	reply = append(reply, byte(port>>8), byte(port))
	_, err := w.Write(reply)
	return err
}

func relayBidirectional(c1, c2 net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)

	copyOne := func(dst, src net.Conn) {
		defer wg.Done()
		buf := copyBufferPool.Get().([]byte)
		defer copyBufferPool.Put(buf)
		_, _ = io.CopyBuffer(dst, src, buf)
		if closeWriter, ok := dst.(interface{ CloseWrite() error }); ok {
			_ = closeWriter.CloseWrite()
		} else {
			_ = dst.Close()
		}
	}

	go copyOne(c1, c2)
	go copyOne(c2, c1)

	wg.Wait()
}
