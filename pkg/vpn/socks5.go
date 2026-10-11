package vpn

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"
)

const (
	socksVersion5        = 0x05
	socksCmdConnect      = 0x01
	socksCmdUdpAssociate = 0x03
	socksAtypIPv4        = 0x01
	socksAtypDomain      = 0x03
	socksAtypIPv6        = 0x04
	socksAuthNoAuth      = 0x00
	socksAuthUserPass    = 0x02
	socksAuthNoAccept    = 0xff
	socksReplySuccess    = 0x00
	socksReplyFailure    = 0x01
	socksReplyCmdUnsup   = 0x07
	socksReplyAtypUnsup  = 0x08
	socksReplyHostUnrch  = 0x04
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
	target, cmd, replyCode, err := handshakeSOCKS5(conn)
	if err != nil {
		if replyCode != 0 {
			_ = writeSOCKSReply(conn, replyCode, nil)
		}
		return
	}
	_ = conn.SetDeadline(time.Time{})

	if cmd == socksCmdUdpAssociate {
		// Handle UDP Associate for DNS queries
		s.handleUdpAssociate(conn)
		return
	}

	s.mu.Lock()
	opener := s.opener
	s.mu.Unlock()

	if opener == nil {
		_ = writeSOCKSReply(conn, socksReplyHostUnrch, nil)
		return
	}

	host, port, _ := net.SplitHostPort(target)
	isIP := net.ParseIP(host) != nil

	// If destination is an IP and port is 443 (HTTPS) or 80 (HTTP),
	// we sniff the real domain name (SNI / Host header) to bypass DNS poisoning!
	if isIP && (port == "443" || port == "80") {
		// Acknowledge SOCKS5 connection immediately so client sends initial packet
		if err := writeSOCKSReply(conn, socksReplySuccess, conn.LocalAddr()); err != nil {
			return
		}

		_ = conn.SetDeadline(time.Now().Add(8 * time.Second))
		peekBuf := make([]byte, 2048)
		n, err := conn.Read(peekBuf)
		if err != nil || n == 0 {
			return
		}
		_ = conn.SetDeadline(time.Time{})

		initialData := peekBuf[:n]
		sniffedDomain := ""

		if port == "443" {
			sniffedDomain = ExtractSNI(initialData)
		} else if port == "80" {
			sniffedDomain = extractHttpHost(initialData)
		}

		actualTarget := target
		if sniffedDomain != "" {
			actualTarget = net.JoinHostPort(sniffedDomain, port)
			s.log(fmt.Sprintf("[SOCKS5] Sniffed domain %s (from IP %s) -> Routing to %s", sniffedDomain, target, actualTarget))
		}

		upstream, err := opener.OpenTunnel(actualTarget)
		if err != nil && sniffedDomain != "" {
			// If domain failed, attempt fallback to original target
			upstream, err = opener.OpenTunnel(target)
		}
		if err != nil {
			s.log(fmt.Sprintf("[SOCKS5] Connect to %s failed: %v", actualTarget, err))
			return
		}
		defer upstream.Close()

		// Write initial sniffed packet to upstream
		if _, err := upstream.Write(initialData); err != nil {
			return
		}

		relayBidirectional(conn, upstream)
		return
	}

	// Standard connect for named domains or other ports
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

func (s *SocksServer) handleUdpAssociate(tcpConn net.Conn) {
	// Allocate a UDP socket for relaying
	udpAddr, err := net.ResolveUDPAddr("udp", "0.0.0.0:0")
	if err != nil {
		_ = writeSOCKSReply(tcpConn, socksReplyFailure, nil)
		return
	}
	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		_ = writeSOCKSReply(tcpConn, socksReplyFailure, nil)
		return
	}
	defer udpConn.Close()

	// Get local address to inform client
	localTCPAddr, ok := tcpConn.LocalAddr().(*net.TCPAddr)
	relayIP := "127.0.0.1"
	if ok && localTCPAddr.IP != nil && !localTCPAddr.IP.IsUnspecified() {
		relayIP = localTCPAddr.IP.String()
	}
	relayPort := udpConn.LocalAddr().(*net.UDPAddr).Port

	bndAddr, _ := net.ResolveTCPAddr("tcp", fmt.Sprintf("%s:%d", relayIP, relayPort))
	if err := writeSOCKSReply(tcpConn, socksReplySuccess, bndAddr); err != nil {
		return
	}

	s.log(fmt.Sprintf("[SOCKS5] UDP Associate relay opened on %s:%d", relayIP, relayPort))

	// Keep TCP connection alive until client disconnects
	buf := make([]byte, 1)
	for {
		_, err := tcpConn.Read(buf)
		if err != nil {
			break
		}
	}
}

func handshakeSOCKS5(conn net.Conn) (string, byte, byte, error) {
	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		return "", 0, 0, err
	}
	if header[0] != socksVersion5 {
		return "", 0, 0, fmt.Errorf("invalid SOCKS version %d", header[0])
	}

	methods := make([]byte, int(header[1]))
	if _, err := io.ReadFull(conn, methods); err != nil {
		return "", 0, 0, err
	}

	// Prefer NoAuth (0x00), then UserPass (0x02)
	selectedMethod := byte(socksAuthNoAccept)
	for _, m := range methods {
		if m == socksAuthNoAuth {
			selectedMethod = socksAuthNoAuth
			break
		}
		if m == socksAuthUserPass && selectedMethod == socksAuthNoAccept {
			selectedMethod = socksAuthUserPass
		}
	}

	if selectedMethod == socksAuthNoAccept {
		_, _ = conn.Write([]byte{socksVersion5, socksAuthNoAccept})
		return "", 0, 0, fmt.Errorf("no acceptable SOCKS auth")
	}

	if _, err := conn.Write([]byte{socksVersion5, selectedMethod}); err != nil {
		return "", 0, 0, err
	}

	// If Username/Password auth was chosen (RFC 1929), accept any credentials
	if selectedMethod == socksAuthUserPass {
		var ver [1]byte
		if _, err := io.ReadFull(conn, ver[:]); err != nil {
			return "", 0, 0, err
		}
		var ulen [1]byte
		if _, err := io.ReadFull(conn, ulen[:]); err != nil {
			return "", 0, 0, err
		}
		uname := make([]byte, int(ulen[0]))
		if _, err := io.ReadFull(conn, uname); err != nil {
			return "", 0, 0, err
		}
		var plen [1]byte
		if _, err := io.ReadFull(conn, plen[:]); err != nil {
			return "", 0, 0, err
		}
		passwd := make([]byte, int(plen[0]))
		if _, err := io.ReadFull(conn, passwd); err != nil {
			return "", 0, 0, err
		}
		// Reply Success (version 0x01, status 0x00)
		if _, err := conn.Write([]byte{0x01, 0x00}); err != nil {
			return "", 0, 0, err
		}
	}

	reqHeader := make([]byte, 4)
	if _, err := io.ReadFull(conn, reqHeader); err != nil {
		return "", 0, 0, err
	}
	if reqHeader[0] != socksVersion5 {
		return "", 0, socksReplyFailure, fmt.Errorf("invalid request version %d", reqHeader[0])
	}

	cmd := reqHeader[1]
	if cmd != socksCmdConnect && cmd != socksCmdUdpAssociate {
		return "", cmd, socksReplyCmdUnsup, fmt.Errorf("unsupported command %d", cmd)
	}

	host, err := readSOCKSAddr(conn, reqHeader[3])
	if err != nil {
		if errors.Is(err, errUnsupportedAddrType) {
			return "", cmd, socksReplyAtypUnsup, err
		}
		return "", cmd, socksReplyFailure, err
	}

	portBytes := make([]byte, 2)
	if _, err := io.ReadFull(conn, portBytes); err != nil {
		return "", cmd, socksReplyFailure, err
	}
	port := binary.BigEndian.Uint16(portBytes)
	return net.JoinHostPort(host, fmt.Sprintf("%d", port)), cmd, socksReplySuccess, nil
}

func extractHttpHost(data []byte) string {
	lines := bytes.Split(data, []byte("\r\n"))
	for _, line := range lines {
		if bytes.HasPrefix(bytes.ToLower(line), []byte("host:")) {
			parts := bytes.SplitN(line, []byte(":"), 2)
			if len(parts) == 2 {
				host := strings.TrimSpace(string(parts[1]))
				if h, _, err := net.SplitHostPort(host); err == nil {
					return h
				}
				return host
			}
		}
	}
	return ""
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
		} else if udpAddr, ok := addr.(*net.UDPAddr); ok {
			host = udpAddr.IP.String()
			port = udpAddr.Port
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
