package vpn

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
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

type bufferedConn struct {
	net.Conn
	r io.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) {
	return c.r.Read(p)
}

type SocksServer struct {
	listenAddr     string
	opener         TunnelOpener
	listener       net.Listener
	udpListener    *net.UDPConn
	dohResolver    *DohResolver
	mu             sync.Mutex
	closed         bool
	onLog          func(string)
	onTokenExpired func()
}

func NewSocksServer(listenAddr string, opener TunnelOpener, onLog func(string), onTokenExpired ...func()) *SocksServer {
	s := &SocksServer{
		listenAddr: listenAddr,
		opener:     opener,
		onLog:      onLog,
	}
	if len(onTokenExpired) > 0 {
		s.onTokenExpired = onTokenExpired[0]
	}
	return s
}

func (s *SocksServer) log(msg string) {
	if s.onLog != nil {
		s.onLog(msg)
	}
}

func (s *SocksServer) getOpener() TunnelOpener {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.opener
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

	// Start Permanent UDP Listener on the exact same port for SOCKS5 UDP Associate & DoH
	udpAddr, err := net.ResolveUDPAddr("udp", s.listenAddr)
	if err == nil {
		udpLn, err := net.ListenUDP("udp", udpAddr)
		if err == nil {
			s.udpListener = udpLn
			s.dohResolver = NewDohResolver(s.getOpener)
			go s.permanentUdpRelayLoop(udpLn)
			s.log(fmt.Sprintf("[UDP-Relay] SOCKS5 UDP Associate listening permanently on %s (DoH active)", s.listenAddr))
		} else {
			s.log(fmt.Sprintf("[UDP-Relay] Warning: Failed to bind UDP %s: %v", s.listenAddr, err))
		}
	}

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
		_ = s.listener.Close()
		s.listener = nil
	}
	if s.udpListener != nil {
		_ = s.udpListener.Close()
		s.udpListener = nil
	}
	return nil
}

func (s *SocksServer) permanentUdpRelayLoop(udpConn *net.UDPConn) {
	buf := make([]byte, 4096)
	for {
		s.mu.Lock()
		closed := s.closed
		s.mu.Unlock()
		if closed {
			return
		}

		n, clientAddr, err := udpConn.ReadFromUDP(buf)
		if err != nil {
			if s.closed {
				return
			}
			time.Sleep(20 * time.Millisecond)
			continue
		}

		if n < 10 {
			continue
		}

		// Parse SOCKS5 UDP Header (RFC 1928):
		// [0..1] RSV (0x00, 0x00)
		// [2] FRAG (0x00)
		// [3] ATYP
		if buf[0] != 0 || buf[1] != 0 || buf[2] != 0 {
			continue // Fragmentation not supported
		}

		atyp := buf[3]
		headerLen := 0
		var dstPort int

		switch atyp {
		case socksAtypIPv4:
			headerLen = 10
			if n < headerLen {
				continue
			}
			dstPort = int(binary.BigEndian.Uint16(buf[8:10]))
		case socksAtypDomain:
			domainLen := int(buf[4])
			headerLen = 5 + domainLen + 2
			if n < headerLen {
				continue
			}
			dstPort = int(binary.BigEndian.Uint16(buf[5+domainLen : 5+domainLen+2]))
		case socksAtypIPv6:
			headerLen = 22
			if n < headerLen {
				continue
			}
			dstPort = int(binary.BigEndian.Uint16(buf[20:22]))
		default:
			continue
		}

		payload := make([]byte, n-headerLen)
		copy(payload, buf[headerLen:n])
		headerCopy := make([]byte, headerLen)
		copy(headerCopy, buf[:headerLen])

		// If destination is DNS port 53, resolve via DoH over Fastly tunnel!
		if dstPort == 53 && s.dohResolver != nil {
			go func(query []byte, respHeader []byte, to *net.UDPAddr) {
				ans, err := s.dohResolver.Resolve(query)
				if err != nil {
					return
				}
				respPacket := make([]byte, len(respHeader)+len(ans))
				copy(respPacket, respHeader)
				copy(respPacket[len(respHeader):], ans)
				_, _ = udpConn.WriteToUDP(respPacket, to)
			}(payload, headerCopy, clientAddr)
		}
	}
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
	br := bufio.NewReader(conn)
	firstByte, err := br.Peek(1)
	if err != nil {
		return
	}

	bConn := &bufferedConn{Conn: conn, r: br}

	if firstByte[0] == 0x05 {
		// SOCKS5 protocol
		s.handleSocks5(bConn)
	} else {
		// HTTP / HTTPS Proxy (Mixed Port)
		s.handleHttpProxy(bConn, br)
	}
}

func (s *SocksServer) handleSocks5(conn net.Conn) {
	target, cmd, replyCode, err := handshakeSOCKS5(conn)
	if err != nil {
		if replyCode != 0 {
			_ = writeSOCKSReply(conn, replyCode, nil)
		}
		return
	}
	_ = conn.SetDeadline(time.Time{})

	if cmd == socksCmdUdpAssociate {
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
	if !isAllowedWebPort(port) {
		// Fastly CDN only permits standard web ports (80, 443, etc.)
		_ = writeSOCKSReply(conn, socksReplyFailure, nil)
		return
	}
	isIP := net.ParseIP(host) != nil

	// If destination is an IP and port is 443 (HTTPS) or 80 (HTTP),
	// sniff the real domain name (SNI / Host header)
	if isIP && (port == "443" || port == "80") {
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
			upstream, err = opener.OpenTunnel(target)
		}
		if err != nil {
			if strings.Contains(err.Error(), "401") || strings.Contains(err.Error(), "token expired") {
				if s.onTokenExpired != nil {
					go s.onTokenExpired()
				}
			}
			s.log(fmt.Sprintf("[SOCKS5] Connect to %s failed: %v", actualTarget, err))
			return
		}
		defer upstream.Close()

		if _, err := upstream.Write(initialData); err != nil {
			return
		}

		relayBidirectional(conn, upstream)
		return
	}

	// Standard connect for named domains or other ports
	upstream, err := opener.OpenTunnel(target)
	if err != nil {
		if strings.Contains(err.Error(), "401") || strings.Contains(err.Error(), "token expired") {
			if s.onTokenExpired != nil {
				go s.onTokenExpired()
			}
		}
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

func (s *SocksServer) handleHttpProxy(conn net.Conn, br *bufio.Reader) {
	req, err := http.ReadRequest(br)
	if err != nil {
		return
	}
	_ = conn.SetDeadline(time.Time{})

	s.mu.Lock()
	opener := s.opener
	s.mu.Unlock()

	if opener == nil {
		_, _ = conn.Write([]byte("HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\n\r\n"))
		return
	}

	if req.Method == http.MethodConnect {
		// HTTPS CONNECT tunnel
		target := req.Host
		if !strings.Contains(target, ":") {
			target = target + ":443"
		}

		host, port, _ := net.SplitHostPort(target)
		isIP := net.ParseIP(host) != nil

		_, err = conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
		if err != nil {
			return
		}

		if isIP && port == "443" {
			_ = conn.SetDeadline(time.Now().Add(8 * time.Second))
			peekBuf := make([]byte, 2048)
			n, err := conn.Read(peekBuf)
			if err != nil || n == 0 {
				return
			}
			_ = conn.SetDeadline(time.Time{})

			initialData := peekBuf[:n]
			sniffedDomain := ExtractSNI(initialData)

			actualTarget := target
			if sniffedDomain != "" {
				actualTarget = net.JoinHostPort(sniffedDomain, port)
				s.log(fmt.Sprintf("[HTTP-Proxy] Sniffed domain %s (from IP %s) -> Routing to %s", sniffedDomain, target, actualTarget))
			}

			upstream, err := opener.OpenTunnel(actualTarget)
			if err != nil && sniffedDomain != "" {
				upstream, err = opener.OpenTunnel(target)
			}
			if err != nil {
				s.log(fmt.Sprintf("[HTTP-Proxy] Connect to %s failed: %v", actualTarget, err))
				return
			}
			defer upstream.Close()

			if _, err := upstream.Write(initialData); err != nil {
				return
			}

			relayBidirectional(conn, upstream)
			return
		}

		upstream, err := opener.OpenTunnel(target)
		if err != nil {
			s.log(fmt.Sprintf("[HTTP-Proxy] Connect to %s failed: %v", target, err))
			return
		}
		defer upstream.Close()

		relayBidirectional(conn, upstream)
		return
	}

	// Plain HTTP request (GET, POST, etc.)
	targetHost := req.URL.Host
	if targetHost == "" {
		targetHost = req.Host
	}
	if !strings.Contains(targetHost, ":") {
		targetHost = targetHost + ":80"
	}

	upstream, err := opener.OpenTunnel(targetHost)
	if err != nil {
		s.log(fmt.Sprintf("[HTTP-Proxy] Connect to %s failed: %v", targetHost, err))
		_, _ = conn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n"))
		return
	}
	defer upstream.Close()

	req.Header.Del("Proxy-Connection")
	req.Header.Del("Proxy-Authorization")
	if err := req.Write(upstream); err != nil {
		return
	}

	relayBidirectional(conn, upstream)
}

func (s *SocksServer) handleUdpAssociate(tcpConn net.Conn) {
	// Point client to the permanent UDP listener on the matching port!
	bndIP := "0.0.0.0"
	bndPort := 1080

	if localTCPAddr, ok := tcpConn.LocalAddr().(*net.TCPAddr); ok {
		if localTCPAddr.IP != nil && !localTCPAddr.IP.IsUnspecified() {
			bndIP = localTCPAddr.IP.String()
		}
		if s.udpListener != nil {
			if udpAddr, ok := s.udpListener.LocalAddr().(*net.UDPAddr); ok {
				bndPort = udpAddr.Port
			}
		} else {
			bndPort = localTCPAddr.Port
		}
	}

	bndAddr, _ := net.ResolveTCPAddr("tcp", fmt.Sprintf("%s:%d", bndIP, bndPort))
	if err := writeSOCKSReply(tcpConn, socksReplySuccess, bndAddr); err != nil {
		return
	}

	// Keep TCP connection alive as lifecycle anchor
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

func isAllowedWebPort(port string) bool {
	return port == "80" || port == "443" || port == "8080" || port == "8443" || port == "2499"
}

func relayBidirectional(c1, c2 net.Conn) {
	done := make(chan struct{}, 2)

	go func() {
		buf := copyBufferPool.Get().([]byte)
		defer copyBufferPool.Put(buf)
		_, _ = io.CopyBuffer(c1, c2, buf)
		done <- struct{}{}
		_ = c1.Close()
	}()

	go func() {
		buf := copyBufferPool.Get().([]byte)
		defer copyBufferPool.Put(buf)
		_, _ = io.CopyBuffer(c2, c1, buf)
		done <- struct{}{}
		_ = c2.Close()
	}()

	<-done
	_ = c1.Close()
	_ = c2.Close()
	<-done
}
