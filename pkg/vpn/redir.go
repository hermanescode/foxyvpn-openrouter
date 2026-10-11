package vpn

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

const SO_ORIGINAL_DST = 80

type RedirServer struct {
	listenAddr string
	opener     TunnelOpener
	listener   net.Listener
	mu         sync.Mutex
	closed     bool
	onLog      func(string)
}

func NewRedirServer(listenAddr string, opener TunnelOpener, onLog func(string)) *RedirServer {
	return &RedirServer{
		listenAddr: listenAddr,
		opener:     opener,
		onLog:      onLog,
	}
}

func (s *RedirServer) log(msg string) {
	if s.onLog != nil {
		s.onLog(msg)
	}
}

func (s *RedirServer) Start() error {
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

func (s *RedirServer) UpdateOpener(opener TunnelOpener) {
	s.mu.Lock()
	s.opener = opener
	s.mu.Unlock()
}

func (s *RedirServer) Stop() error {
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

func (s *RedirServer) acceptLoop(ln net.Listener) {
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

func (s *RedirServer) handleClient(conn net.Conn) {
	defer conn.Close()

	origDst, err := getOriginalDst(conn)
	if err != nil {
		return
	}

	_, port, _ := net.SplitHostPort(origDst)
	if !isAllowedWebPort(port) {
		return
	}

	if isBlockedDomain(origDst) {
		return
	}

	s.mu.Lock()
	opener := s.opener
	s.mu.Unlock()

	if opener == nil {
		return
	}

	_ = conn.SetDeadline(time.Now().Add(6 * time.Second))
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

	actualTarget := origDst
	if sniffedDomain != "" {
		if isBlockedDomain(sniffedDomain) {
			s.log(fmt.Sprintf("[Filter] Bypassed/Blocked domestic domain: %s", sniffedDomain))
			return
		}
		actualTarget = net.JoinHostPort(sniffedDomain, port)
	}

	upstream, err := opener.OpenTunnel(actualTarget)
	if err != nil && sniffedDomain != "" {
		upstream, err = opener.OpenTunnel(origDst)
	}
	if err != nil {
		return
	}
	defer upstream.Close()

	if _, err := upstream.Write(initialData); err != nil {
		return
	}

	relayBidirectional(conn, upstream)
}

func getOriginalDst(conn net.Conn) (string, error) {
	tcpConn, ok := conn.(*net.TCPConn)
	if !ok {
		return "", fmt.Errorf("not a tcp conn")
	}
	rawConn, err := tcpConn.SyscallConn()
	if err != nil {
		return "", err
	}

	var addr syscall.RawSockaddrInet4
	var errSock error

	err = rawConn.Control(func(fd uintptr) {
		size := uint32(unsafe.Sizeof(addr))
		_, _, errno := syscall.Syscall6(
			syscall.SYS_GETSOCKOPT,
			fd,
			syscall.SOL_IP,
			SO_ORIGINAL_DST,
			uintptr(unsafe.Pointer(&addr)),
			uintptr(unsafe.Pointer(&size)),
			0,
		)
		if errno != 0 {
			errSock = errno
		}
	})

	if err != nil {
		return "", err
	}
	if errSock != nil {
		return "", errSock
	}

	ip := net.IPv4(addr.Addr[0], addr.Addr[1], addr.Addr[2], addr.Addr[3])
	port := binary.BigEndian.Uint16((*[2]byte)(unsafe.Pointer(&addr.Port))[:])
	return fmt.Sprintf("%s:%d", ip.String(), port), nil
}

func isBlockedDomain(target string) bool {
	host, _, err := net.SplitHostPort(target)
	if err != nil {
		host = target
	}
	host = strings.ToLower(strings.TrimSpace(host))
	return strings.HasSuffix(host, ".ir") || strings.HasSuffix(host, ".ir.")
}
