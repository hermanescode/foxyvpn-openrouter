package vpn

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"testing"
	"time"
)

type mockTunnelOpener struct {
	openedTargets []string
}

func (m *mockTunnelOpener) OpenTunnel(authority string) (net.Conn, error) {
	m.openedTargets = append(m.openedTargets, authority)
	c1, c2 := net.Pipe()
	go func() {
		buf := make([]byte, 1024)
		_, _ = c2.Read(buf)
		_ = c2.Close()
	}()
	return c1, nil
}

func (m *mockTunnelOpener) Close() error { return nil }

func TestSocksAuthUserPassAndSNI(t *testing.T) {
	mockOpener := &mockTunnelOpener{}
	server := NewSocksServer("127.0.0.1:0", mockOpener, nil)
	if err := server.Start(); err != nil {
		t.Fatalf("Failed to start socks server: %v", err)
	}
	defer server.Stop()

	// 1. Test SOCKS5 with Username/Password auth (like socks://Og@192.168.8.1:1080)
	conn, err := net.Dial("tcp", server.listener.Addr().String())
	if err != nil {
		t.Fatalf("Dial failed: %v", err)
	}
	defer conn.Close()

	// Send version 5, 1 method: 0x02 (UserPass)
	_, _ = conn.Write([]byte{0x05, 0x01, 0x02})
	resp := make([]byte, 2)
	_, _ = io.ReadFull(conn, resp)
	if resp[0] != 0x05 || resp[1] != 0x02 {
		t.Fatalf("Expected method 0x02 accepted, got %v", resp)
	}

	// Send RFC 1929 subnegotiation: user "Og", pass ""
	_, _ = conn.Write([]byte{0x01, 0x02, 'O', 'g', 0x00})
	authResp := make([]byte, 2)
	_, _ = io.ReadFull(conn, authResp)
	if authResp[0] != 0x01 || authResp[1] != 0x00 {
		t.Fatalf("Expected auth success 0x01 0x00, got %v", authResp)
	}

	// Connect to an IP on port 443 (e.g. 46.245.77.82:443)
	ip := net.ParseIP("46.245.77.82").To4()
	req := []byte{0x05, 0x01, 0x00, 0x01}
	req = append(req, ip...)
	req = append(req, 0x01, 0xbb) // port 443
	_, _ = conn.Write(req)

	reply := make([]byte, 10)
	_, _ = io.ReadFull(conn, reply)
	if reply[1] != 0x00 {
		t.Fatalf("Expected SOCKS reply success, got %x", reply[1])
	}

	// Capture a ClientHello with ServerName: "youtube.com"
	p1, p2 := net.Pipe()
	go func() {
		defer p2.Close()
		client := tls.Client(p2, &tls.Config{ServerName: "youtube.com"})
		_ = client.Handshake()
	}()
	clientHello := make([]byte, 1024)
	n, _ := p1.Read(clientHello)
	p1.Close()

	// Send the real ClientHello packet into the SOCKS connection
	_, _ = conn.Write(clientHello[:n])

	time.Sleep(100 * time.Millisecond)

	found := false
	for _, target := range mockOpener.openedTargets {
		if target == "youtube.com:443" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("Expected SNI sniffing to route to youtube.com:443, got targets: %v", mockOpener.openedTargets)
	}
}

func TestMixedPortHttpProxy(t *testing.T) {
	mockOpener := &mockTunnelOpener{}
	server := NewSocksServer("127.0.0.1:0", mockOpener, nil)
	if err := server.Start(); err != nil {
		t.Fatalf("Failed to start socks server: %v", err)
	}
	defer server.Stop()

	// Connect with HTTP CONNECT to the SAME port
	conn, err := net.Dial("tcp", server.listener.Addr().String())
	if err != nil {
		t.Fatalf("Dial failed: %v", err)
	}
	defer conn.Close()

	reqStr := "CONNECT www.google.com:443 HTTP/1.1\r\nHost: www.google.com:443\r\n\r\n"
	_, _ = conn.Write([]byte(reqStr))

	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("ReadResponse failed: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("Expected 200 Connection Established, got %d", resp.StatusCode)
	}

	time.Sleep(50 * time.Millisecond)

	found := false
	for _, target := range mockOpener.openedTargets {
		if target == "www.google.com:443" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("Expected HTTP proxy to route to www.google.com:443, got targets: %v", mockOpener.openedTargets)
	}
	fmt.Println("Mixed Port HTTP Proxy Verified Successfully!")
}
