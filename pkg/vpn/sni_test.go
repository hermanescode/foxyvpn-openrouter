package vpn

import (
	"crypto/tls"
	"net"
	"testing"
)

func TestExtractSNI(t *testing.T) {
	// Generate a real ClientHello using crypto/tls
	server, client := net.Pipe()
	go func() {
		defer client.Close()
		tlsConfig := &tls.Config{
			ServerName: "example.com",
		}
		tlsConn := tls.Client(client, tlsConfig)
		_ = tlsConn.Handshake()
	}()

	buf := make([]byte, 1024)
	n, err := server.Read(buf)
	server.Close()
	if err != nil {
		t.Fatalf("Failed to read ClientHello: %v", err)
	}

	sni := ExtractSNI(buf[:n])
	if sni != "example.com" {
		t.Fatalf("Expected example.com, got %q", sni)
	}
}
