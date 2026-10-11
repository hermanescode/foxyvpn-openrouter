package vpn

import (
	"net"
	"testing"
)

type realDirectOpener struct{}

func (r *realDirectOpener) OpenTunnel(authority string) (net.Conn, error) {
	return net.Dial("tcp", authority)
}

func (r *realDirectOpener) Close() error { return nil }

func TestDohResolver(t *testing.T) {
	resolver := NewDohResolver(func() TunnelOpener {
		return &realDirectOpener{}
	})

	dnsQuery := []byte("\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x06google\x03com\x00\x00\x01\x00\x01")
	resp, err := resolver.Resolve(dnsQuery)
	if err != nil {
		t.Fatalf("DoH resolve failed: %v", err)
	}
	if len(resp) == 0 {
		t.Fatalf("Empty DoH response")
	}
	t.Logf("DoH response length: %d bytes", len(resp))
}
