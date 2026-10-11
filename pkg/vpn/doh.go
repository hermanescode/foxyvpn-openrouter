package vpn

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"
)

type DohResolver struct {
	client *http.Client
}

func NewDohResolver(openerProvider func() TunnelOpener) *DohResolver {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			ServerName: "cloudflare-dns.com",
			MinVersion: tls.VersionTLS12,
		},
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			opener := openerProvider()
			if opener == nil {
				return nil, fmt.Errorf("VPN tunnel opener is nil")
			}
			return opener.OpenTunnel("1.1.1.1:443")
		},
		DisableKeepAlives: false,
		MaxIdleConns:      10,
		IdleConnTimeout:   60 * time.Second,
	}

	return &DohResolver{
		client: &http.Client{
			Transport: transport,
			Timeout:   5 * time.Second,
		},
	}
}

func (r *DohResolver) Resolve(dnsQuery []byte) ([]byte, error) {
	req, err := http.NewRequest(http.MethodPost, "https://1.1.1.1/dns-query", bytes.NewReader(dnsQuery))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")

	resp, err := r.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("DoH returned HTTP %d", resp.StatusCode)
	}

	return io.ReadAll(io.LimitReader(resp.Body, 4096))
}
