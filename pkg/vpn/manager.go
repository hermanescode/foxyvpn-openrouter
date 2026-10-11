package vpn

import (
	"context"
	"crypto/tls"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/hermanescode/foxyvpn-openrouter/pkg/config"
	"github.com/hermanescode/foxyvpn-openrouter/pkg/core"
)

//go:embed default_servers.json
var defaultServersRaw []byte

type ServerInfo struct {
	CountryName string `json:"country_name"`
	CountryCode string `json:"country_code"`
	CityName    string `json:"city_name"`
	CityCode    string `json:"city_code"`
	Host        string `json:"host"`
	Port        int    `json:"port"`
	Addr        string `json:"addr"`
	LatencyMs   int64  `json:"latency_ms"`
}

type StatusInfo struct {
	State            string  `json:"state"` // "disconnected", "connecting", "connected", "error"
	Email            string  `json:"email"`
	LoggedIn         bool    `json:"logged_in"`
	ActiveServer     string  `json:"active_server"`
	ActiveCountry    string  `json:"active_country"`
	ActiveCity       string  `json:"active_city"`
	ExitIP           string  `json:"exit_ip"`
	ExitCountry      string  `json:"exit_country"`
	SocksListen      string  `json:"socks_listen"`
	LatencyMs        int64   `json:"latency_ms"`
	QuotaMax         int64   `json:"quota_max"`
	QuotaLeft        int64   `json:"quota_left"`
	QuotaUsed        int64   `json:"quota_used"`
	QuotaPercentUsed float64 `json:"quota_percent_used"`
	QuotaReset       string  `json:"quota_reset"`
	LastError        string  `json:"last_error"`
	ConnectedAt      string  `json:"connected_at"`
	Mode             string  `json:"mode"`
}

type LogEntry struct {
	Timestamp string `json:"timestamp"`
	Message   string `json:"message"`
}

type VPNManager struct {
	cfg          *config.Config
	socksServer  *SocksServer
	h2Session    *H2ProxySession
	countries    []core.Country
	serversList  []ServerInfo
	serversMu    sync.RWMutex
	state        string
	lastError    string
	activeServer ServerInfo
	exitIP       string
	exitCountry  string
	latencyMs    int64
	quotaMax     int64
	quotaLeft    int64
	quotaReset   string
	connectedAt   time.Time
	passExpiresAt time.Time
	failureCount  int
	logs          []LogEntry
	logsMu       sync.Mutex
	mu           sync.RWMutex
	stopChan     chan struct{}
	running      bool
}

func (m *VPNManager) getLogPath() string {
	if m.cfg != nil && m.cfg.FilePath() != "" {
		return filepath.Join(filepath.Dir(m.cfg.FilePath()), "foxyvpn.log")
	}
	return "/etc/foxyvpn/foxyvpn.log"
}

func (m *VPNManager) loadPersistedLogs() {
	p := m.getLogPath()
	data, err := os.ReadFile(p)
	if err != nil {
		return
	}
	lines := strings.Split(string(data), "\n")
	m.logsMu.Lock()
	defer m.logsMu.Unlock()
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, " ", 2)
		ts := time.Now().Format("15:04:05")
		msg := line
		if len(parts) == 2 && strings.HasPrefix(parts[0], "[") && strings.HasSuffix(parts[0], "]") {
			ts = strings.Trim(parts[0], "[]")
			msg = parts[1]
		}
		m.logs = append(m.logs, LogEntry{Timestamp: ts, Message: msg})
	}
	if len(m.logs) > 300 {
		m.logs = m.logs[len(m.logs)-300:]
	}
}

func NewVPNManager(cfg *config.Config) *VPNManager {
	m := &VPNManager{
		cfg:      cfg,
		state:    "disconnected",
		stopChan: make(chan struct{}),
	}
	m.loadPersistedLogs()
	m.socksServer = NewSocksServer(cfg.SocksListen, nil, func(msg string) {
		m.AddLog(msg)
	}, func() {
		_ = m.renewProxyPass()
	})
	return m
}

func (m *VPNManager) AddLog(msg string) {
	level := "info"
	if strings.Contains(msg, "failed") || strings.Contains(msg, "Error") || strings.Contains(msg, "WARNING") {
		level = "error"
	} else if strings.Contains(msg, "Sniffed domain") || strings.Contains(msg, "UDP Associate") {
		level = "debug"
	}
	m.AddLogLevel(level, msg)
}

func (m *VPNManager) AddLogLevel(level, msg string) {
	cfgLevel := "info"
	if m.cfg != nil && m.cfg.LogLevel != "" {
		cfgLevel = m.cfg.LogLevel
	}

	if cfgLevel == "none" {
		return
	}
	if cfgLevel == "error" && level != "error" {
		return
	}
	if (cfgLevel == "info" || cfgLevel == "") && level == "debug" {
		return
	}

	nowStr := time.Now().Format("15:04:05")
	entry := LogEntry{
		Timestamp: nowStr,
		Message:   msg,
	}

	m.logsMu.Lock()
	m.logs = append(m.logs, entry)
	if len(m.logs) > 300 {
		m.logs = m.logs[len(m.logs)-300:]
	}
	m.logsMu.Unlock()

	// Append to persistent log file
	p := m.getLogPath()
	f, err := os.OpenFile(p, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err == nil {
		_, _ = f.WriteString(fmt.Sprintf("[%s] %s\n", nowStr, msg))
		_ = f.Close()
	}
}

func (m *VPNManager) ClearLogs() {
	m.logsMu.Lock()
	m.logs = nil
	m.logsMu.Unlock()
	_ = os.Truncate(m.getLogPath(), 0)
}

func (m *VPNManager) GetLogs() []LogEntry {
	m.logsMu.Lock()
	defer m.logsMu.Unlock()
	res := make([]LogEntry, len(m.logs))
	copy(res, m.logs)
	return res
}

func (m *VPNManager) Start() error {
	m.mu.Lock()
	if m.running {
		m.mu.Unlock()
		return nil
	}
	m.running = true
	m.mu.Unlock()

	m.AddLog("FoxyVPN OpenRouter service initialized")

	now := time.Now()
	if now.Year() < 2026 || (now.Year() == 2026 && now.Month() < time.October) {
		m.AddLog(fmt.Sprintf("⚠️ WARNING: Router system clock is %s (behind real time). SSL/TLS certificates will fail until time is synced! Run: date -s '2026-10-11 12:00:00'", now.Format("2006-01-02 15:04:05")))
	}

	// Start socks server listener
	if err := m.socksServer.Start(); err != nil {
		m.AddLog(fmt.Sprintf("Failed to bind SOCKS5 on %s: %v", m.cfg.SocksListen, err))
	} else {
		m.AddLog(fmt.Sprintf("SOCKS5 listening on %s", m.cfg.SocksListen))
	}

	// Fetch server list in background
	go m.refreshServersList()

	// Start supervisor loop
	go m.supervisorLoop()

	// If auto_connect is on and we have tokens, connect
	if m.cfg.AutoConnect && m.cfg.RefreshToken != "" {
		go func() {
			time.Sleep(1 * time.Second)
			_ = m.Connect("", "")
		}()
	}

	return nil
}

func (m *VPNManager) Stop() {
	m.mu.Lock()
	if !m.running {
		m.mu.Unlock()
		return
	}
	m.running = false
	close(m.stopChan)
	m.mu.Unlock()

	_ = m.Disconnect()
	_ = m.socksServer.Stop()
}

func (m *VPNManager) GetStatus() StatusInfo {
	m.mu.RLock()
	defer m.mu.RUnlock()

	used := m.quotaMax - m.quotaLeft
	if used < 0 {
		used = 0
	}
	var pct float64
	if m.quotaMax > 0 {
		pct = float64(used) / float64(m.quotaMax) * 100
	}

	connectedTime := ""
	if !m.connectedAt.IsZero() && m.state == "connected" {
		connectedTime = m.connectedAt.Format(time.RFC3339)
	}

	return StatusInfo{
		State:            m.state,
		Email:            m.cfg.Email,
		LoggedIn:         m.cfg.RefreshToken != "" || m.state == "connected",
		ActiveServer:     m.activeServer.Addr,
		ActiveCountry:    m.activeServer.CountryName,
		ActiveCity:       m.activeServer.CityName,
		ExitIP:           m.exitIP,
		ExitCountry:      m.exitCountry,
		SocksListen:      m.cfg.SocksListen,
		LatencyMs:        m.latencyMs,
		QuotaMax:         m.quotaMax,
		QuotaLeft:        m.quotaLeft,
		QuotaUsed:        used,
		QuotaPercentUsed: pct,
		QuotaReset:       m.quotaReset,
		LastError:        m.lastError,
		ConnectedAt:      connectedTime,
		Mode:             m.cfg.Mode,
	}
}

func (m *VPNManager) refreshServersList() {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	countries, err := core.FetchServerList(ctx)
	if err != nil {
		m.AddLog(fmt.Sprintf("Failed to fetch live server list (%v). Loading bundled server list...", err))
		var rawCountries []json.RawMessage
		if unmarshalErr := json.Unmarshal(defaultServersRaw, &rawCountries); unmarshalErr == nil {
			for _, r := range rawCountries {
				var c core.Country
				if json.Unmarshal(r, &c) == nil && c.Code != "" && len(c.Cities) > 0 {
					countries = append(countries, c)
				}
			}
		}
	}

	var servers []ServerInfo
	for _, c := range countries {
		for _, city := range c.Cities {
			for _, srv := range city.Servers {
				if srv.Quarantined {
					continue
				}
				if len(srv.Protocols) == 0 && srv.Hostname != "" && srv.Port > 0 {
					servers = append(servers, ServerInfo{
						CountryName: c.Name,
						CountryCode: c.Code,
						CityName:    city.Name,
						CityCode:    city.Code,
						Host:        srv.Hostname,
						Port:        srv.Port,
						Addr:        fmt.Sprintf("%s:%d", srv.Hostname, srv.Port),
					})
					continue
				}
				for _, proto := range srv.Protocols {
					if proto.Name == "connect" && proto.Host != "" && proto.Port > 0 {
						servers = append(servers, ServerInfo{
							CountryName: c.Name,
							CountryCode: c.Code,
							CityName:    city.Name,
							CityCode:    city.Code,
							Host:        proto.Host,
							Port:        proto.Port,
							Addr:        fmt.Sprintf("%s:%d", proto.Host, proto.Port),
						})
					}
				}
			}
		}
	}

	m.serversMu.Lock()
	m.countries = countries
	m.serversList = servers
	m.serversMu.Unlock()

	m.AddLog(fmt.Sprintf("Loaded %d edge proxy servers across %d countries", len(servers), len(countries)))
}

func (m *VPNManager) GetServers() []ServerInfo {
	m.serversMu.RLock()
	defer m.serversMu.RUnlock()
	res := make([]ServerInfo, len(m.serversList))
	copy(res, m.serversList)
	return res
}

func (m *VPNManager) Connect(country, serverAddr string) error {
	m.mu.Lock()
	if m.state == "connecting" {
		m.mu.Unlock()
		return fmt.Errorf("already connecting")
	}
	m.state = "connecting"
	m.lastError = ""
	m.mu.Unlock()

	m.AddLog("Initiating VPN connection...")

	go func() {
		err := m.doConnect(country, serverAddr)
		m.mu.Lock()
		var countryName, serverAddr string
		if err != nil {
			m.state = "error"
			m.lastError = err.Error()
			m.failureCount++
		} else {
			m.state = "connected"
			m.lastError = ""
			m.connectedAt = time.Now()
			m.failureCount = 0
			countryName = m.activeServer.CountryName
			serverAddr = m.activeServer.Addr
		}
		m.mu.Unlock()

		if err != nil {
			m.AddLog(fmt.Sprintf("Connection failed: %v", err))
		} else {
			m.AddLog(fmt.Sprintf("Connected to %s (%s). SOCKS5 ready at %s", countryName, serverAddr, m.cfg.SocksListen))
			go m.verifyExitProbe()
		}
	}()

	return nil
}

func (m *VPNManager) doConnect(country, serverAddr string) error {
	if m.cfg.RefreshToken == "" {
		return fmt.Errorf("not logged in: please log in with your Firefox account")
	}

	// 1. Refresh OAuth access token if needed
	accessToken := m.cfg.AccessToken
	if accessToken == "" || time.Since(m.cfg.ObtainedAt) > time.Duration(m.cfg.ExpiresIn-120)*time.Second {
		m.AddLog("Refreshing Firefox OAuth token...")
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		tokenResp, err := core.FxaRefreshToken(ctx, m.cfg.RefreshToken)
		cancel()
		if err != nil {
			return fmt.Errorf("token refresh failed: %w", err)
		}
		_ = m.cfg.SetTokens(m.cfg.Email, tokenResp.AccessToken, tokenResp.RefreshToken, tokenResp.ExpiresIn)
		accessToken = tokenResp.AccessToken
	}

	guardianEndpoint := m.cfg.GuardianEndpoint
	if guardianEndpoint == "" {
		guardianEndpoint = core.GuardianEndpointDefault
	}

	// 2. Fetch Proxy Pass from Guardian
	m.AddLog("Acquiring proxy pass token from Mozilla Guardian...")
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	pass, err := core.FetchProxyPass(ctx, guardianEndpoint, accessToken)
	cancel()
	if err != nil {
		if strings.Contains(err.Error(), "token invalid") || strings.Contains(err.Error(), "403") {
			m.AddLog("Guardian proxy pass requires activation. Activating...")
			actCtx, actCancel := context.WithTimeout(context.Background(), 20*time.Second)
			_, actErr := core.ActivateGuardian(actCtx, guardianEndpoint, accessToken)
			actCancel()
			if actErr != nil {
				return fmt.Errorf("guardian activate failed: %w", actErr)
			}
			m.AddLog("Guardian activated! Retrying proxy pass...")
			retryCtx, retryCancel := context.WithTimeout(context.Background(), 20*time.Second)
			pass, err = core.FetchProxyPass(retryCtx, guardianEndpoint, accessToken)
			retryCancel()
			if err != nil {
				return fmt.Errorf("retry proxy pass failed: %w", err)
			}
		} else {
			return fmt.Errorf("guardian fetch proxy pass failed: %w", err)
		}
	}

	// Update quota & expiration info
	m.mu.Lock()
	m.passExpiresAt = pass.ExpiresAt()
	if pass.QuotaMax != "" {
		maxBytes, _ := strconv.ParseInt(pass.QuotaMax, 10, 64)
		leftBytes, _ := strconv.ParseInt(pass.QuotaLeft, 10, 64)
		m.quotaMax = maxBytes
		m.quotaLeft = leftBytes
		m.quotaReset = pass.QuotaReset
	}
	m.mu.Unlock()

	// 3. Resolve edge server
	targetServer, err := m.resolveServer(country, serverAddr)
	if err != nil {
		return fmt.Errorf("server selection failed: %w", err)
	}

	m.AddLog(fmt.Sprintf("Connecting to edge proxy %s (%s, %s)...", targetServer.Addr, targetServer.CountryName, targetServer.CityName))

	// 4. Connect HTTP/2 tunnel
	proxyURL, err := url.Parse("https://" + targetServer.Addr)
	if err != nil {
		return fmt.Errorf("invalid proxy URL: %w", err)
	}

	sessionStart := time.Now()
	h2Session, err := NewH2ProxySession(proxyURL, pass.RawToken, 20*time.Second)
	if err != nil {
		return fmt.Errorf("failed to establish upstream H2 session: %w", err)
	}
	latency := time.Since(sessionStart).Milliseconds()

	m.mu.Lock()
	if m.h2Session != nil {
		_ = m.h2Session.Close()
	}
	m.h2Session = h2Session
	m.activeServer = targetServer
	m.latencyMs = latency
	m.socksServer.UpdateOpener(h2Session)
	m.mu.Unlock()

	return nil
}

func (m *VPNManager) resolveServer(country, serverAddr string) (ServerInfo, error) {
	m.serversMu.RLock()
	servers := m.serversList
	m.serversMu.RUnlock()

	if len(servers) == 0 {
		m.refreshServersList()
		m.serversMu.RLock()
		servers = m.serversList
		m.serversMu.RUnlock()
	}

	if len(servers) == 0 {
		// Fallback to Mozilla default Fastly edge if list unavailable
		return ServerInfo{
			CountryName: "Auto",
			CountryCode: "US",
			CityName:    "Default",
			Addr:        "proxy.fastly.net:443",
		}, nil
	}

	if serverAddr != "" {
		for _, s := range servers {
			if s.Addr == serverAddr {
				return s, nil
			}
		}
	}

	if country != "" {
		for _, s := range servers {
			if strings.EqualFold(s.CountryCode, country) || strings.EqualFold(s.CountryName, country) {
				return s, nil
			}
		}
	}

	if m.cfg.Mode == "manual" && m.cfg.SelectedServer != "" {
		for _, s := range servers {
			if s.Addr == m.cfg.SelectedServer {
				return s, nil
			}
		}
	}

	// Mode auto: Probe the top 5 servers or select fastest
	m.AddLog("Auto mode: selecting lowest latency server...")
	bestServer := servers[0]
	bestLatency := int64(99999)

	sample := servers
	if len(sample) > 8 {
		sample = sample[:8]
	}

	for _, s := range sample {
		lat := probeTcpLatency(s.Addr, 2*time.Second)
		if lat > 0 && lat < bestLatency {
			bestLatency = lat
			bestServer = s
			bestServer.LatencyMs = lat
		}
	}

	return bestServer, nil
}

func probeTcpLatency(addr string, timeout time.Duration) int64 {
	start := time.Now()
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return -1
	}
	_ = conn.Close()
	return time.Since(start).Milliseconds()
}

func (m *VPNManager) verifyExitProbe() {
	m.mu.RLock()
	session := m.h2Session
	m.mu.RUnlock()

	if session == nil {
		return
	}

	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
			DialContext: func(ctx context.Context, _, authority string) (net.Conn, error) {
				return session.OpenTunnel(authority)
			},
		},
	}

	resp, err := client.Get("https://www.cloudflare.com/cdn-cgi/trace")
	if err != nil {
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return
	}

	lines := strings.Split(string(body), "\n")
	var ip, loc string
	for _, l := range lines {
		parts := strings.SplitN(l, "=", 2)
		if len(parts) == 2 {
			if parts[0] == "ip" {
				ip = parts[1]
			} else if parts[0] == "loc" {
				loc = parts[1]
			}
		}
	}

	if ip != "" {
		m.mu.Lock()
		m.exitIP = ip
		m.exitCountry = loc
		m.mu.Unlock()
		m.AddLog(fmt.Sprintf("Exit IP verified: %s (%s)", ip, loc))
	}
}

func (m *VPNManager) Disconnect() error {
	m.mu.Lock()
	if m.h2Session != nil {
		_ = m.h2Session.Close()
		m.h2Session = nil
	}
	m.socksServer.UpdateOpener(nil)
	m.state = "disconnected"
	m.exitIP = ""
	m.exitCountry = ""
	m.latencyMs = 0
	m.activeServer = ServerInfo{}
	m.connectedAt = time.Time{}
	m.mu.Unlock()

	m.AddLog("VPN disconnected")
	return nil
}

func (m *VPNManager) Login(email, password string) error {
	m.AddLog(fmt.Sprintf("Logging in to Firefox Account (%s)...", email))
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	loginResp, err := core.FxaLogin(ctx, email, password)
	if err != nil {
		m.AddLog(fmt.Sprintf("Firefox login failed: %v", err))
		return err
	}

	m.AddLog("Getting OAuth VPN token...")
	tokenResp, err := core.FxaOAuthToken(ctx, loginResp.SessionToken)
	if err != nil {
		m.AddLog(fmt.Sprintf("OAuth token exchange failed: %v", err))
		return err
	}

	if err := m.cfg.SetTokens(email, tokenResp.AccessToken, tokenResp.RefreshToken, tokenResp.ExpiresIn); err != nil {
		return err
	}

	m.AddLog(fmt.Sprintf("Successfully logged in as %s", email))
	return nil
}

func (m *VPNManager) Logout() error {
	_ = m.Disconnect()
	return m.cfg.ClearTokens()
}

func (m *VPNManager) supervisorLoop() {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-m.stopChan:
			return
		case <-ticker.C:
			m.checkHealthAndReconnect()
			m.checkProxyPassRenewal()
		}
	}
}

func (m *VPNManager) checkProxyPassRenewal() {
	m.mu.RLock()
	state := m.state
	exp := m.passExpiresAt
	session := m.h2Session
	m.mu.RUnlock()

	if state != "connected" || session == nil || exp.IsZero() {
		return
	}

	if time.Until(exp) < 5*time.Minute {
		m.AddLog(fmt.Sprintf("Proxy pass token expires in %s. Renewing in background...", time.Until(exp).Round(time.Second)))
		_ = m.renewProxyPass()
	}
}

func (m *VPNManager) renewProxyPass() error {
	m.mu.RLock()
	session := m.h2Session
	accessToken := m.cfg.AccessToken
	guardian := m.cfg.GuardianEndpoint
	if guardian == "" {
		guardian = core.GuardianEndpointDefault
	}
	m.mu.RUnlock()

	if session == nil {
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	pass, err := core.FetchProxyPass(ctx, guardian, accessToken)
	cancel()
	if err != nil {
		refCtx, refCancel := context.WithTimeout(context.Background(), 20*time.Second)
		tokenResp, refErr := core.FxaRefreshToken(refCtx, m.cfg.RefreshToken)
		refCancel()
		if refErr == nil {
			_ = m.cfg.SetTokens(m.cfg.Email, tokenResp.AccessToken, tokenResp.RefreshToken, tokenResp.ExpiresIn)
			accessToken = tokenResp.AccessToken
			retryCtx, retryCancel := context.WithTimeout(context.Background(), 20*time.Second)
			pass, err = core.FetchProxyPass(retryCtx, guardian, accessToken)
			retryCancel()
		}
	}

	if err != nil {
		m.AddLog(fmt.Sprintf("Background proxy pass renewal failed: %v", err))
		return err
	}

	session.UpdateToken(pass.RawToken)
	m.mu.Lock()
	m.passExpiresAt = pass.ExpiresAt()
	m.mu.Unlock()
	m.AddLog(fmt.Sprintf("Proxy pass token renewed. Valid until %s", pass.ExpiresAt().Format("15:04:05")))
	return nil
}

func (m *VPNManager) checkHealthAndReconnect() {
	m.mu.RLock()
	state := m.state
	session := m.h2Session
	m.mu.RUnlock()

	if state == "connected" {
		if session == nil || !session.IsAlive() {
			m.AddLog("Upstream connection dropped. Triggering auto-reconnect...")
			_ = m.Disconnect()
			time.Sleep(2 * time.Second)
			_ = m.Connect("", "")
		}
	} else if state == "error" && m.cfg.AutoConnect && m.cfg.RefreshToken != "" {
		if m.failureCount < 5 {
			m.AddLog(fmt.Sprintf("Retrying connection after failure (attempt %d)...", m.failureCount+1))
			time.Sleep(3 * time.Second)
			_ = m.Connect("", "")
		}
	}
}

func (m *VPNManager) TestTarget(target string) (int64, string, error) {
	m.mu.RLock()
	session := m.h2Session
	m.mu.RUnlock()

	if session == nil {
		return 0, "", fmt.Errorf("VPN is not connected")
	}

	target = strings.TrimSpace(target)
	if !strings.Contains(target, ":") {
		target = target + ":443"
	}

	start := time.Now()
	conn, err := session.OpenTunnel(target)
	if err != nil {
		m.AddLog(fmt.Sprintf("[Test] Connection to %s failed: %v", target, err))
		return 0, "", err
	}
	defer conn.Close()
	latency := time.Since(start).Milliseconds()

	msg := fmt.Sprintf("Tunnel successfully opened to %s in %d ms", target, latency)
	m.AddLog(fmt.Sprintf("[Test] %s", msg))
	return latency, msg, nil
}

func (m *VPNManager) UpdateConfig(newCfg *config.Config) error {
	m.mu.Lock()
	rebindSocks := m.cfg.SocksListen != newCfg.SocksListen
	m.cfg.WebListen = newCfg.WebListen
	m.cfg.WebPassword = newCfg.WebPassword
	m.cfg.SocksListen = newCfg.SocksListen
	m.cfg.AutoConnect = newCfg.AutoConnect
	m.cfg.Mode = newCfg.Mode
	m.cfg.SelectedCountry = newCfg.SelectedCountry
	m.cfg.SelectedServer = newCfg.SelectedServer
	m.cfg.LogLevel = newCfg.LogLevel
	m.mu.Unlock()

	if err := m.cfg.Save(); err != nil {
		return err
	}

	if rebindSocks {
		_ = m.socksServer.Stop()
		m.socksServer = NewSocksServer(m.cfg.SocksListen, m.h2Session, func(msg string) {
			m.AddLog(msg)
		})
		_ = m.socksServer.Start()
		m.AddLog(fmt.Sprintf("SOCKS5 re-bound to %s", m.cfg.SocksListen))
	}

	return nil
}
