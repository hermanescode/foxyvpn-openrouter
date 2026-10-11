package web

import (
	"crypto/subtle"
	"embed"
	"encoding/json"
	"io/fs"
	"net/http"
	"strings"
	"time"

	"github.com/hermanescode/foxyvpn-openrouter/pkg/config"
	"github.com/hermanescode/foxyvpn-openrouter/pkg/vpn"
)

//go:embed static/*
var staticFS embed.FS

type Server struct {
	cfg     *config.Config
	manager *vpn.VPNManager
	srv     *http.Server
}

func NewServer(cfg *config.Config, manager *vpn.VPNManager) *Server {
	return &Server{
		cfg:     cfg,
		manager: manager,
	}
}

func (s *Server) Start() error {
	mux := http.NewServeMux()

	// API routes (accessible across local network)
	mux.HandleFunc("/api/status", s.handleStatus)
	mux.HandleFunc("/api/connect", s.handleConnect)
	mux.HandleFunc("/api/disconnect", s.handleDisconnect)
	mux.HandleFunc("/api/servers", s.handleServers)
	mux.HandleFunc("/api/login", s.handleLogin)
	mux.HandleFunc("/api/logout", s.handleLogout)
	mux.HandleFunc("/api/config", s.handleConfig)
	mux.HandleFunc("/api/logs", s.handleLogs)
	mux.HandleFunc("/api/logs/clear", s.handleClearLogs)
	mux.HandleFunc("/api/test", s.handleTest)
	mux.HandleFunc("/api/gateway/status", s.handleGatewayStatus)
	mux.HandleFunc("/api/gateway/toggle", s.handleGatewayToggle)
	mux.HandleFunc("/api/auth/check", s.handleAuthCheck)
	mux.HandleFunc("/api/auth/login", s.handleWebAuthLogin)

	// Static UI with no-cache headers
	sub, err := fs.Sub(staticFS, "static")
	if err != nil {
		return err
	}
	fileServer := http.FileServer(http.FS(sub))
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
		w.Header().Set("Pragma", "no-cache")
		w.Header().Set("Expires", "0")
		fileServer.ServeHTTP(w, r)
	})

	s.srv = &http.Server{
		Addr:         s.cfg.WebListen,
		Handler:      mux,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
	}

	return s.srv.ListenAndServe()
}

func (s *Server) Stop() error {
	if s.srv != nil {
		return s.srv.Close()
	}
	return nil
}

func (s *Server) checkWebAuth(r *http.Request) bool {
	if s.cfg.WebPassword == "" {
		return true
	}
	cookie, err := r.Cookie("foxy_session")
	if err == nil && cookie.Value != "" {
		if subtle.ConstantTimeCompare([]byte(cookie.Value), []byte(s.cfg.WebPassword)) == 1 {
			return true
		}
	}
	authHeader := r.Header.Get("Authorization")
	if strings.HasPrefix(authHeader, "Bearer ") {
		token := strings.TrimPrefix(authHeader, "Bearer ")
		if subtle.ConstantTimeCompare([]byte(token), []byte(s.cfg.WebPassword)) == 1 {
			return true
		}
	}
	return false
}

func (s *Server) authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.checkWebAuth(r) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"error":     "Unauthorized",
				"need_auth": true,
			})
			return
		}
		next(w, r)
	}
}

func (s *Server) handleAuthCheck(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	needAuth := s.cfg.WebPassword != ""
	authenticated := s.checkWebAuth(r)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"need_auth":     needAuth,
		"authenticated": authenticated,
	})
}

func (s *Server) handleWebAuthLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if s.cfg.WebPassword == "" || subtle.ConstantTimeCompare([]byte(req.Password), []byte(s.cfg.WebPassword)) == 1 {
		http.SetCookie(w, &http.Cookie{
			Name:     "foxy_session",
			Value:    req.Password,
			Path:     "/",
			HttpOnly: true,
			MaxAge:   86400 * 30,
		})
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"success": true})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"success": false,
		"error":   "Invalid password",
	})
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	status := s.manager.GetStatus()
	_ = json.NewEncoder(w).Encode(status)
}

func (s *Server) handleConnect(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Country string `json:"country"`
		Server  string `json:"server"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)

	err := s.manager.Connect(req.Country, req.Server)
	w.Header().Set("Content-Type", "application/json")
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]any{"success": false, "error": err.Error()})
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"success": true})
}

func (s *Server) handleDisconnect(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	err := s.manager.Disconnect()
	w.Header().Set("Content-Type", "application/json")
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]any{"success": false, "error": err.Error()})
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"success": true})
}

func (s *Server) handleServers(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	servers := s.manager.GetServers()
	_ = json.NewEncoder(w).Encode(servers)
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if req.Email == "" || req.Password == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]any{"success": false, "error": "Email and password are required"})
		return
	}

	err := s.manager.Login(req.Email, req.Password)
	w.Header().Set("Content-Type", "application/json")
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(map[string]any{"success": false, "error": err.Error()})
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"success": true})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	err := s.manager.Logout()
	w.Header().Set("Content-Type", "application/json")
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]any{"success": false, "error": err.Error()})
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"success": true})
}

func (s *Server) handleConfig(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if r.Method == http.MethodGet {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"web_listen":       s.cfg.WebListen,
			"has_password":     s.cfg.WebPassword != "",
			"socks_listen":     s.cfg.SocksListen,
			"auto_connect":     s.cfg.AutoConnect,
			"mode":             s.cfg.Mode,
			"selected_country": s.cfg.SelectedCountry,
			"selected_server":  s.cfg.SelectedServer,
			"log_level":        s.cfg.LogLevel,
			"email":            s.cfg.Email,
		})
		return
	}

	if r.Method == http.MethodPost {
		var req struct {
			WebPassword     *string `json:"web_password"`
			SocksListen     *string `json:"socks_listen"`
			AutoConnect     *bool   `json:"auto_connect"`
			Mode            *string `json:"mode"`
			SelectedCountry *string `json:"selected_country"`
			SelectedServer  *string `json:"selected_server"`
			LogLevel        *string `json:"log_level"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		newCfg := *s.cfg
		if req.WebPassword != nil {
			newCfg.WebPassword = *req.WebPassword
		}
		if req.SocksListen != nil {
			newCfg.SocksListen = *req.SocksListen
		}
		if req.AutoConnect != nil {
			newCfg.AutoConnect = *req.AutoConnect
		}
		if req.Mode != nil {
			newCfg.Mode = *req.Mode
		}
		if req.SelectedCountry != nil {
			newCfg.SelectedCountry = *req.SelectedCountry
		}
		if req.SelectedServer != nil {
			newCfg.SelectedServer = *req.SelectedServer
		}
		if req.LogLevel != nil {
			newCfg.LogLevel = *req.LogLevel
		}

		if err := s.manager.UpdateConfig(&newCfg); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			_ = json.NewEncoder(w).Encode(map[string]any{"success": false, "error": err.Error()})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"success": true})
		return
	}

	http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
}

func (s *Server) handleLogs(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	logs := s.manager.GetLogs()
	_ = json.NewEncoder(w).Encode(logs)
}

func (s *Server) handleClearLogs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	s.manager.ClearLogs()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"success": true})
}

func (s *Server) handleTest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Target string `json:"target"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if req.Target == "" {
		req.Target = "google.com:443"
	}

	latency, msg, err := s.manager.TestTarget(req.Target)
	w.Header().Set("Content-Type", "application/json")
	if err != nil {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"success": false,
			"target":  req.Target,
			"error":   err.Error(),
		})
		return
	}

	_ = json.NewEncoder(w).Encode(map[string]any{
		"success":    true,
		"target":     req.Target,
		"latency_ms": latency,
		"message":    msg,
	})
}

func (s *Server) handleGatewayStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	enabled := vpn.IsGatewayEnabled()
	_ = json.NewEncoder(w).Encode(map[string]any{"enabled": enabled})
}

func (s *Server) handleGatewayToggle(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Enable bool `json:"enable"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)

	out, err := vpn.SetGatewayEnabled(req.Enable)
	w.Header().Set("Content-Type", "application/json")
	if err != nil {
		_ = json.NewEncoder(w).Encode(map[string]any{"success": false, "error": out})
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "enabled": req.Enable})
}
