package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type Config struct {
	WebListen        string    `json:"web_listen"`
	WebPassword      string    `json:"web_password"`
	SocksListen      string    `json:"socks_listen"`
	AutoConnect      bool      `json:"auto_connect"`
	Mode             string    `json:"mode"` // "auto" or "manual"
	SelectedCountry  string    `json:"selected_country"`
	SelectedCity     string    `json:"selected_city"`
	SelectedServer   string    `json:"selected_server"`
	Email            string    `json:"email"`
	AccessToken      string    `json:"access_token"`
	RefreshToken     string    `json:"refresh_token"`
	ExpiresIn        int       `json:"expires_in"`
	ObtainedAt       time.Time `json:"obtained_at"`
	GuardianEndpoint string    `json:"guardian_endpoint"`
	UseH3            bool      `json:"use_h3"`
	Verbose          bool      `json:"verbose"`
	LogLevel         string    `json:"log_level"` // "debug", "info", "error", "none"

	filePath string     `json:"-"`
	mu       sync.Mutex `json:"-"`
}

func DefaultConfig(filePath string) *Config {
	return &Config{
		WebListen:        ":8080",
		WebPassword:      "",
		SocksListen:      "0.0.0.0:1080",
		AutoConnect:      true,
		Mode:             "auto",
		GuardianEndpoint: "https://vpn.mozilla.org",
		UseH3:            false,
		Verbose:          false,
		LogLevel:         "info",
		filePath:         filePath,
	}
}

func LoadConfig(filePath string) (*Config, error) {
	cfg := DefaultConfig(filePath)

	data, err := os.ReadFile(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			_ = cfg.Save()
			return cfg, nil
		}
		return nil, err
	}

	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, err
	}
	cfg.filePath = filePath
	return cfg, nil
}

func (c *Config) Save() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.filePath == "" {
		return nil
	}

	dir := filepath.Dir(c.filePath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(c.filePath, data, 0600)
}

func (c *Config) SetTokens(email, accessToken, refreshToken string, expiresIn int) error {
	c.mu.Lock()
	c.Email = email
	c.AccessToken = accessToken
	c.RefreshToken = refreshToken
	c.ExpiresIn = expiresIn
	c.ObtainedAt = time.Now()
	c.mu.Unlock()
	return c.Save()
}

func (c *Config) ClearTokens() error {
	c.mu.Lock()
	c.Email = ""
	c.AccessToken = ""
	c.RefreshToken = ""
	c.ExpiresIn = 0
	c.ObtainedAt = time.Time{}
	c.mu.Unlock()
	return c.Save()
}
