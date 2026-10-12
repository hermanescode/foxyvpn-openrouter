package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type Account struct {
	Email         string    `json:"email"`
	Password      string    `json:"password,omitempty"`
	AccessToken   string    `json:"access_token"`
	RefreshToken  string    `json:"refresh_token"`
	ExpiresIn     int       `json:"expires_in"`
	ObtainedAt    time.Time `json:"obtained_at"`
	QuotaMax      int64     `json:"quota_max"`
	QuotaLeft     int64     `json:"quota_left"`
	QuotaReset    string    `json:"quota_reset"`
	LastCheckedAt time.Time `json:"last_checked_at"`
	Status        string    `json:"status"` // "active", "standby", "exhausted", "error"
	LastError     string    `json:"last_error,omitempty"`
}

type Config struct {
	WebListen          string    `json:"web_listen"`
	WebPassword        string    `json:"web_password"`
	SocksListen        string    `json:"socks_listen"`
	AutoConnect        bool      `json:"auto_connect"`
	Mode               string    `json:"mode"` // "auto" or "manual"
	SelectedCountry    string    `json:"selected_country"`
	SelectedCity       string    `json:"selected_city"`
	SelectedServer     string    `json:"selected_server"`
	Email              string    `json:"email"`
	AccessToken        string    `json:"access_token"`
	RefreshToken       string    `json:"refresh_token"`
	ExpiresIn          int       `json:"expires_in"`
	ObtainedAt         time.Time `json:"obtained_at"`
	GuardianEndpoint   string    `json:"guardian_endpoint"`
	UseH3              bool      `json:"use_h3"`
	Verbose            bool      `json:"verbose"`
	LogLevel           string    `json:"log_level"` // "debug", "info", "error", "none"
	Accounts           []Account `json:"accounts"`
	ActiveAccountEmail string    `json:"active_account_email"`
	AutoRotateAccounts bool      `json:"auto_rotate_accounts"`

	filePath string     `json:"-"`
	mu       sync.Mutex `json:"-"`
}

func DefaultConfig(filePath string) *Config {
	return &Config{
		WebListen:          ":8080",
		WebPassword:        "",
		SocksListen:        "0.0.0.0:1080",
		AutoConnect:        true,
		Mode:               "auto",
		GuardianEndpoint:   "https://vpn.mozilla.org",
		UseH3:              false,
		Verbose:            false,
		LogLevel:           "info",
		AutoRotateAccounts: true,
		filePath:           filePath,
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

	// Backward compatibility: migrate legacy single account to Accounts list
	if len(cfg.Accounts) == 0 && cfg.RefreshToken != "" && cfg.Email != "" {
		cfg.Accounts = append(cfg.Accounts, Account{
			Email:        cfg.Email,
			AccessToken:  cfg.AccessToken,
			RefreshToken: cfg.RefreshToken,
			ExpiresIn:    cfg.ExpiresIn,
			ObtainedAt:   cfg.ObtainedAt,
			Status:       "active",
		})
		cfg.ActiveAccountEmail = cfg.Email
	}

	return cfg, nil
}

func (c *Config) FilePath() string {
	return c.filePath
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
	c.ActiveAccountEmail = email

	found := false
	for i := range c.Accounts {
		if strings.EqualFold(c.Accounts[i].Email, email) {
			c.Accounts[i].AccessToken = accessToken
			c.Accounts[i].RefreshToken = refreshToken
			c.Accounts[i].ExpiresIn = expiresIn
			c.Accounts[i].ObtainedAt = c.ObtainedAt
			c.Accounts[i].Status = "active"
			found = true
			break
		}
	}
	if !found {
		c.Accounts = append(c.Accounts, Account{
			Email:        email,
			AccessToken:  accessToken,
			RefreshToken: refreshToken,
			ExpiresIn:    expiresIn,
			ObtainedAt:   c.ObtainedAt,
			Status:       "active",
		})
	}
	c.mu.Unlock()
	return c.Save()
}

func (c *Config) UpsertAccount(acc Account) error {
	c.mu.Lock()
	found := false
	for i := range c.Accounts {
		if strings.EqualFold(c.Accounts[i].Email, acc.Email) {
			c.Accounts[i] = acc
			found = true
			break
		}
	}
	if !found {
		c.Accounts = append(c.Accounts, acc)
	}
	c.mu.Unlock()
	return c.Save()
}

func (c *Config) RemoveAccount(email string) error {
	c.mu.Lock()
	var newAccs []Account
	for _, a := range c.Accounts {
		if !strings.EqualFold(a.Email, email) {
			newAccs = append(newAccs, a)
		}
	}
	c.Accounts = newAccs
	if strings.EqualFold(c.ActiveAccountEmail, email) {
		if len(newAccs) > 0 {
			c.ActiveAccountEmail = newAccs[0].Email
			c.Email = newAccs[0].Email
			c.AccessToken = newAccs[0].AccessToken
			c.RefreshToken = newAccs[0].RefreshToken
			c.ExpiresIn = newAccs[0].ExpiresIn
			c.ObtainedAt = newAccs[0].ObtainedAt
		} else {
			c.ActiveAccountEmail = ""
			c.Email = ""
			c.AccessToken = ""
			c.RefreshToken = ""
			c.ExpiresIn = 0
			c.ObtainedAt = time.Time{}
		}
	}
	c.mu.Unlock()
	return c.Save()
}

func (c *Config) SetActiveAccount(email string) (*Account, error) {
	c.mu.Lock()
	var selected *Account
	for i := range c.Accounts {
		if strings.EqualFold(c.Accounts[i].Email, email) {
			c.Accounts[i].Status = "active"
			c.ActiveAccountEmail = c.Accounts[i].Email
			c.Email = c.Accounts[i].Email
			c.AccessToken = c.Accounts[i].AccessToken
			c.RefreshToken = c.Accounts[i].RefreshToken
			c.ExpiresIn = c.Accounts[i].ExpiresIn
			c.ObtainedAt = c.Accounts[i].ObtainedAt
			selected = &c.Accounts[i]
		} else if c.Accounts[i].Status == "active" {
			c.Accounts[i].Status = "standby"
		}
	}
	c.mu.Unlock()
	if selected != nil {
		_ = c.Save()
	}
	return selected, nil
}

func (c *Config) UpdateAccountQuota(email string, quotaMax, quotaLeft int64, reset string) {
	c.mu.Lock()
	for i := range c.Accounts {
		if strings.EqualFold(c.Accounts[i].Email, email) {
			c.Accounts[i].QuotaMax = quotaMax
			c.Accounts[i].QuotaLeft = quotaLeft
			c.Accounts[i].QuotaReset = reset
			c.Accounts[i].LastCheckedAt = time.Now()
			// If remaining quota is < 5%, mark exhausted
			if quotaMax > 0 {
				pctRemaining := float64(quotaLeft) / float64(quotaMax) * 100
				if pctRemaining <= 5.0 {
					c.Accounts[i].Status = "exhausted"
				} else if c.Accounts[i].Status == "exhausted" {
					c.Accounts[i].Status = "standby"
				}
			}
			break
		}
	}
	c.mu.Unlock()
	_ = c.Save()
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
