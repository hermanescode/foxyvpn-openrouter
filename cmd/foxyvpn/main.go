package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/hermanescode/foxyvpn-openrouter/pkg/config"
	"github.com/hermanescode/foxyvpn-openrouter/pkg/vpn"
	"github.com/hermanescode/foxyvpn-openrouter/pkg/web"
)

const version = "1.0.0"

func main() {
	configPathFlag := flag.String("config", "", "Path to config file (default: /etc/foxyvpn/config.json or ./config.json)")
	webListenFlag := flag.String("web", "", "Web UI listen address (e.g. :8080)")
	socksListenFlag := flag.String("socks", "", "SOCKS5 listen address (e.g. 0.0.0.0:1080)")
	versionFlag := flag.Bool("version", false, "Print version and exit")
	flag.Parse()

	if *versionFlag {
		fmt.Printf("FoxyVPN OpenRouter v%s\n", version)
		os.Exit(0)
	}

	configPath := *configPathFlag
	if configPath == "" {
		if os.Geteuid() == 0 {
			configPath = "/etc/foxyvpn/config.json"
		} else {
			configPath = "./config.json"
		}
	}

	cfg, err := config.LoadConfig(configPath)
	if err != nil {
		log.Fatalf("Failed to load config from %s: %v", configPath, err)
	}

	if *webListenFlag != "" {
		cfg.WebListen = *webListenFlag
	}
	if *socksListenFlag != "" {
		cfg.SocksListen = *socksListenFlag
	}

	fmt.Println("====================================================")
	fmt.Printf("🦊 FoxyVPN OpenRouter v%s\n", version)
	fmt.Printf("Web Dashboard : http://localhost%s\n", cfg.WebListen)
	fmt.Printf("SOCKS5 Proxy  : socks5://%s\n", cfg.SocksListen)
	fmt.Printf("Config File   : %s\n", configPath)
	fmt.Println("====================================================")

	manager := vpn.NewVPNManager(cfg)
	if err := manager.Start(); err != nil {
		log.Fatalf("Failed to start VPN manager: %v", err)
	}

	server := web.NewServer(cfg, manager)

	// Graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-sigChan
		fmt.Println("\nShutting down FoxyVPN...")
		_ = server.Stop()
		manager.Stop()
		os.Exit(0)
	}()

	if err := server.Start(); err != nil {
		log.Printf("Web server stopped: %v", err)
	}
}
