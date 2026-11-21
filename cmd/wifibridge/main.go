package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
	"wifibridge/internal/auth"
	"wifibridge/internal/config"
	"wifibridge/internal/network"
	"wifibridge/internal/web"
)

// Version is set at build time via -ldflags="-X main.Version=...".
var Version = "1.0.7"

func main() {
	var (
		listenAddr = flag.String("listen", "10.99.0.1:80", "HTTP server listen address (e.g. 10.99.0.1:80 or 127.0.0.1:8080)")
		stateDir   = flag.String("state-dir", "/var/lib/wifibridge", "Path to state directory for auth.json and config.json")
		sysRoot    = flag.String("sys-root", "/", "Root filesystem prefix for rendered system configurations")
		mockMode   = flag.Bool("mock", false, "Run in simulation/mock mode without executing root systemctl/D-Bus commands")
		showVer    = flag.Bool("version", false, "Print WifiBridge version and exit")
	)
	flag.Parse()

	if *showVer {
		fmt.Printf("WifiBridge version %s\n", Version)
		os.Exit(0)
	}

	// Environment variable override for listen address
	if envListen := os.Getenv("WIFIBRIDGE_LISTEN"); envListen != "" {
		*listenAddr = envListen
	}

	log.Printf("==================================================")
	log.Printf(" Starting WifiBridge Daemon v%s", Version)
	log.Printf(" Binding HTTP listener: %s", *listenAddr)
	log.Printf(" State directory:       %s", *stateDir)
	log.Printf(" Target system root:    %s", *sysRoot)
	log.Printf(" Simulation mock mode:  %v", *mockMode)
	log.Printf("==================================================")

	// Initialize State Manager
	cfgMgr, err := config.NewManager(*stateDir)
	if err != nil {
		log.Fatalf("FATAL: Failed to initialize config manager: %v", err)
	}

	// Initialize Authentication Manager
	authMgr, err := auth.NewManager(*stateDir)
	if err != nil {
		log.Fatalf("FATAL: Failed to initialize auth manager: %v", err)
	}

	// Select System Manager (Linux systemctl vs. Mock simulation)
	var sysMgr network.SystemManager
	if *mockMode {
		sysMgr = &network.MockSystemManager{
			UplinkSuccess: true,
			AssignedIP:    "192.168.1.150",
			MockLeases: []network.DHCPLease{
				{
					IPAddress:  "10.99.0.100",
					MACAddress: "da:a1:19:84:c2:4e",
					Hostname:   "iPhone-15",
					ExpiresAt:  time.Now().Add(18 * time.Hour),
				},
				{
					IPAddress:  "10.99.0.101",
					MACAddress: "3c:22:fb:a4:12:88",
					Hostname:   "MacBook-Air",
					ExpiresAt:  time.Now().Add(22 * time.Hour),
				},
			},
		}
	} else {
		sysMgr = &network.LinuxSystemManager{}
	}

	// Initialize Network Applier
	applier := network.NewApplier(cfgMgr, sysMgr, *sysRoot)

	// Ensure system config files exist on first startup
	liveCfg := cfgMgr.GetLive()
	if err := applier.ApplyFiles(liveCfg); err != nil {
		log.Printf("Warning: Initial file application returned error: %v", err)
	}

	// Adjust listenAddr if default and GatewayIP is custom
	if *listenAddr == "10.99.0.1:80" && liveCfg.LAN.GatewayIP != "" && liveCfg.LAN.GatewayIP != "10.99.0.1" {
		*listenAddr = liveCfg.LAN.GatewayIP + ":80"
	}

	// Initialize HTTP Server & Routes
	srv, err := web.NewServer(cfgMgr, authMgr, applier, sysMgr, *sysRoot, *mockMode)
	if err != nil {
		log.Fatalf("FATAL: Failed to initialize web server: %v", err)
	}

	httpServer := &http.Server{
		Addr:         *listenAddr,
		Handler:      srv,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Create TCP listener bound to bridge device (if non-loopback)
	ln, err := createBridgeListener(*listenAddr, liveCfg.LAN.Interface)
	if err != nil {
		log.Fatalf("FATAL: HTTP listener failed on %s: %v", *listenAddr, err)
	}

	// Run HTTP server in background goroutine
	go func() {
		log.Printf("Web UI active and listening on http://%s (bound to %s)", *listenAddr, liveCfg.LAN.Interface)
		if err := httpServer.Serve(ln); err != nil && err != http.ErrServerClosed {
			log.Fatalf("FATAL: HTTP listener failed: %v", err)
		}
	}()

	// Wait for termination signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	sig := <-sigChan
	log.Printf("Received termination signal %s; shutting down...", sig)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := httpServer.Shutdown(ctx); err != nil {
		log.Printf("Error during server shutdown: %v", err)
	}
	log.Printf("WifiBridge daemon stopped.")
}

func createBridgeListener(addr, iface string) (net.Listener, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}

	isLoopback := host == "127.0.0.1" || host == "::1" || host == "localhost"

	lc := net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			if !isLoopback && iface != "" {
				_ = c.Control(func(fd uintptr) {
					// unix.SO_BINDTODEVICE is 25 on Linux
					// Ignore error so execution succeeds if interface not yet created or non-root
					_ = syscall.SetsockoptString(int(fd), syscall.SOL_SOCKET, 25, iface)
				})
			}
			return nil
		},
	}
	return lc.Listen(context.Background(), "tcp", addr)
}
