package network

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
	"wifibridge/internal/config"
)

// Applier orchestrates compiling configuration files, applying them to the system, and monitoring failsafe rollbacks.
type Applier struct {
	mu           sync.RWMutex
	cfgMgr       *config.Manager
	sysMgr       SystemManager
	sysRoot      string
	iwdDir       string
	alertBanner  string
	alertType    string // "warning", "danger", "success"
	inRollback   bool
	rollbackWait time.Duration
}

// NewApplier creates a network applier.
func NewApplier(cfgMgr *config.Manager, sysMgr SystemManager, sysRoot string) *Applier {
	if sysRoot == "" {
		sysRoot = "/"
	}
	return &Applier{
		cfgMgr:       cfgMgr,
		sysMgr:       sysMgr,
		sysRoot:      sysRoot,
		iwdDir:       filepath.Join(sysRoot, "var/lib/iwd"),
		rollbackWait: 60 * time.Second,
	}
}

// SetRollbackWait configures the timeout for tests or dev environments.
func (a *Applier) SetRollbackWait(d time.Duration) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.rollbackWait = d
}

// GetAlert returns any active alert banner message and its type.
func (a *Applier) GetAlert() (message string, alertType string) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.alertBanner, a.alertType
}

// ClearAlert clears any displayed alert banner.
func (a *Applier) ClearAlert() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.alertBanner = ""
	a.alertType = ""
}

// PushStaged commits staged changes and applies them to live system files.
func (a *Applier) PushStaged() error {
	live, backup, err := a.cfgMgr.CommitStaged()
	if err != nil {
		return fmt.Errorf("failed to commit staged config: %w", err)
	}

	if err := a.ApplyFiles(live); err != nil {
		return fmt.Errorf("failed to apply configuration files: %w", err)
	}

	a.reloadServices(live)

	// Check if WAN uplink changed; if so, trigger failsafe verification
	wanChanged := backup != nil && (live.WAN.Mode != backup.WAN.Mode ||
		(live.WAN.Mode == "wireless" && live.WAN.SSID != backup.WAN.SSID))

	if wanChanged {
		go a.monitorWANFailsafe(live, backup)
	} else {
		a.mu.Lock()
		a.alertBanner = "Configuration pushed and applied successfully to live system."
		a.alertType = "success"
		a.mu.Unlock()
	}

	return nil
}

// ApplyFiles renders and writes all system configuration files without restarting services.
func (a *Applier) ApplyFiles(cfg *config.Config) error {
	netDir := filepath.Join(a.sysRoot, "etc/systemd/network")
	resDir := filepath.Join(a.sysRoot, "etc/systemd/resolved.conf.d")
	hapdDir := filepath.Join(a.sysRoot, "etc/hostapd")
	swanDir := filepath.Join(a.sysRoot, "etc/swanctl/conf.d")

	for _, dir := range []string{netDir, resDir, hapdDir, swanDir, a.iwdDir} {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("failed to create directory %s: %w", dir, err)
		}
	}

	// 0. Bridge Netdev (05-br0.netdev)
	brName := cfg.LAN.Interface
	if brName == "" {
		brName = "br0"
	}
	brNetdevContent, err := GenerateBridgeNetdev(brName)
	if err != nil {
		return fmt.Errorf("bridge netdev error: %w", err)
	}
	if err := writeAtomic(filepath.Join(netDir, "05-br0.netdev"), brNetdevContent, 0644); err != nil {
		return err
	}

	// 1. LAN Network (10-lan-br0.network)
	lanContent, err := GenerateLANNetwork(&cfg.LAN)
	if err != nil {
		return fmt.Errorf("lan network error: %w", err)
	}
	if err := writeAtomic(filepath.Join(netDir, "10-lan-br0.network"), lanContent, 0644); err != nil {
		return err
	}
	// Clean up legacy 10-lan-ap.network if present
	_ = os.Remove(filepath.Join(netDir, "10-lan-ap.network"))

	// 1a. AP wireless interface always enslaved to br0 (15-wlan-bridge.network)
	apIface := cfg.AP.Interface
	if apIface == "" {
		apIface = "wlan0"
	}
	wlanBridgeContent, err := GenerateInterfaceBridgeNetwork(apIface, brName)
	if err != nil {
		return fmt.Errorf("ap interface %s bridge error: %w", apIface, err)
	}
	if err := writeAtomic(filepath.Join(netDir, "15-wlan-bridge.network"), wlanBridgeContent, 0644); err != nil {
		return err
	}

	// 1b. Ethernet member of bridge (16-eth-bridge.network)
	// The ethernet interface should be a member of this bridge if it is not the uplink interface.
	ethBridgePath := filepath.Join(netDir, "16-eth-bridge.network")
	ethInterface := cfg.ETH.Interface
	if ethInterface == "" {
		ethInterface = "eth0"
	}
	wanEthIface := cfg.WAN.Interface
	if wanEthIface == "" {
		wanEthIface = "wlan1"
	}
	if cfg.WAN.Mode != "ethernet" {
		ethBridgeContent, err := GenerateInterfaceBridgeNetwork(ethInterface, brName)
		if err != nil {
			return fmt.Errorf("eth bridge error: %w", err)
		}
		if err := writeAtomic(ethBridgePath, ethBridgeContent, 0644); err != nil {
			return err
		}
	} else {
		// ethInterface is the uplink WAN interface, so it is NOT a bridge member
		_ = os.Remove(ethBridgePath)
	}

	// 2. WAN Network (20-wan.network)
	wanContent, err := GenerateWANNetwork(&cfg.WAN)
	if err != nil {
		return fmt.Errorf("wan network error: %w", err)
	}
	if err := writeAtomic(filepath.Join(netDir, "20-wan.network"), wanContent, 0644); err != nil {
		return err
	}

	// 3. DNS Stub Listener (wifibridge.conf)
	resContent, err := GenerateResolvedConf(cfg.LAN.GatewayIP)
	if err != nil {
		return fmt.Errorf("resolved conf error: %w", err)
	}
	if err := writeAtomic(filepath.Join(resDir, "wifibridge.conf"), resContent, 0644); err != nil {
		return err
	}

	// 4. Hostapd AP (hostapd.conf)
	apCfg := cfg.AP
	if apCfg.Bridge == "" {
		apCfg.Bridge = brName
	}
	hapdContent, err := GenerateHostapdConf(&apCfg)
	if err != nil {
		return fmt.Errorf("hostapd conf error: %w", err)
	}
	if err := writeAtomic(filepath.Join(hapdDir, "hostapd.conf"), hapdContent, 0600); err != nil {
		return err
	}

	// 5. Upstream Wireless WAN Profile (iwd)
	if cfg.WAN.Mode == "wireless" && cfg.WAN.SSID != "" {
		if err := WriteIWDProfile(a.iwdDir, &cfg.WAN); err != nil {
			return fmt.Errorf("iwd profile error: %w", err)
		}
	}

	// 6. WireGuard (30-wg0.netdev & 30-wg0.network)
	wgNetdevPath := filepath.Join(netDir, "30-wg0.netdev")
	wgNetPath := filepath.Join(netDir, "30-wg0.network")
	if cfg.WireGuard.Enabled {
		netdevContent, err := GenerateWireGuardNetdev(&cfg.WireGuard)
		if err != nil {
			return fmt.Errorf("wg netdev error: %w", err)
		}
		if err := writeAtomic(wgNetdevPath, netdevContent, 0600); err != nil {
			return err
		}

		networkContent, err := GenerateWireGuardNetwork(&cfg.WireGuard)
		if err != nil {
			return fmt.Errorf("wg network error: %w", err)
		}
		if err := writeAtomic(wgNetPath, networkContent, 0644); err != nil {
			return err
		}
	} else {
		_ = os.Remove(wgNetdevPath)
		_ = os.Remove(wgNetPath)
	}

	// 7. IPSec (swanctl wifibridge.conf)
	swanPath := filepath.Join(swanDir, "wifibridge.conf")
	if cfg.IPSec.Enabled {
		swanContent, err := GenerateSwanctlConf(&cfg.IPSec)
		if err != nil {
			return fmt.Errorf("swanctl conf error: %w", err)
		}
		if err := writeAtomic(swanPath, swanContent, 0600); err != nil {
			return err
		}
	} else {
		_ = os.Remove(swanPath)
	}

	// 8. nftables WAN firewall (wifibridge.nft)
	wanIface := cfg.WAN.Interface
	if wanIface == "" {
		if cfg.WAN.Mode == "wireless" {
			wanIface = "wlan1"
		} else {
			wanIface = "eth0"
		}
	}
	nftDir := filepath.Join(a.sysRoot, "etc/nftables.d")
	if err := os.MkdirAll(nftDir, 0755); err != nil {
		return fmt.Errorf("nftables dir error: %w", err)
	}
	if err := writeAtomic(filepath.Join(nftDir, "wifibridge.nft"), GenerateNftablesRules(wanIface), 0644); err != nil {
		return err
	}

	return nil
}

func (a *Applier) reloadServices(cfg *config.Config) {
	_ = a.sysMgr.ReloadNftables()
	_ = a.sysMgr.ReloadNetworkd()
	_ = a.sysMgr.RestartHostapd()
	_ = a.sysMgr.RestartResolved()
	if cfg.WAN.Mode == "wireless" {
		_ = a.sysMgr.RestartIWD()
	}
	if cfg.IPSec.Enabled {
		_ = a.sysMgr.ReloadSwanctl()
	}
}

func (a *Applier) monitorWANFailsafe(newLive *config.Config, backup *config.Config) {
	a.mu.Lock()
	a.inRollback = false
	a.alertBanner = fmt.Sprintf("Verifying new %s WAN uplink connectivity (failsafe active for up to %v)...",
		newLive.WAN.Mode, a.rollbackWait)
	a.alertType = "warning"
	timeout := a.rollbackWait
	a.mu.Unlock()

	activeIface := newLive.WAN.Interface
	if activeIface == "" {
		if newLive.WAN.Mode == "wireless" {
			activeIface = "wlan1"
		} else {
			activeIface = "eth0"
		}
	}

	deadline := time.Now().Add(timeout)
	tickInterval := 2 * time.Second
	if timeout < 2*time.Second {
		tickInterval = 20 * time.Millisecond
	}
	ticker := time.NewTicker(tickInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			ok, assignedIP, _ := a.sysMgr.CheckUplinkLease(activeIface)
			if ok && assignedIP != "" {
				a.mu.Lock()
				a.alertBanner = fmt.Sprintf("WAN uplink verified successfully: %s active with IP %s.", activeIface, assignedIP)
				a.alertType = "success"
				a.mu.Unlock()
				return
			}

			if time.Now().After(deadline) {
				// Failsafe rollback triggered!
				a.executeRollback(backup)
				return
			}
		}
	}
}

func (a *Applier) executeRollback(backup *config.Config) {
	a.mu.Lock()
	a.inRollback = true
	a.alertBanner = "Uplink switch failed to acquire lease within timeout. Automatically rolled back to previous configuration."
	a.alertType = "danger"
	a.mu.Unlock()

	_, err := a.cfgMgr.Rollback()
	if err == nil && backup != nil {
		_ = a.ApplyFiles(backup)
		a.reloadServices(backup)
	}
}

func writeAtomic(path string, content string, mode os.FileMode) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(content), mode); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
