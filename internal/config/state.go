package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
)

// Config represents the complete appliance network configuration.
type Config struct {
	WAN       WANConfig       `json:"wan"`
	LAN       LANConfig       `json:"lan"`
	AP        APConfig        `json:"ap"`
	WireGuard WireGuardConfig `json:"wireguard"`
	IPSec     IPSecConfig     `json:"ipsec"`
}

// WANConfig represents upstream WAN settings.
type WANConfig struct {
	Mode        string `json:"mode"`                   // "ethernet" or "wireless"
	Interface   string `json:"interface,omitempty"`    // e.g. "eth0", "enp3s0", "wlan0"
	SSID        string `json:"ssid,omitempty"`         // Wi-Fi WAN SSID
	Security    string `json:"security,omitempty"`     // "open", "psk", "8021x"
	Password    string `json:"password,omitempty"`     // Masked in UI
	EAPIdentity string `json:"eap_identity,omitempty"`
	EAPPassword string `json:"eap_password,omitempty"`
	EAPMethod   string `json:"eap_method,omitempty"`   // "PEAP", "TTLS", "TLS"
}

// LANConfig represents downstream LAN network and DHCP settings.
type LANConfig struct {
	Interface    string `json:"interface"`      // "br0"
	Subnet       string `json:"subnet"`         // "10.99.0.0/24"
	GatewayIP    string `json:"gateway_ip"`     // "10.99.0.1"
	PoolOffset   int    `json:"pool_offset"`    // 100 -> 10.99.0.100
	PoolSize     int    `json:"pool_size"`      // 151 -> up to 10.99.0.250
	LeaseTimeSec int    `json:"lease_time_sec"` // 86400
}

// APConfig represents downstream hostapd Access Point settings.
type APConfig struct {
	Interface  string `json:"interface"`            // "wlan1"
	Bridge     string `json:"bridge,omitempty"`     // "br0"
	SSID       string `json:"ssid"`                 // "WifiBridge"
	Security   string `json:"security"`             // "open" or "wpa2-psk"
	Passphrase string `json:"passphrase,omitempty"` // 8-63 ASCII
	Channel    int    `json:"channel"`              // e.g. 6 (2.4G) or 36 (5G)
	Band       string `json:"band"`                 // "2.4GHz" or "5GHz"
}

// WireGuardConfig represents systemd-networkd WireGuard VPN settings.
type WireGuardConfig struct {
	Enabled             bool   `json:"enabled"`
	PrivateKey          string `json:"private_key,omitempty"` // Masked in UI
	LocalIP             string `json:"local_ip"`              // e.g. "10.100.0.2/24"
	PeerPublicKey       string `json:"peer_public_key"`
	PeerPresharedKey    string `json:"peer_preshared_key,omitempty"`
	PeerEndpoint        string `json:"peer_endpoint"`         // host:port
	AllowedIPs          string `json:"allowed_ips"`           // default "0.0.0.0/0"
	PersistentKeepalive int    `json:"persistent_keepalive"`  // 25
}

// IPSecConfig represents strongSwan swanctl IPSec Site-to-Site settings.
type IPSecConfig struct {
	Enabled       bool   `json:"enabled"`
	LocalGateway  string `json:"local_gateway"`  // "%defaultroute" or IP
	RemoteGateway string `json:"remote_gateway"` // Remote peer IP/FQDN
	AuthMethod    string `json:"auth_method"`    // "psk"
	PSK           string `json:"psk,omitempty"`  // Masked in UI
	LocalSubnet   string `json:"local_subnet"`   // "10.99.0.0/24"
	RemoteSubnet  string `json:"remote_subnet"`  // Remote LAN subnet
	Proposals     string `json:"proposals"`      // e.g. "aes256-sha256-modp2048"
}

// ConfigChange represents a single detected difference between live and staged.
type ConfigChange struct {
	Section string `json:"section"`
	Field   string `json:"field"`
	OldVal  string `json:"old_val"`
	NewVal  string `json:"new_val"`
}

// Manager manages live and staged configurations with persistence.
type Manager struct {
	mu        sync.RWMutex
	stateDir  string
	live      *Config
	staged    *Config
	livePath  string
	stagePath string
	backPath  string
}

// DefaultConfig returns the initial default configuration per SPECS.md.
func DefaultConfig() *Config {
	return &Config{
		WAN: WANConfig{
			Mode:      "ethernet",
			Interface: "eth0",
		},
		LAN: LANConfig{
			Interface:    "br0",
			Subnet:       "10.99.0.0/24",
			GatewayIP:    "10.99.0.1",
			PoolOffset:   100,
			PoolSize:     151,
			LeaseTimeSec: 86400,
		},
		AP: APConfig{
			Interface: "wlan1",
			Bridge:    "br0",
			SSID:      "WifiBridge",
			Security:  "open",
			Channel:   6,
			Band:      "2.4GHz",
		},
		WireGuard: WireGuardConfig{
			Enabled:             false,
			LocalIP:             "10.100.0.2/24",
			AllowedIPs:          "0.0.0.0/0",
			PersistentKeepalive: 25,
		},
		IPSec: IPSecConfig{
			Enabled:      false,
			LocalGateway: "%defaultroute",
			AuthMethod:   "psk",
			LocalSubnet:  "10.99.0.0/24",
			Proposals:    "aes256-sha256-modp2048",
		},
	}
}

func normalizeConfig(cfg *Config) {
	if cfg == nil {
		return
	}
	if cfg.WAN.Interface == "" {
		if cfg.WAN.Mode == "wireless" {
			cfg.WAN.Interface = "wlan0"
		} else {
			cfg.WAN.Interface = "eth0"
		}
	}
	if cfg.LAN.Interface == "" || cfg.LAN.Interface == "wlan1" {
		cfg.LAN.Interface = "br0"
	}
	if cfg.AP.Bridge == "" {
		cfg.AP.Bridge = "br0"
	}
	if cfg.AP.Interface == "" {
		cfg.AP.Interface = "wlan1"
	}
}

// NewManager initializes a config manager from the given state directory.
func NewManager(stateDir string) (*Manager, error) {
	if err := os.MkdirAll(stateDir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create state directory: %w", err)
	}

	m := &Manager{
		stateDir:  stateDir,
		livePath:  filepath.Join(stateDir, "config.json"),
		stagePath: filepath.Join(stateDir, "staged_config.json"),
		backPath:  filepath.Join(stateDir, "config.backup.json"),
	}

	// Load live configuration or create default
	live, err := m.loadFromFile(m.livePath)
	if err != nil {
		if os.IsNotExist(err) {
			live = DefaultConfig()
			if err := m.saveToFile(m.livePath, live); err != nil {
				return nil, fmt.Errorf("failed to save default live config: %w", err)
			}
		} else {
			return nil, fmt.Errorf("failed to read live config: %w", err)
		}
	}
	normalizeConfig(live)
	m.live = live

	// Load staged configuration or clone from live
	staged, err := m.loadFromFile(m.stagePath)
	if err != nil {
		if os.IsNotExist(err) {
			staged = cloneConfig(m.live)
			if err := m.saveToFile(m.stagePath, staged); err != nil {
				return nil, fmt.Errorf("failed to save initial staged config: %w", err)
			}
		} else {
			return nil, fmt.Errorf("failed to read staged config: %w", err)
		}
	}
	normalizeConfig(staged)
	m.staged = staged

	return m, nil
}

// GetLive returns a deep copy of the currently active configuration.
func (m *Manager) GetLive() *Config {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return cloneConfig(m.live)
}

// GetStaged returns a deep copy of the staged configuration.
func (m *Manager) GetStaged() *Config {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return cloneConfig(m.staged)
}

// UpdateStaged applies an in-place mutation to the staged configuration and persists it.
func (m *Manager) UpdateStaged(fn func(*Config)) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	fn(m.staged)
	if err := m.saveToFile(m.stagePath, m.staged); err != nil {
		return fmt.Errorf("failed to persist staged config: %w", err)
	}
	return nil
}

// HasStagedChanges returns true if staged config differs from live config.
func (m *Manager) HasStagedChanges() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return !reflect.DeepEqual(m.live, m.staged)
}

// DiscardStaged resets the staged config to match the current live config.
func (m *Manager) DiscardStaged() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.staged = cloneConfig(m.live)
	return m.saveToFile(m.stagePath, m.staged)
}

// CommitStaged backs up the live config, promotes staged to live, and saves to disk.
func (m *Manager) CommitStaged() (live *Config, backup *Config, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Backup current live
	if err := m.saveToFile(m.backPath, m.live); err != nil {
		return nil, nil, fmt.Errorf("failed to write backup config: %w", err)
	}
	backup = cloneConfig(m.live)

	// Promote staged to live
	m.live = cloneConfig(m.staged)
	if err := m.saveToFile(m.livePath, m.live); err != nil {
		return nil, nil, fmt.Errorf("failed to save live config: %w", err)
	}

	return cloneConfig(m.live), backup, nil
}

// Rollback restores live config from backup and resets staged config.
func (m *Manager) Rollback() (*Config, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	backup, err := m.loadFromFile(m.backPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load backup config: %w", err)
	}

	m.live = backup
	m.staged = cloneConfig(backup)

	if err := m.saveToFile(m.livePath, m.live); err != nil {
		return nil, fmt.Errorf("failed to restore live config: %w", err)
	}
	if err := m.saveToFile(m.stagePath, m.staged); err != nil {
		return nil, fmt.Errorf("failed to restore staged config: %w", err)
	}

	return cloneConfig(m.live), nil
}

// GetDiff returns a slice of human-readable diffs between live and staged.
func (m *Manager) GetDiff() []ConfigChange {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var diffs []ConfigChange

	// WAN
	if m.live.WAN.Mode != m.staged.WAN.Mode {
		diffs = append(diffs, ConfigChange{"WAN", "Mode", m.live.WAN.Mode, m.staged.WAN.Mode})
	}
	if m.live.WAN.Interface != m.staged.WAN.Interface {
		diffs = append(diffs, ConfigChange{"WAN", "Interface", m.live.WAN.Interface, m.staged.WAN.Interface})
	}
	if m.live.WAN.SSID != m.staged.WAN.SSID {
		diffs = append(diffs, ConfigChange{"WAN", "SSID", m.live.WAN.SSID, m.staged.WAN.SSID})
	}
	if m.live.WAN.Security != m.staged.WAN.Security {
		diffs = append(diffs, ConfigChange{"WAN", "Security", m.live.WAN.Security, m.staged.WAN.Security})
	}
	if m.live.WAN.Password != m.staged.WAN.Password {
		diffs = append(diffs, ConfigChange{"WAN", "Password", maskVal(m.live.WAN.Password), maskVal(m.staged.WAN.Password)})
	}

	// LAN
	if m.live.LAN.Interface != m.staged.LAN.Interface {
		diffs = append(diffs, ConfigChange{"LAN", "Interface", m.live.LAN.Interface, m.staged.LAN.Interface})
	}
	if m.live.LAN.Subnet != m.staged.LAN.Subnet {
		diffs = append(diffs, ConfigChange{"LAN", "Subnet", m.live.LAN.Subnet, m.staged.LAN.Subnet})
	}
	if m.live.LAN.GatewayIP != m.staged.LAN.GatewayIP {
		diffs = append(diffs, ConfigChange{"LAN", "Gateway IP", m.live.LAN.GatewayIP, m.staged.LAN.GatewayIP})
	}
	if m.live.LAN.PoolOffset != m.staged.LAN.PoolOffset || m.live.LAN.PoolSize != m.staged.LAN.PoolSize {
		diffs = append(diffs, ConfigChange{"LAN", "DHCP Pool",
			fmt.Sprintf("offset:%d size:%d", m.live.LAN.PoolOffset, m.live.LAN.PoolSize),
			fmt.Sprintf("offset:%d size:%d", m.staged.LAN.PoolOffset, m.staged.LAN.PoolSize)})
	}
	if m.live.LAN.LeaseTimeSec != m.staged.LAN.LeaseTimeSec {
		diffs = append(diffs, ConfigChange{"LAN", "Lease Time",
			fmt.Sprintf("%d s", m.live.LAN.LeaseTimeSec),
			fmt.Sprintf("%d s", m.staged.LAN.LeaseTimeSec)})
	}

	// AP
	if m.live.AP.Interface != m.staged.AP.Interface {
		diffs = append(diffs, ConfigChange{"Access Point", "Interface", m.live.AP.Interface, m.staged.AP.Interface})
	}
	if m.live.AP.Bridge != m.staged.AP.Bridge {
		diffs = append(diffs, ConfigChange{"Access Point", "Bridge", m.live.AP.Bridge, m.staged.AP.Bridge})
	}
	if m.live.AP.SSID != m.staged.AP.SSID {
		diffs = append(diffs, ConfigChange{"Access Point", "SSID", m.live.AP.SSID, m.staged.AP.SSID})
	}
	if m.live.AP.Security != m.staged.AP.Security {
		diffs = append(diffs, ConfigChange{"Access Point", "Security", m.live.AP.Security, m.staged.AP.Security})
	}
	if m.live.AP.Passphrase != m.staged.AP.Passphrase {
		diffs = append(diffs, ConfigChange{"Access Point", "Passphrase", maskVal(m.live.AP.Passphrase), maskVal(m.staged.AP.Passphrase)})
	}
	if m.live.AP.Channel != m.staged.AP.Channel {
		diffs = append(diffs, ConfigChange{"Access Point", "Channel", fmt.Sprintf("%d", m.live.AP.Channel), fmt.Sprintf("%d", m.staged.AP.Channel)})
	}
	if m.live.AP.Band != m.staged.AP.Band {
		diffs = append(diffs, ConfigChange{"Access Point", "Band", m.live.AP.Band, m.staged.AP.Band})
	}

	// WireGuard
	if m.live.WireGuard.Enabled != m.staged.WireGuard.Enabled {
		diffs = append(diffs, ConfigChange{"WireGuard", "Enabled", fmt.Sprintf("%v", m.live.WireGuard.Enabled), fmt.Sprintf("%v", m.staged.WireGuard.Enabled)})
	}
	if m.live.WireGuard.LocalIP != m.staged.WireGuard.LocalIP {
		diffs = append(diffs, ConfigChange{"WireGuard", "Local IP", m.live.WireGuard.LocalIP, m.staged.WireGuard.LocalIP})
	}
	if m.live.WireGuard.PeerPublicKey != m.staged.WireGuard.PeerPublicKey {
		diffs = append(diffs, ConfigChange{"WireGuard", "Peer Public Key", m.live.WireGuard.PeerPublicKey, m.staged.WireGuard.PeerPublicKey})
	}
	if m.live.WireGuard.PeerEndpoint != m.staged.WireGuard.PeerEndpoint {
		diffs = append(diffs, ConfigChange{"WireGuard", "Peer Endpoint", m.live.WireGuard.PeerEndpoint, m.staged.WireGuard.PeerEndpoint})
	}
	if m.live.WireGuard.AllowedIPs != m.staged.WireGuard.AllowedIPs {
		diffs = append(diffs, ConfigChange{"WireGuard", "Allowed IPs", m.live.WireGuard.AllowedIPs, m.staged.WireGuard.AllowedIPs})
	}

	// IPSec
	if m.live.IPSec.Enabled != m.staged.IPSec.Enabled {
		diffs = append(diffs, ConfigChange{"IPSec", "Enabled", fmt.Sprintf("%v", m.live.IPSec.Enabled), fmt.Sprintf("%v", m.staged.IPSec.Enabled)})
	}
	if m.live.IPSec.RemoteGateway != m.staged.IPSec.RemoteGateway {
		diffs = append(diffs, ConfigChange{"IPSec", "Remote Gateway", m.live.IPSec.RemoteGateway, m.staged.IPSec.RemoteGateway})
	}
	if m.live.IPSec.LocalSubnet != m.staged.IPSec.LocalSubnet {
		diffs = append(diffs, ConfigChange{"IPSec", "Local Subnet", m.live.IPSec.LocalSubnet, m.staged.IPSec.LocalSubnet})
	}
	if m.live.IPSec.RemoteSubnet != m.staged.IPSec.RemoteSubnet {
		diffs = append(diffs, ConfigChange{"IPSec", "Remote Subnet", m.live.IPSec.RemoteSubnet, m.staged.IPSec.RemoteSubnet})
	}
	if m.live.IPSec.PSK != m.staged.IPSec.PSK {
		diffs = append(diffs, ConfigChange{"IPSec", "Pre-Shared Key", maskVal(m.live.IPSec.PSK), maskVal(m.staged.IPSec.PSK)})
	}

	return diffs
}

func maskVal(val string) string {
	if val == "" {
		return "<empty>"
	}
	return "••••••••"
}

func cloneConfig(src *Config) *Config {
	if src == nil {
		return nil
	}
	data, _ := json.Marshal(src)
	var dst Config
	_ = json.Unmarshal(data, &dst)
	return &dst
}

func (m *Manager) loadFromFile(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("malformed config JSON: %w", err)
	}
	return &cfg, nil
}

func (m *Manager) saveToFile(path string, cfg *Config) error {
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// SanitizeInput strips control characters (newlines/carriage returns) to prevent INI injection.
func SanitizeInput(s string) string {
	s = strings.ReplaceAll(s, "\r", "")
	s = strings.ReplaceAll(s, "\n", "")
	return strings.TrimSpace(s)
}
