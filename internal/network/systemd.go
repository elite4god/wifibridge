package network

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"text/template"
	"time"
	"wifibridge/internal/config"
)

const bridgeNetdevTemplate = `[NetDev]
Name={{.Name}}
Kind=bridge
`

const ethBridgeNetworkTemplate = `[Match]
Name={{.Interface}}

[Network]
Bridge={{.Bridge}}
`

const lanNetworkTemplate = `[Match]
Name={{.Interface}}

[Network]
Address={{.Address}}
DHCPServer=yes
IPForward=yes

[DHCPServer]
PoolOffset={{.PoolOffset}}
PoolSize={{.PoolSize}}
DefaultLeaseTimeSec={{.LeaseTimeSec}}
DNS={{.DNS}}
`

const wanNetworkTemplate = `[Match]
Name={{.Interface}}

[Network]
DHCP=yes
IPForward=yes
IPMasquerade=ipv4
`

const resolvedConfTemplate = `[Resolve]
DNSStubListenerExtra={{.DNSStub}}
`

// BridgeNetdevData holds template parameters for 05-br0.netdev.
type BridgeNetdevData struct {
	Name string
}

// EthBridgeNetworkData holds template parameters for 15-eth-bridge.network.
type EthBridgeNetworkData struct {
	Interface string
	Bridge    string
}

// LANNetworkData holds template parameters for 10-lan-br0.network.
type LANNetworkData struct {
	Interface    string
	Address      string
	PoolOffset   int
	PoolSize     int
	LeaseTimeSec int
	DNS          string
}

// WANNetworkData holds template parameters for 20-wan.network.
type WANNetworkData struct {
	Interface string
}

// ResolvedConfData holds template parameters for resolved.conf.d/wifibridge.conf.
type ResolvedConfData struct {
	DNSStub string
}

// DHCPLease represents an active downstream client DHCP lease.
type DHCPLease struct {
	MACAddress string    `json:"mac_address"`
	IPAddress  string    `json:"ip_address"`
	Hostname   string    `json:"hostname"`
	ExpiresAt  time.Time `json:"expires_at"`
}

// WANStatus represents the current live status and IP configuration of the public/uplink interface.
type WANStatus struct {
	Interface string `json:"interface"`
	IPAddress string `json:"ip_address"`
	Gateway   string `json:"gateway"`
	DNS       string `json:"dns"`
	State     string `json:"state"`
	Online    bool   `json:"online"`
}

// SystemManager defines operations for interacting with underlying OS daemons.
type SystemManager interface {
	ReloadNetworkd() error
	RestartHostapd() error
	RestartResolved() error
	RestartIWD() error
	ReloadSwanctl() error
	CheckUplinkLease(iface string) (bool, string, error)
	GetDHCPLeases(sysRoot string) ([]DHCPLease, error)
	GetWANStatus(iface string) WANStatus
	ReloadNftables() error
}

// LinuxSystemManager executes actual host commands via systemctl / networkctl.
type LinuxSystemManager struct{}

func (s *LinuxSystemManager) ReloadNetworkd() error {
	cmd := exec.Command("networkctl", "reload")
	return cmd.Run()
}

func (s *LinuxSystemManager) RestartHostapd() error {
	cmd := exec.Command("systemctl", "restart", "hostapd")
	return cmd.Run()
}

func (s *LinuxSystemManager) RestartResolved() error {
	cmd := exec.Command("systemctl", "restart", "systemd-resolved")
	return cmd.Run()
}

func (s *LinuxSystemManager) RestartIWD() error {
	cmd := exec.Command("systemctl", "restart", "iwd")
	return cmd.Run()
}

func (s *LinuxSystemManager) ReloadSwanctl() error {
	cmd := exec.Command("swanctl", "--load-all")
	return cmd.Run()
}

func (s *LinuxSystemManager) ReloadNftables() error {
	return exec.Command("systemctl", "restart", "nftables").Run()
}

func (s *LinuxSystemManager) CheckUplinkLease(iface string) (bool, string, error) {
	cmd := exec.Command("networkctl", "status", iface)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return false, "", err
	}
	output := string(out)

	// Check if interface has routable state or an assigned IP
	hasRoutable := strings.Contains(output, "routable") || strings.Contains(output, "configured")
	var assignedIP string

	lines := strings.Split(output, "\n")
	for _, l := range lines {
		trimmed := strings.TrimSpace(l)
		if strings.HasPrefix(trimmed, "Address:") {
			parts := strings.Fields(trimmed)
			if len(parts) >= 2 {
				assignedIP = parts[1]
				break
			}
		}
	}

	return hasRoutable && assignedIP != "", assignedIP, nil
}

func (s *LinuxSystemManager) GetWANStatus(iface string) WANStatus {
	status := WANStatus{
		Interface: iface,
	}

	// 1. Query networkctl status <iface> if available
	cmd := exec.Command("networkctl", "status", iface)
	if out, err := cmd.CombinedOutput(); err == nil {
		status = ParseNetworkctlInterfaceStatus(string(out), iface)
	}

	// 2. Query Go net.InterfaceByName if IP is missing
	if status.IPAddress == "" {
		if ifc, err := net.InterfaceByName(iface); err == nil {
			if addrs, err := ifc.Addrs(); err == nil {
				for _, addr := range addrs {
					if ipNet, ok := addr.(*net.IPNet); ok {
						if ip4 := ipNet.IP.To4(); ip4 != nil && !ip4.IsLoopback() {
							status.IPAddress = ipNet.String()
							status.Online = true
							if status.State == "" {
								status.State = "routable"
							}
							break
						}
					}
				}
			}
		}
	}

	// 3. Fallback: Parse lease file in /run/systemd/netif/leases
	if status.IPAddress == "" {
		leasesDir := "/run/systemd/netif/leases"
		if entries, err := os.ReadDir(leasesDir); err == nil {
			for _, entry := range entries {
				if entry.IsDir() {
					continue
				}
				data, err := os.ReadFile(filepath.Join(leasesDir, entry.Name()))
				if err != nil {
					continue
				}
				text := string(data)
				if strings.Contains(text, "ROUTER=") || strings.Contains(text, "SERVER_ADDRESS=") {
					scanner := bufio.NewScanner(strings.NewReader(text))
					for scanner.Scan() {
						line := strings.TrimSpace(scanner.Text())
						if strings.HasPrefix(line, "ADDRESS=") {
							status.IPAddress = strings.TrimPrefix(line, "ADDRESS=")
							status.Online = true
							if status.State == "" {
								status.State = "routable"
							}
						} else if strings.HasPrefix(line, "ROUTER=") && status.Gateway == "" {
							status.Gateway = strings.TrimPrefix(line, "ROUTER=")
						} else if strings.HasPrefix(line, "DNS=") && status.DNS == "" {
							status.DNS = strings.TrimPrefix(line, "DNS=")
						}
					}
					if status.IPAddress != "" {
						break
					}
				}
			}
		}
	}

	return status
}

func (s *LinuxSystemManager) GetDHCPLeases(sysRoot string) ([]DHCPLease, error) {
	// If a custom sysRoot is given (e.g. during isolated tests), parse lease files in sysRoot
	if sysRoot != "" && sysRoot != "/" {
		leasesDir := filepath.Join(sysRoot, "run/systemd/netif/leases")
		return ParseSystemdLeases(leasesDir)
	}

	leaseMap := make(map[string]DHCPLease)

	// 0. Try targeted server-side leases for br0 by interface index
	if idx, err := GetIfIndex("br0"); err == nil {
		leasePath := "/run/systemd/netif/leases/" + idx
		entries, _ := os.ReadDir(leasePath)
		if entries == nil {
			// It may be a single file (older format) or a directory
			if lease, err := parseSingleLease(leasePath); err == nil && lease.IPAddress != "" && lease.IPAddress != "10.99.0.1" {
				leaseMap[lease.IPAddress] = lease
			}
		} else {
			for _, e := range entries {
				if !e.IsDir() {
					if lease, err := parseSingleLease(filepath.Join(leasePath, e.Name())); err == nil && lease.IPAddress != "" && lease.IPAddress != "10.99.0.1" {
						leaseMap[lease.IPAddress] = lease
					}
				}
			}
		}
	}

	// 1. Try querying networkctl status for active server leases (Offered DHCP leases)
	cmd := exec.Command("networkctl", "status", "*")
	if out, err := cmd.CombinedOutput(); err == nil {
		for _, l := range ParseNetworkctlStatus(string(out)) {
			if l.IPAddress != "" && l.IPAddress != "10.99.0.1" {
				leaseMap[l.IPAddress] = l
			}
		}
	}

	// 2. Read /proc/net/arp for connected clients on downstream LAN bridge interface
	if arpBytes, err := os.ReadFile("/proc/net/arp"); err == nil {
		arpLeases := ParseARPTable(string(arpBytes), "br0", "10.99.0.0/24")
		for _, l := range arpLeases {
			if _, exists := leaseMap[l.IPAddress]; !exists {
				leaseMap[l.IPAddress] = l
			}
		}
	}

	// 3. Fallback: ParseSystemdLeases in /run/systemd/netif/leases (if any valid client leases exist)
	if len(leaseMap) == 0 {
		leasesDir := "/run/systemd/netif/leases"
		if fileLeases, err := ParseSystemdLeases(leasesDir); err == nil {
			for _, l := range fileLeases {
				if l.IPAddress != "" && l.IPAddress != "10.99.0.1" {
					leaseMap[l.IPAddress] = l
				}
			}
		}
	}

	var result []DHCPLease
	for _, l := range leaseMap {
		result = append(result, l)
	}

	sort.Slice(result, func(i, j int) bool {
		return result[i].IPAddress < result[j].IPAddress
	})

	return result, nil
}

// MockSystemManager is used in development and tests.
type MockSystemManager struct {
	UplinkSuccess bool
	AssignedIP    string
	GatewayIP     string
	DNS           string
	State         string
	MockLeases    []DHCPLease
}

func (m *MockSystemManager) ReloadNetworkd() error  { return nil }
func (m *MockSystemManager) RestartHostapd() error  { return nil }
func (m *MockSystemManager) RestartResolved() error { return nil }
func (m *MockSystemManager) RestartIWD() error      { return nil }
func (m *MockSystemManager) ReloadSwanctl() error   { return nil }
func (m *MockSystemManager) ReloadNftables() error  { return nil }
func (m *MockSystemManager) CheckUplinkLease(iface string) (bool, string, error) {
	return m.UplinkSuccess, m.AssignedIP, nil
}
func (m *MockSystemManager) GetDHCPLeases(sysRoot string) ([]DHCPLease, error) {
	if len(m.MockLeases) > 0 {
		return m.MockLeases, nil
	}
	leasesDir := filepath.Join(sysRoot, "run/systemd/netif/leases")
	return ParseSystemdLeases(leasesDir)
}
func (m *MockSystemManager) GetWANStatus(iface string) WANStatus {
	ip := m.AssignedIP
	if ip == "" && m.UplinkSuccess {
		ip = "192.168.1.150/24"
	}
	gw := m.GatewayIP
	if gw == "" && ip != "" {
		gw = "192.168.1.1"
	}
	dns := m.DNS
	if dns == "" && ip != "" {
		dns = "1.1.1.1"
	}
	state := m.State
	if state == "" {
		if ip != "" {
			state = "routable (configured)"
		} else {
			state = "disconnected"
		}
	}
	return WANStatus{
		Interface: iface,
		IPAddress: ip,
		Gateway:   gw,
		DNS:       dns,
		State:     state,
		Online:    ip != "",
	}
}

// GenerateBridgeNetdev generates content for 05-br0.netdev.
func GenerateBridgeNetdev(name string) (string, error) {
	if name == "" {
		name = "br0"
	}
	data := BridgeNetdevData{Name: name}
	tmpl, err := template.New("bridge_netdev").Parse(bridgeNetdevTemplate)
	if err != nil {
		return "", err
	}
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return "", err
	}
	return buf.String(), nil
}

// GenerateEthernetBridgeNetwork generates content for 15-eth-bridge.network.
func GenerateEthernetBridgeNetwork(iface, bridge string) (string, error) {
	if iface == "" {
		iface = "eth0"
	}
	if bridge == "" {
		bridge = "br0"
	}
	data := EthBridgeNetworkData{
		Interface: iface,
		Bridge:    bridge,
	}
	tmpl, err := template.New("eth_bridge").Parse(ethBridgeNetworkTemplate)
	if err != nil {
		return "", err
	}
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return "", err
	}
	return buf.String(), nil
}

// GenerateLANNetwork generates content for 10-lan-br0.network.
func GenerateLANNetwork(cfg *config.LANConfig) (string, error) {
	if cfg == nil {
		return "", errors.New("nil LAN config")
	}

	iface := cfg.Interface
	if iface == "" {
		iface = "br0"
	}

	gateway := cfg.GatewayIP
	if gateway == "" {
		gateway = "10.99.0.1"
	}

	subnet := cfg.Subnet
	if subnet == "" {
		subnet = "10.99.0.0/24"
	}

	// Calculate CIDR prefix
	_, ipNet, err := net.ParseCIDR(subnet)
	if err != nil {
		return "", fmt.Errorf("invalid subnet CIDR %q: %w", subnet, err)
	}
	ones, _ := ipNet.Mask.Size()
	addressWithCIDR := fmt.Sprintf("%s/%d", gateway, ones)

	offset := cfg.PoolOffset
	if offset <= 0 {
		offset = 100
	}

	size := cfg.PoolSize
	if size <= 0 {
		size = 151
	}

	leaseTime := cfg.LeaseTimeSec
	if leaseTime <= 0 {
		leaseTime = 86400
	}

	data := LANNetworkData{
		Interface:    iface,
		Address:      addressWithCIDR,
		PoolOffset:   offset,
		PoolSize:     size,
		LeaseTimeSec: leaseTime,
		DNS:          gateway,
	}

	tmpl, err := template.New("lan").Parse(lanNetworkTemplate)
	if err != nil {
		return "", err
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return "", err
	}
	return buf.String(), nil
}

// GenerateWANNetwork generates content for 20-wan.network.
func GenerateWANNetwork(cfg *config.WANConfig) (string, error) {
	if cfg == nil {
		return "", errors.New("nil WAN config")
	}

	iface := "eth0"
	if cfg.Mode == "wireless" {
		iface = "wlan0"
	}

	data := WANNetworkData{Interface: iface}
	tmpl, err := template.New("wan").Parse(wanNetworkTemplate)
	if err != nil {
		return "", err
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return "", err
	}
	return buf.String(), nil
}

// GenerateResolvedConf generates content for resolved.conf.d/wifibridge.conf.
func GenerateResolvedConf(gatewayIP string) (string, error) {
	if gatewayIP == "" {
		gatewayIP = "10.99.0.1"
	}
	data := ResolvedConfData{DNSStub: gatewayIP}
	tmpl, err := template.New("resolved").Parse(resolvedConfTemplate)
	if err != nil {
		return "", err
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return "", err
	}
	return buf.String(), nil
}

var (
	leaseLineRegex     = regexp.MustCompile(`(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+\(to\s+([0-9a-fA-F:-]{12,17})(?:,\s*"([^"]*)")?\)(?:,\s*expires in\s+([^\n\r]+))?`)
	durationTokenRegex = regexp.MustCompile(`(\d+)\s*([a-zA-Z]+)`)
)

func parseSystemdDuration(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	matches := durationTokenRegex.FindAllStringSubmatch(s, -1)
	if len(matches) == 0 {
		return 0, fmt.Errorf("invalid duration format: %q", s)
	}

	var total time.Duration
	for _, m := range matches {
		val, err := strconv.Atoi(m[1])
		if err != nil {
			continue
		}
		unit := strings.ToLower(m[2])
		switch unit {
		case "y", "years", "year":
			total += time.Duration(val) * 365 * 24 * time.Hour
		case "month", "months":
			total += time.Duration(val) * 30 * 24 * time.Hour
		case "w", "weeks", "week":
			total += time.Duration(val) * 7 * 24 * time.Hour
		case "d", "days", "day":
			total += time.Duration(val) * 24 * time.Hour
		case "h", "hr", "hrs", "hours", "hour":
			total += time.Duration(val) * time.Hour
		case "m", "min", "mins", "minutes", "minute":
			total += time.Duration(val) * time.Minute
		case "s", "sec", "secs", "seconds", "second":
			total += time.Duration(val) * time.Second
		case "ms":
			total += time.Duration(val) * time.Millisecond
		}
	}
	return total, nil
}

func extractLeaseFromMatch(match []string) DHCPLease {
	lease := DHCPLease{
		IPAddress:  match[1],
		MACAddress: strings.ToLower(match[2]),
		Hostname:   match[3],
		ExpiresAt:  time.Now().Add(24 * time.Hour),
	}
	if len(match) > 4 && strings.TrimSpace(match[4]) != "" {
		if dur, err := parseSystemdDuration(match[4]); err == nil {
			lease.ExpiresAt = time.Now().Add(dur)
		}
	}
	return lease
}

// ParseNetworkctlStatus parses active downstream leases from "networkctl status" output.
func ParseNetworkctlStatus(output string) []DHCPLease {
	var leases []DHCPLease
	lines := strings.Split(output, "\n")
	inOfferedSection := false

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		lower := strings.ToLower(trimmed)

		if strings.Contains(lower, "offered dhcp leases:") {
			inOfferedSection = true
			colonIdx := strings.Index(trimmed, ":")
			afterColon := strings.TrimSpace(trimmed[colonIdx+1:])
			if afterColon != "" {
				if match := leaseLineRegex.FindStringSubmatch(afterColon); match != nil {
					leases = append(leases, extractLeaseFromMatch(match))
				}
			}
			continue
		}

		if inOfferedSection {
			if match := leaseLineRegex.FindStringSubmatch(trimmed); match != nil {
				leases = append(leases, extractLeaseFromMatch(match))
			} else if strings.Contains(trimmed, ":") && !strings.Contains(trimmed, "(to") {
				inOfferedSection = false
			} else if trimmed == "" {
				inOfferedSection = false
			}
		}
	}
	return leases
}

// ParseNetworkctlInterfaceStatus parses output of "networkctl status <iface>" into a WANStatus.
func ParseNetworkctlInterfaceStatus(output string, iface string) WANStatus {
	status := WANStatus{
		Interface: iface,
	}

	lines := strings.Split(output, "\n")
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		colonIdx := strings.Index(trimmed, ":")
		if colonIdx == -1 {
			continue
		}
		key := strings.TrimSpace(trimmed[:colonIdx])
		val := strings.TrimSpace(trimmed[colonIdx+1:])

		switch key {
		case "State":
			status.State = val
			if strings.Contains(val, "routable") || strings.Contains(val, "configured") {
				status.Online = true
			}
		case "Address":
			if status.IPAddress == "" {
				fields := strings.Fields(val)
				if len(fields) > 0 {
					for _, f := range fields {
						cleanIP := strings.Trim(f, "(),")
						ipPart := cleanIP
						if idx := strings.Index(cleanIP, "/"); idx != -1 {
							ipPart = cleanIP[:idx]
						}
						if parsed := net.ParseIP(ipPart); parsed != nil && parsed.To4() != nil {
							status.IPAddress = cleanIP
							status.Online = true
							break
						}
					}
				}
			}
		case "Gateway":
			fields := strings.Fields(val)
			if len(fields) > 0 {
				status.Gateway = fields[0]
			}
		case "DNS":
			status.DNS = val
		}
	}

	return status
}

// ParseARPTable parses /proc/net/arp to find active LAN clients.
func ParseARPTable(content, lanIface, lanSubnet string) []DHCPLease {
	var leases []DHCPLease
	var ipNet *net.IPNet
	if lanSubnet != "" {
		_, ipNet, _ = net.ParseCIDR(lanSubnet)
	}

	lines := strings.Split(content, "\n")
	for i, line := range lines {
		if i == 0 {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 6 {
			continue
		}
		ipStr := fields[0]
		flags := fields[2]
		mac := fields[3]
		dev := fields[5]

		// Skip incomplete entries (flags 0x0 or zero MAC)
		if flags == "0x0" || mac == "00:00:00:00:00:00" {
			continue
		}

		// Filter by interface if specified
		if lanIface != "" && dev != lanIface {
			// If looking for br0, also accept member interfaces (wlan1 or eth0)
			if !(lanIface == "br0" && (dev == "wlan1" || dev == "eth0")) {
				continue
			}
		}

		// Filter by subnet if specified
		parsedIP := net.ParseIP(ipStr)
		if parsedIP == nil {
			continue
		}
		if ipNet != nil && !ipNet.Contains(parsedIP) {
			continue
		}

		// Never include the appliance gateway itself (10.99.0.1)
		if ipStr == "10.99.0.1" {
			continue
		}

		leases = append(leases, DHCPLease{
			IPAddress:  ipStr,
			MACAddress: strings.ToLower(mac),
			ExpiresAt:  time.Now().Add(24 * time.Hour),
		})
	}
	return leases
}

// GetIfIndex reads the kernel interface index for a given interface name.
func GetIfIndex(ifname string) (string, error) {
	data, err := os.ReadFile("/sys/class/net/" + ifname + "/ifindex")
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(data)), nil
}

// ParseSystemdLeases parses lease files in /run/systemd/netif/leases, ignoring upstream WAN gateway leases.
func ParseSystemdLeases(leasesDir string) ([]DHCPLease, error) {
	entries, err := os.ReadDir(leasesDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	var leases []DHCPLease
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		filePath := filepath.Join(leasesDir, entry.Name())
		lease, err := parseSingleLease(filePath)
		if err == nil && lease.IPAddress != "" && lease.IPAddress != "10.99.0.1" {
			leases = append(leases, lease)
		}
	}
	return leases, nil
}

func parseSingleLease(filePath string) (DHCPLease, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return DHCPLease{}, err
	}
	defer f.Close()

	var lease DHCPLease
	var isUpstreamClient bool
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "ADDRESS=") {
			lease.IPAddress = strings.TrimPrefix(line, "ADDRESS=")
		} else if strings.HasPrefix(line, "MAC_ADDRESS=") {
			lease.MACAddress = strings.TrimPrefix(line, "MAC_ADDRESS=")
		} else if strings.HasPrefix(line, "CLIENT_ID=") && lease.MACAddress == "" {
			lease.MACAddress = strings.TrimPrefix(line, "CLIENT_ID=")
		} else if strings.HasPrefix(line, "HOSTNAME=") {
			lease.Hostname = strings.TrimPrefix(line, "HOSTNAME=")
		} else if strings.HasPrefix(line, "ROUTER=") {
			isUpstreamClient = true
		} else if strings.HasPrefix(line, "LIFETIME=") {
			secsStr := strings.TrimPrefix(line, "LIFETIME=")
			if secs, err := strconv.Atoi(secsStr); err == nil {
				lease.ExpiresAt = time.Now().Add(time.Duration(secs) * time.Second)
			}
		}
	}
	if isUpstreamClient || lease.IPAddress == "10.99.0.1" {
		return DHCPLease{}, nil
	}
	return lease, scanner.Err()
}
