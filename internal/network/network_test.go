package network

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"wifibridge/internal/config"
)

func TestHostapdConf(t *testing.T) {
	// Test Open AP
	openCfg := &config.APConfig{
		Interface: "wlan1",
		Bridge:    "br0",
		SSID:      "OpenBridge",
		Security:  "open",
		Channel:   6,
		Band:      "2.4GHz",
	}
	conf, err := GenerateHostapdConf(openCfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(conf, "ssid=OpenBridge") || strings.Contains(conf, "wpa_passphrase") {
		t.Errorf("unexpected open conf output:\n%s", conf)
	}
	if !strings.Contains(conf, "bridge=br0") {
		t.Errorf("expected bridge=br0 in conf, got:\n%s", conf)
	}

	// Test WPA2-PSK
	pskCfg := &config.APConfig{
		Interface:  "wlan1",
		Bridge:     "br0",
		SSID:       "SecureBridge",
		Security:   "wpa2-psk",
		Passphrase: "SuperSecurePassword123",
		Channel:    36,
		Band:       "5GHz",
	}
	confPSK, err := GenerateHostapdConf(pskCfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(confPSK, "hw_mode=a") || !strings.Contains(confPSK, "wpa_passphrase=SuperSecurePassword123") {
		t.Errorf("unexpected PSK conf output:\n%s", confPSK)
	}
	if !strings.Contains(confPSK, "bridge=br0") {
		t.Errorf("expected bridge=br0 in confPSK, got:\n%s", confPSK)
	}

	// Test invalid passphrase
	badPSK := &config.APConfig{
		Interface:  "wlan1",
		Bridge:     "br0",
		SSID:       "BadPSK",
		Security:   "wpa2-psk",
		Passphrase: "short",
		Channel:    6,
	}
	_, err = GenerateHostapdConf(badPSK)
	if err == nil {
		t.Errorf("expected error for short passphrase, got nil")
	}
}

func TestSystemdConfigs(t *testing.T) {
	brNetdev, err := GenerateBridgeNetdev("br0")
	if err != nil {
		t.Fatalf("failed to generate bridge netdev: %v", err)
	}
	if !strings.Contains(brNetdev, "Name=br0") || !strings.Contains(brNetdev, "Kind=bridge") {
		t.Errorf("unexpected bridge netdev:\n%s", brNetdev)
	}

	ethBridgeNet, err := GenerateInterfaceBridgeNetwork("eth0", "br0")
	if err != nil {
		t.Fatalf("failed to generate eth bridge net: %v", err)
	}
	if !strings.Contains(ethBridgeNet, "Name=eth0") || !strings.Contains(ethBridgeNet, "Bridge=br0") {
		t.Errorf("unexpected eth bridge net:\n%s", ethBridgeNet)
	}

	lanCfg := &config.LANConfig{
		Interface:    "br0",
		Subnet:       "10.99.0.0/24",
		GatewayIP:    "10.99.0.1",
		PoolOffset:   100,
		PoolSize:     151,
		LeaseTimeSec: 86400,
	}
	lanNet, err := GenerateLANNetwork(lanCfg)
	if err != nil {
		t.Fatalf("failed to generate LAN network: %v", err)
	}
	if !strings.Contains(lanNet, "Name=br0") || !strings.Contains(lanNet, "Address=10.99.0.1/24") || !strings.Contains(lanNet, "DHCPServer=yes") {
		t.Errorf("unexpected LAN network output:\n%s", lanNet)
	}

	wanEth := &config.WANConfig{Mode: "ethernet"}
	wanNetEth, err := GenerateWANNetwork(wanEth)
	if err != nil {
		t.Fatalf("failed to generate WAN eth: %v", err)
	}
	if !strings.Contains(wanNetEth, "Name=eth0") {
		t.Errorf("expected Name=eth0, got:\n%s", wanNetEth)
	}

	wanWifi := &config.WANConfig{Mode: "wireless"}
	wanNetWifi, err := GenerateWANNetwork(wanWifi)
	if err != nil {
		t.Fatalf("failed to generate WAN wifi: %v", err)
	}
	if !strings.Contains(wanNetWifi, "Name=wlan0") {
		t.Errorf("expected Name=wlan0, got:\n%s", wanNetWifi)
	}

	// Test custom interfaces
	wanCustomEth := &config.WANConfig{Mode: "ethernet", Interface: "enp3s0"}
	wanNetCustomEth, err := GenerateWANNetwork(wanCustomEth)
	if err != nil {
		t.Fatalf("failed to generate WAN custom eth: %v", err)
	}
	if !strings.Contains(wanNetCustomEth, "Name=enp3s0") {
		t.Errorf("expected Name=enp3s0, got:\n%s", wanNetCustomEth)
	}

	wanCustomWifi := &config.WANConfig{Mode: "wireless", Interface: "wlan2"}
	wanNetCustomWifi, err := GenerateWANNetwork(wanCustomWifi)
	if err != nil {
		t.Fatalf("failed to generate WAN custom wifi: %v", err)
	}
	if !strings.Contains(wanNetCustomWifi, "Name=wlan2") {
		t.Errorf("expected Name=wlan2, got:\n%s", wanNetCustomWifi)
	}

	// Test ListNetworkInterfaces
	ifaces := ListNetworkInterfaces()
	if len(ifaces) == 0 {
		t.Errorf("expected ListNetworkInterfaces to return at least 1 interface candidate")
	}

	resConf, err := GenerateResolvedConf("10.99.0.1")
	if err != nil {
		t.Fatalf("failed to generate resolved conf: %v", err)
	}
	if !strings.Contains(resConf, "DNSStubListenerExtra=10.99.0.1") {
		t.Errorf("unexpected resolved conf:\n%s", resConf)
	}
}

func TestWireGuardConfigAndKeygen(t *testing.T) {
	priv, pub, err := GenerateWireGuardKeyPair()
	if err != nil {
		t.Fatalf("failed to generate WireGuard keypair: %v", err)
	}
	if priv == "" || pub == "" {
		t.Errorf("generated keys cannot be empty")
	}

	wgCfg := &config.WireGuardConfig{
		Enabled:             true,
		PrivateKey:          priv,
		LocalIP:             "10.100.0.2/24",
		PeerPublicKey:       pub,
		PeerEndpoint:        "vpn.example.com:51820",
		AllowedIPs:          "0.0.0.0/0",
		PersistentKeepalive: 25,
	}

	netdev, err := GenerateWireGuardNetdev(wgCfg)
	if err != nil {
		t.Fatalf("failed to generate wg netdev: %v", err)
	}
	if !strings.Contains(netdev, "Kind=wireguard") || !strings.Contains(netdev, "Endpoint=vpn.example.com:51820") {
		t.Errorf("unexpected wg netdev:\n%s", netdev)
	}

	network, err := GenerateWireGuardNetwork(wgCfg)
	if err != nil {
		t.Fatalf("failed to generate wg network: %v", err)
	}
	if !strings.Contains(network, "Address=10.100.0.2/24") {
		t.Errorf("unexpected wg network:\n%s", network)
	}
}

func TestIPSecConfigAndParser(t *testing.T) {
	ipsecCfg := &config.IPSecConfig{
		Enabled:       true,
		LocalGateway:  "%defaultroute",
		RemoteGateway: "vpn.corp.com",
		AuthMethod:    "psk",
		PSK:           "corp-secret-psk-123",
		LocalSubnet:   "10.99.0.0/24",
		RemoteSubnet:  "192.168.10.0/24",
		Proposals:     "aes256-sha256-modp2048",
	}

	conf, err := GenerateSwanctlConf(ipsecCfg)
	if err != nil {
		t.Fatalf("failed to generate swanctl conf: %v", err)
	}
	if !strings.Contains(conf, "remote_addrs = vpn.corp.com") || !strings.Contains(conf, "secret = \"corp-secret-psk-123\"") {
		t.Errorf("unexpected swanctl conf:\n%s", conf)
	}

	mockOutput := `wifibridge-s2s: #1, ESTABLISHED, IKEv2
  net-to-net: #1, reqid 1, INSTALLED, TUNNEL, ESP:AES_GCM_16_128/MODP_2048
    installed 3600s ago, in: 12345B, out: 67890B`
	status := ParseSwanctlSAs(mockOutput)
	if !status.Connected || !status.Active {
		t.Errorf("expected IPSec status to be connected and active")
	}
}

func TestApplierAndFailsafe(t *testing.T) {
	stateDir, err := os.MkdirTemp("", "wb-state-*")
	if err != nil {
		t.Fatalf("failed temp dir: %v", err)
	}
	defer os.RemoveAll(stateDir)

	sysRoot, err := os.MkdirTemp("", "wb-sys-*")
	if err != nil {
		t.Fatalf("failed sys dir: %v", err)
	}
	defer os.RemoveAll(sysRoot)

	cfgMgr, err := config.NewManager(stateDir)
	if err != nil {
		t.Fatalf("failed config manager: %v", err)
	}

	mockSys := &MockSystemManager{
		UplinkSuccess: true,
		AssignedIP:    "192.168.1.50",
	}

	applier := NewApplier(cfgMgr, mockSys, sysRoot)
	applier.SetRollbackWait(100 * time.Millisecond)

	// Test Initial Push
	err = applier.PushStaged()
	if err != nil {
		t.Fatalf("failed to push staged: %v", err)
	}

	// Verify generated files exist in sysRoot
	expectedFiles := []string{
		filepath.Join(sysRoot, "etc/systemd/network/05-br0.netdev"),
		filepath.Join(sysRoot, "etc/systemd/network/10-lan-br0.network"),
		filepath.Join(sysRoot, "etc/systemd/network/15-wlan-bridge.network"),
		filepath.Join(sysRoot, "etc/systemd/network/16-eth-bridge.network"),
		filepath.Join(sysRoot, "etc/systemd/network/20-wan.network"),
		filepath.Join(sysRoot, "etc/systemd/resolved.conf.d/wifibridge.conf"),
		filepath.Join(sysRoot, "etc/hostapd/hostapd.conf"),
	}
	for _, f := range expectedFiles {
		if _, err := os.Stat(f); os.IsNotExist(err) {
			t.Errorf("expected generated file does not exist: %s", f)
		}
	}

	// In ethernet WAN mode, 16-eth-bridge.network should NOT exist
	ethBridgeFile := filepath.Join(sysRoot, "etc/systemd/network/16-eth-bridge.network")
	/*	if _, err := os.Stat(ethBridgeFile); !os.IsNotExist(err) {
			t.Errorf("16-eth-bridge.network should not exist when eth0 is the uplink")
		}
	*/
	// Test WAN Switch with Successful Verification
	err = cfgMgr.UpdateStaged(func(cfg *config.Config) {
		cfg.WAN.Mode = "wireless"
		cfg.WAN.SSID = "TestAP"
		cfg.WAN.Security = "psk"
		cfg.WAN.Password = "TestPassphrase123"
	})
	if err != nil {
		t.Fatalf("failed to stage WAN change: %v", err)
	}

	err = applier.PushStaged()
	if err != nil {
		t.Fatalf("failed to push staged WAN change: %v", err)
	}

	// In wireless WAN mode, eth0 should be a member of br0 via 16-eth-bridge.network
	if _, err := os.Stat(ethBridgeFile); os.IsNotExist(err) {
		t.Errorf("16-eth-bridge.network must exist when eth0 is not the uplink")
	}

	// Give monitor time to verify
	time.Sleep(250 * time.Millisecond)
	msg, alertType := applier.GetAlert()
	if alertType != "success" && alertType != "warning" {
		t.Errorf("expected success/warning alert, got %s: %s", alertType, msg)
	}

	// Test WAN Switch with Failed Verification -> Rollback
	mockSys.UplinkSuccess = false
	mockSys.AssignedIP = ""
	applier.SetRollbackWait(100 * time.Millisecond)

	err = cfgMgr.UpdateStaged(func(cfg *config.Config) {
		cfg.WAN.Mode = "ethernet"
	})
	if err != nil {
		t.Fatalf("failed to stage WAN revert: %v", err)
	}

	err = applier.PushStaged()
	if err != nil {
		t.Fatalf("failed to push WAN switch: %v", err)
	}

	// Wait for rollback timeout
	time.Sleep(400 * time.Millisecond)
	msg, alertType = applier.GetAlert()
	if alertType != "danger" || !strings.Contains(msg, "Automatically rolled back") {
		t.Errorf("expected danger rollback alert, got %s: %s", alertType, msg)
	}
	if _, err := os.Stat(ethBridgeFile); os.IsNotExist(err) {
		t.Errorf("16-eth-bridge.network must exist after rollback to wireless WAN")
	}
}

func TestParseNetworkctlStatus(t *testing.T) {
	mockOutput := `● 2: eth0
       Link File: /usr/lib/systemd/network/99-default.link
    Network File: /etc/systemd/network/20-wan.network
            Type: ether
           State: routable (configured)
         Address: 192.168.1.50

● 3: wlan1
       Link File: /usr/lib/systemd/network/99-default.link
    Network File: /etc/systemd/network/10-lan-ap.network
            Type: wlan
           State: routable (configured)
         Address: 10.99.0.1
   Offered DHCP leases: 10.99.0.100 (to 52:54:00:12:34:56, "ubuntu-client"), expires in 23h 58m 12s
                        10.99.0.101 (to aa:bb:cc:dd:ee:ff), expires in 45min 10s
                        10.99.0.102 (to 11:22:33:44:55:66, "pixel-8")
                  DHCP4: yes`

	leases := ParseNetworkctlStatus(mockOutput)
	if len(leases) != 3 {
		t.Fatalf("expected 3 leases, got %d", len(leases))
	}

	// Verify lease 1
	if leases[0].IPAddress != "10.99.0.100" || leases[0].MACAddress != "52:54:00:12:34:56" || leases[0].Hostname != "ubuntu-client" {
		t.Errorf("unexpected lease 0: %+v", leases[0])
	}
	if time.Until(leases[0].ExpiresAt) < 23*time.Hour {
		t.Errorf("expected expiration > 23h, got %v", time.Until(leases[0].ExpiresAt))
	}

	// Verify lease 2
	if leases[1].IPAddress != "10.99.0.101" || leases[1].MACAddress != "aa:bb:cc:dd:ee:ff" || leases[1].Hostname != "" {
		t.Errorf("unexpected lease 1: %+v", leases[1])
	}
	if time.Until(leases[1].ExpiresAt) > 46*time.Minute || time.Until(leases[1].ExpiresAt) < 44*time.Minute {
		t.Errorf("expected expiration around 45min, got %v", time.Until(leases[1].ExpiresAt))
	}

	// Verify lease 3
	if leases[2].IPAddress != "10.99.0.102" || leases[2].MACAddress != "11:22:33:44:55:66" || leases[2].Hostname != "pixel-8" {
		t.Errorf("unexpected lease 2: %+v", leases[2])
	}
}

func TestParseARPTable(t *testing.T) {
	mockARP := `IP address       HW type     Flags       HW address            Mask     Device
10.99.0.100      0x1         0x2         3c:22:fb:12:34:56     *        br0
10.99.0.101      0x1         0x0         00:00:00:00:00:00     *        br0
10.99.0.1        0x1         0x2         fe:ee:dd:cc:bb:aa     *        br0
10.99.0.102      0x1         0x2         da:a1:19:84:c2:4e     *        wlan1
192.168.1.1      0x1         0x2         00:11:22:33:44:55     *        eth0
`
	leases := ParseARPTable(mockARP, "br0", "10.99.0.0/24")
	if len(leases) != 2 {
		t.Fatalf("expected 2 valid ARP leases on br0/members, got %d", len(leases))
	}
	if leases[0].IPAddress != "10.99.0.100" || leases[0].MACAddress != "3c:22:fb:12:34:56" {
		t.Errorf("unexpected ARP lease 0: %+v", leases[0])
	}
	if leases[1].IPAddress != "10.99.0.102" || leases[1].MACAddress != "da:a1:19:84:c2:4e" {
		t.Errorf("unexpected ARP lease 1: %+v", leases[1])
	}
}

func TestParseNetworkctlInterfaceStatus(t *testing.T) {
	mockStatus := `● 2: eth0
                     Link File: /usr/lib/systemd/network/99-default.link
                  Network File: /etc/systemd/network/20-wan.network
                          Type: ether
                         State: routable (configured)
                  Online state: online
                       Address: 192.168.1.150 (DHCPv4 via 192.168.1.1)
                                fe80::3e22:fbff:fea4:1288
                       Gateway: 192.168.1.1
                           DNS: 1.1.1.1
`
	status := ParseNetworkctlInterfaceStatus(mockStatus, "eth0")
	if status.Interface != "eth0" {
		t.Errorf("expected eth0, got %s", status.Interface)
	}
	if status.IPAddress != "192.168.1.150" {
		t.Errorf("expected IP 192.168.1.150, got %s", status.IPAddress)
	}
	if status.Gateway != "192.168.1.1" {
		t.Errorf("expected Gateway 192.168.1.1, got %s", status.Gateway)
	}
	if status.DNS != "1.1.1.1" {
		t.Errorf("expected DNS 1.1.1.1, got %s", status.DNS)
	}
	if !status.Online {
		t.Errorf("expected status to be online")
	}

	// Test CIDR format Address
	mockStatusCIDR := `● 3: wlan0
                         State: routable (configured)
                       Address: 10.0.0.55/24
                       Gateway: 10.0.0.1
`
	statusCIDR := ParseNetworkctlInterfaceStatus(mockStatusCIDR, "wlan0")
	if statusCIDR.IPAddress != "10.0.0.55/24" {
		t.Errorf("expected IP 10.0.0.55/24, got %s", statusCIDR.IPAddress)
	}
	if statusCIDR.Gateway != "10.0.0.1" {
		t.Errorf("expected Gateway 10.0.0.1, got %s", statusCIDR.Gateway)
	}
}

func TestParseSystemdLeasesFilter(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "wb-leases-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// File 1: Upstream WAN lease received from gateway -> Must be ignored!
	wanLease := `ADDRESS=192.168.1.100
NETMASK=255.255.255.0
ROUTER=192.168.1.1
SERVER_ADDRESS=192.168.1.1
CLIENT_ID=01001122334455
`
	_ = os.WriteFile(filepath.Join(tempDir, "2"), []byte(wanLease), 0644)

	// File 2: Appliance own gateway address -> Must be ignored!
	gatewayLease := `ADDRESS=10.99.0.1
MAC_ADDRESS=fe:ed:fe:ed:fe:ed
`
	_ = os.WriteFile(filepath.Join(tempDir, "gateway"), []byte(gatewayLease), 0644)

	// File 3: Valid downstream client lease -> Must be included!
	clientLease := `ADDRESS=10.99.0.150
MAC_ADDRESS=12:34:56:78:90:ab
HOSTNAME=laptop-alpha
LIFETIME=3600
`
	_ = os.WriteFile(filepath.Join(tempDir, "client1"), []byte(clientLease), 0644)

	leases, err := ParseSystemdLeases(tempDir)
	if err != nil {
		t.Fatalf("ParseSystemdLeases error: %v", err)
	}

	if len(leases) != 1 {
		t.Fatalf("expected exactly 1 client lease, got %d", len(leases))
	}
	if leases[0].IPAddress != "10.99.0.150" || leases[0].Hostname != "laptop-alpha" {
		t.Errorf("unexpected client lease: %+v", leases[0])
	}
}

func TestWlan1BridgeFileWritten(t *testing.T) {
	stateDir, err := os.MkdirTemp("", "wb-state-*")
	if err != nil {
		t.Fatalf("failed temp state dir: %v", err)
	}
	defer os.RemoveAll(stateDir)

	sysRoot, err := os.MkdirTemp("", "wb-sys-*")
	if err != nil {
		t.Fatalf("failed temp sys dir: %v", err)
	}
	defer os.RemoveAll(sysRoot)

	cfgMgr, err := config.NewManager(stateDir)
	if err != nil {
		t.Fatalf("failed config manager: %v", err)
	}

	mockSys := &MockSystemManager{UplinkSuccess: true, AssignedIP: "192.168.1.50"}
	applier := NewApplier(cfgMgr, mockSys, sysRoot)

	live := cfgMgr.GetLive()
	if err := applier.ApplyFiles(live); err != nil {
		t.Fatalf("ApplyFiles failed: %v", err)
	}

	wlanBridgePath := filepath.Join(sysRoot, "etc/systemd/network/15-wlan-bridge.network")
	data, err := os.ReadFile(wlanBridgePath)
	if err != nil {
		t.Fatalf("15-wlan-bridge.network not written: %v", err)
	}
	content := string(data)
	if !strings.Contains(content, "Name=wlan0") {
		t.Errorf("expected Name=wlan0 in 15-wlan-bridge.network, got:\n%s", content)
	}
	if !strings.Contains(content, "Bridge=br0") {
		t.Errorf("expected Bridge=br0 in 15-wlan-bridge.network, got:\n%s", content)
	}
}

func TestParseSingleLeaseServerSide(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "wb-lease-srv-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Server-side lease from Debian 13 systemd-networkd DHCPServer:
	// contains SERVER_ADDRESS but should NOT be discarded — it is a downstream client lease.
	serverLease := `ADDRESS=10.99.0.105
MAC_ADDRESS=aa:bb:cc:dd:ee:ff
HOSTNAME=client-deb13
SERVER_ADDRESS=10.99.0.1
LIFETIME=86400
`
	leaseFile := filepath.Join(tempDir, "12345")
	if err := os.WriteFile(leaseFile, []byte(serverLease), 0644); err != nil {
		t.Fatalf("failed to write lease file: %v", err)
	}

	lease, err := parseSingleLease(leaseFile)
	if err != nil {
		t.Fatalf("parseSingleLease error: %v", err)
	}
	if lease.IPAddress != "10.99.0.105" {
		t.Errorf("expected IPAddress=10.99.0.105 (not discarded), got %q", lease.IPAddress)
	}
	if lease.MACAddress != "aa:bb:cc:dd:ee:ff" {
		t.Errorf("expected MACAddress=aa:bb:cc:dd:ee:ff, got %q", lease.MACAddress)
	}
}

func TestGetIfIndex(t *testing.T) {
	// A non-existent interface should return an error but not panic.
	_, err := GetIfIndex("nonexistent-iface-xyz")
	if err == nil {
		t.Error("expected error for non-existent interface, got nil")
	}
}

func TestGenerateNftablesRules(t *testing.T) {
	eth := GenerateNftablesRules("eth0")
	if !strings.Contains(eth, `iif "eth0"`) {
		t.Errorf("expected eth0 iif rule, got:\n%s", eth)
	}
	if !strings.Contains(eth, "table inet wifibridge") {
		t.Errorf("expected wifibridge table, got:\n%s", eth)
	}

	wlan := GenerateNftablesRules("wlan0")
	if !strings.Contains(wlan, `iif "wlan0"`) {
		t.Errorf("expected wlan0 iif rule, got:\n%s", wlan)
	}
}

func TestNftablesFileWritten(t *testing.T) {
	stateDir, err := os.MkdirTemp("", "wb-state-nft-*")
	if err != nil {
		t.Fatalf("failed temp dir: %v", err)
	}
	defer os.RemoveAll(stateDir)

	sysRoot, err := os.MkdirTemp("", "wb-sys-nft-*")
	if err != nil {
		t.Fatalf("failed temp sys dir: %v", err)
	}
	defer os.RemoveAll(sysRoot)

	cfgMgr, err := config.NewManager(stateDir)
	if err != nil {
		t.Fatalf("failed config manager: %v", err)
	}

	mockSys := &MockSystemManager{UplinkSuccess: true, AssignedIP: "192.168.1.50"}
	applier := NewApplier(cfgMgr, mockSys, sysRoot)

	live := cfgMgr.GetLive()
	if err := applier.ApplyFiles(live); err != nil {
		t.Fatalf("ApplyFiles failed: %v", err)
	}

	nftPath := filepath.Join(sysRoot, "etc/nftables.d/wifibridge.nft")
	data, err := os.ReadFile(nftPath)
	if err != nil {
		t.Fatalf("wifibridge.nft not written: %v", err)
	}
	content := string(data)
	if !strings.Contains(content, `iif "wlan1"`) {
		t.Errorf("expected iif \"wlan1\" in wifibridge.nft, got:\n%s", content)
	}
	if !strings.Contains(content, "table inet wifibridge") {
		t.Errorf("expected table inet wifibridge in wifibridge.nft, got:\n%s", content)
	}
}
