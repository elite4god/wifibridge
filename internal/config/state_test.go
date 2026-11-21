package config

import (
	"os"
	"testing"
)

func TestConfigManagerStaging(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "wifibridge-cfg-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	mgr, err := NewManager(tempDir)
	if err != nil {
		t.Fatalf("failed to initialize config manager: %v", err)
	}

	// Initial state: live matches default, no staged changes
	if mgr.HasStagedChanges() {
		t.Errorf("expected no staged changes initially")
	}

	live := mgr.GetLive()
	if live.AP.SSID != "WifiBridge" {
		t.Errorf("expected AP SSID to be WifiBridge, got %s", live.AP.SSID)
	}
	if live.LAN.Interface != "br0" {
		t.Errorf("expected LAN Interface to be br0, got %s", live.LAN.Interface)
	}
	if live.AP.Bridge != "br0" {
		t.Errorf("expected AP Bridge to be br0, got %s", live.AP.Bridge)
	}

	// Update staged configuration
	err = mgr.UpdateStaged(func(cfg *Config) {
		cfg.AP.SSID = "NewTravelAP"
		cfg.AP.Security = "wpa2-psk"
		cfg.AP.Passphrase = "SecretPass123"
	})
	if err != nil {
		t.Fatalf("failed to update staged config: %v", err)
	}

	if !mgr.HasStagedChanges() {
		t.Errorf("expected staged changes to be present")
	}

	diffs := mgr.GetDiff()
	if len(diffs) != 3 {
		t.Fatalf("expected 3 diff entries, got %d", len(diffs))
	}

	// Verify live config is still untouched
	live = mgr.GetLive()
	if live.AP.SSID != "WifiBridge" {
		t.Errorf("live config should remain WifiBridge, got %s", live.AP.SSID)
	}

	// Test discard
	err = mgr.DiscardStaged()
	if err != nil {
		t.Fatalf("failed to discard staged: %v", err)
	}
	if mgr.HasStagedChanges() {
		t.Errorf("expected no staged changes after discard")
	}
	staged := mgr.GetStaged()
	if staged.AP.SSID != "WifiBridge" {
		t.Errorf("staged config should be reverted to WifiBridge, got %s", staged.AP.SSID)
	}

	// Make another change and commit
	err = mgr.UpdateStaged(func(cfg *Config) {
		cfg.WAN.Mode = "wireless"
		cfg.WAN.Interface = "wlan2"
		cfg.WAN.SSID = "HotelWiFi"
		cfg.AP.Interface = "wlan3"
		cfg.LAN.Interface = "br1"
	})
	if err != nil {
		t.Fatalf("failed to update staged: %v", err)
	}

	diffs = mgr.GetDiff()
	hasWANInterfaceDiff := false
	hasAPInterfaceDiff := false
	hasLANInterfaceDiff := false
	for _, d := range diffs {
		if d.Section == "WAN" && d.Field == "Interface" && d.OldVal == "wlan1" && d.NewVal == "wlan2" {
			hasWANInterfaceDiff = true
		}
		if d.Section == "Access Point" && d.Field == "Interface" && d.OldVal == "wlan0" && d.NewVal == "wlan3" {
			hasAPInterfaceDiff = true
		}
		if d.Section == "LAN" && d.Field == "Interface" && d.OldVal == "br0" && d.NewVal == "br1" {
			hasLANInterfaceDiff = true
		}
	}
	if !hasWANInterfaceDiff {
		t.Errorf("expected WAN Interface diff from eth0 to wlan2")
	}
	if !hasAPInterfaceDiff {
		t.Errorf("expected AP Interface diff from wlan1 to wlan3")
	}
	if !hasLANInterfaceDiff {
		t.Errorf("expected LAN Interface diff from br0 to br1")
	}

	newLive, backup, err := mgr.CommitStaged()
	if err != nil {
		t.Fatalf("failed to commit staged: %v", err)
	}
	if newLive.WAN.Mode != "wireless" {
		t.Errorf("expected new live WAN mode to be wireless, got %s", newLive.WAN.Mode)
	}
	if newLive.WAN.Interface != "wlan2" {
		t.Errorf("expected new live WAN interface to be wlan2, got %s", newLive.WAN.Interface)
	}
	if newLive.AP.Interface != "wlan3" {
		t.Errorf("expected new live AP interface to be wlan3, got %s", newLive.AP.Interface)
	}
	if newLive.LAN.Interface != "br1" {
		t.Errorf("expected new live LAN interface to be br1, got %s", newLive.LAN.Interface)
	}
	if backup.WAN.Mode != "wireless" {
		t.Errorf("expected backup WAN mode to be wireless, got %s", backup.WAN.Mode)
	}
	if mgr.HasStagedChanges() {
		t.Errorf("expected no staged changes after commit")
	}

	// Test rollback
	restored, err := mgr.Rollback()
	if err != nil {
		t.Fatalf("failed to rollback: %v", err)
	}
	if restored.WAN.Mode != "wireless" {
		t.Errorf("expected restored WAN mode to be wireless, got %s", restored.WAN.Mode)
	}
}

func TestSanitizeInput(t *testing.T) {
	input := "SSID\r\nName\n"
	expected := "SSIDName"
	if got := SanitizeInput(input); got != expected {
		t.Errorf("expected %q, got %q", expected, got)
	}
}

func TestNormalizeConfigETHInterface(t *testing.T) {
	cfg := &Config{
		AP: APConfig{
			Interface: "wlan0",
		},
		ETH: ETHConfig{
			Interface: "",
		},
	}
	normalizeConfig(cfg)
	if cfg.ETH.Interface != "eth0" {
		t.Errorf("expected ETH.Interface to default to eth0, got %q", cfg.ETH.Interface)
	}
	if cfg.AP.Interface != "wlan0" {
		t.Errorf("expected AP.Interface to remain wlan0, got %q", cfg.AP.Interface)
	}
}
