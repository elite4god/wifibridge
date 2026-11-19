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
		cfg.WAN.SSID = "HotelWiFi"
	})
	if err != nil {
		t.Fatalf("failed to update staged: %v", err)
	}

	newLive, backup, err := mgr.CommitStaged()
	if err != nil {
		t.Fatalf("failed to commit staged: %v", err)
	}
	if newLive.WAN.Mode != "wireless" {
		t.Errorf("expected new live WAN mode to be wireless, got %s", newLive.WAN.Mode)
	}
	if backup.WAN.Mode != "ethernet" {
		t.Errorf("expected backup WAN mode to be ethernet, got %s", backup.WAN.Mode)
	}
	if mgr.HasStagedChanges() {
		t.Errorf("expected no staged changes after commit")
	}

	// Test rollback
	restored, err := mgr.Rollback()
	if err != nil {
		t.Fatalf("failed to rollback: %v", err)
	}
	if restored.WAN.Mode != "ethernet" {
		t.Errorf("expected restored WAN mode to be ethernet, got %s", restored.WAN.Mode)
	}
}

func TestSanitizeInput(t *testing.T) {
	input := "SSID\r\nName\n"
	expected := "SSIDName"
	if got := SanitizeInput(input); got != expected {
		t.Errorf("expected %q, got %q", expected, got)
	}
}
