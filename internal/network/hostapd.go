package network

import (
	"bytes"
	"errors"
	"fmt"
	"text/template"
	"wifibridge/internal/config"
)

const hostapdTemplate = `interface={{.Interface}}
{{if .Bridge}}bridge={{.Bridge}}
{{end}}driver=nl80211
ssid={{.SSID}}
hw_mode={{.HWMode}}
channel={{.Channel}}
ieee80211n=1
{{if eq .Security "wpa2-psk"}}
wpa=2
wpa_key_mgmt=WPA-PSK
rsn_pairwise=CCMP
wpa_passphrase={{.Passphrase}}
{{end}}
`

// HostapdTemplateData holds template parameters for hostapd.conf.
type HostapdTemplateData struct {
	Interface  string
	Bridge     string
	SSID       string
	HWMode     string
	Channel    int
	Security   string
	Passphrase string
}

// GenerateHostapdConf generates hostapd.conf content from an APConfig.
func GenerateHostapdConf(cfg *config.APConfig) (string, error) {
	if cfg == nil {
		return "", errors.New("nil AP config")
	}

	ssid := config.SanitizeInput(cfg.SSID)
	if ssid == "" {
		return "", errors.New("SSID cannot be empty")
	}
	if len(ssid) > 32 {
		return "", errors.New("SSID cannot exceed 32 octets")
	}

	channel := cfg.Channel
	if channel <= 0 {
		channel = 6
	}

	hwMode := "g"
	if cfg.Band == "5GHz" || channel > 14 {
		hwMode = "a"
	}

	security := cfg.Security
	if security != "wpa2-psk" {
		security = "open"
	}

	passphrase := config.SanitizeInput(cfg.Passphrase)
	if security == "wpa2-psk" {
		if len(passphrase) < 8 || len(passphrase) > 63 {
			return "", errors.New("WPA2 passphrase must be between 8 and 63 characters")
		}
	}

	bridge := cfg.Bridge
	if bridge == "" {
		bridge = "br0"
	}

	data := HostapdTemplateData{
		Interface:  cfg.Interface,
		Bridge:     bridge,
		SSID:       ssid,
		HWMode:     hwMode,
		Channel:    channel,
		Security:   security,
		Passphrase: passphrase,
	}
	if data.Interface == "" {
		data.Interface = "wlan1"
	}

	tmpl, err := template.New("hostapd").Parse(hostapdTemplate)
	if err != nil {
		return "", fmt.Errorf("failed to parse hostapd template: %w", err)
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return "", fmt.Errorf("failed to render hostapd template: %w", err)
	}

	return buf.String(), nil
}
