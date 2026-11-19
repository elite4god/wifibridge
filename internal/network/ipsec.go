package network

import (
	"bytes"
	"errors"
	"os/exec"
	"strings"
	"text/template"
	"wifibridge/internal/config"
)

const swanctlTemplate = `connections {
  wifibridge-s2s {
    local_addrs = {{.LocalGateway}}
    remote_addrs = {{.RemoteGateway}}
    local {
      auth = psk
    }
    remote {
      auth = psk
    }
    children {
      net-to-net {
        local_ts = {{.LocalSubnet}}
        remote_ts = {{.RemoteSubnet}}
        esp_proposals = {{.ESPProposals}}
        start_action = start
      }
    }
    version = 2
    proposals = {{.IKEProposals}}
  }
}
secrets {
  ike-wifibridge {
    secret = "{{.PSK}}"
  }
}
`

// IPSecStatus represents live status of the IPSec tunnel.
type IPSecStatus struct {
	Active        bool   `json:"active"`
	Connected     bool   `json:"connected"`
	SecurityAssoc string `json:"security_assoc"`
	LocalHost     string `json:"local_host"`
	RemoteHost    string `json:"remote_host"`
	Uptime        string `json:"uptime"`
	Details       string `json:"details"`
}

// GenerateSwanctlConf renders swanctl configuration from IPSecConfig.
func GenerateSwanctlConf(cfg *config.IPSecConfig) (string, error) {
	if cfg == nil {
		return "", errors.New("nil IPSec config")
	}

	localGW := config.SanitizeInput(cfg.LocalGateway)
	if localGW == "" {
		localGW = "%defaultroute"
	}

	remoteGW := config.SanitizeInput(cfg.RemoteGateway)
	if remoteGW == "" {
		return "", errors.New("remote gateway cannot be empty")
	}

	psk := config.SanitizeInput(cfg.PSK)
	localSubnet := config.SanitizeInput(cfg.LocalSubnet)
	if localSubnet == "" {
		localSubnet = "10.99.0.0/24"
	}

	remoteSubnet := config.SanitizeInput(cfg.RemoteSubnet)
	if remoteSubnet == "" {
		return "", errors.New("remote subnet cannot be empty")
	}

	ikeProposals := config.SanitizeInput(cfg.Proposals)
	if ikeProposals == "" {
		ikeProposals = "aes256-sha256-modp2048"
	}
	espProposals := "aes256gcm128-sha256-modp2048,aes256-sha256-modp2048"

	data := struct {
		LocalGateway  string
		RemoteGateway string
		PSK           string
		LocalSubnet   string
		RemoteSubnet  string
		IKEProposals  string
		ESPProposals  string
	}{
		LocalGateway:  localGW,
		RemoteGateway: remoteGW,
		PSK:           psk,
		LocalSubnet:   localSubnet,
		RemoteSubnet:  remoteSubnet,
		IKEProposals:  ikeProposals,
		ESPProposals:  espProposals,
	}

	tmpl, err := template.New("swanctl").Parse(swanctlTemplate)
	if err != nil {
		return "", err
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return "", err
	}
	return buf.String(), nil
}

// ParseSwanctlSAs parses text output from swanctl --list-sas.
func ParseSwanctlSAs(output string) IPSecStatus {
	var status IPSecStatus
	lines := strings.Split(output, "\n")

	for _, l := range lines {
		trimmed := strings.TrimSpace(l)
		if strings.HasPrefix(trimmed, "wifibridge-s2s") {
			status.Connected = true
			status.Active = true
			status.SecurityAssoc = trimmed
		} else if strings.Contains(trimmed, "INSTALLED") {
			status.Connected = true
			status.Active = true
		}
	}

	if status.Connected {
		status.Details = "Tunnel established and active"
	} else {
		status.Details = "Disconnected or idle"
	}

	return status
}

// GetIPSecLiveStatus retrieves live IPSec status via swanctl or mock.
func GetIPSecLiveStatus(mock bool) IPSecStatus {
	if mock {
		return IPSecStatus{
			Active:    false,
			Connected: false,
			Details:   "Simulation mode (idle)",
		}
	}

	cmd := exec.Command("swanctl", "--list-sas")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return IPSecStatus{
			Active:    false,
			Connected: false,
			Details:   "swanctl inactive or not running",
		}
	}

	return ParseSwanctlSAs(string(out))
}
