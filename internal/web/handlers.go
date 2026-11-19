package web

import (
	"fmt"
	"log"
	"net/http"
	"strconv"
	"wifibridge/internal/config"
	"wifibridge/internal/network"
)

// Setup Handlers
func (s *Server) handleSetupGet(w http.ResponseWriter, r *http.Request) {
	if s.authMgr.IsSetupComplete() {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	_ = s.templates["setup.html"].Execute(w, nil)
}

func (s *Server) handleSetupPost(w http.ResponseWriter, r *http.Request) {
	if s.authMgr.IsSetupComplete() {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")
	confirm := r.FormValue("confirm_password")

	if password != confirm {
		_ = s.templates["setup.html"].Execute(w, map[string]interface{}{
			"Error": "Passwords do not match.",
		})
		return
	}

	if err := s.authMgr.CreateAdmin(username, password); err != nil {
		_ = s.templates["setup.html"].Execute(w, map[string]interface{}{
			"Error": err.Error(),
		})
		return
	}

	s.authMgr.CreateSession(w)
	http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
}

// Login Handlers
func (s *Server) handleLoginGet(w http.ResponseWriter, r *http.Request) {
	if !s.authMgr.IsSetupComplete() {
		http.Redirect(w, r, "/setup", http.StatusFound)
		return
	}
	if s.authMgr.ValidateSession(r) {
		http.Redirect(w, r, "/dashboard", http.StatusFound)
		return
	}
	_ = s.templates["login.html"].Execute(w, nil)
}

func (s *Server) handleLoginPost(w http.ResponseWriter, r *http.Request) {
	username := r.FormValue("username")
	password := r.FormValue("password")

	if !s.authMgr.Authenticate(username, password) {
		_ = s.templates["login.html"].Execute(w, map[string]interface{}{
			"Error": "Invalid administrator username or password.",
		})
		return
	}

	s.authMgr.CreateSession(w)
	http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	s.authMgr.ClearSession(w)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// Dashboard Handler
func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	data := s.baseViewData("dashboard")
	_ = s.templates["dashboard.html"].Execute(w, data)
}

// WAN Handlers
func (s *Server) handleWANGet(w http.ResponseWriter, r *http.Request) {
	data := s.baseViewData("wan")
	_ = s.templates["wan.html"].Execute(w, data)
}

func (s *Server) handleWANPost(w http.ResponseWriter, r *http.Request) {
	mode := config.SanitizeInput(r.FormValue("mode"))
	if mode != "wireless" {
		mode = "ethernet"
	}

	wanIface := config.SanitizeInput(r.FormValue("wan_interface"))

	ssid := config.SanitizeInput(r.FormValue("ssid"))
	security := config.SanitizeInput(r.FormValue("security"))
	password := config.SanitizeInput(r.FormValue("password"))
	eapMethod := config.SanitizeInput(r.FormValue("eap_method"))
	eapIdentity := config.SanitizeInput(r.FormValue("eap_identity"))
	eapPassword := config.SanitizeInput(r.FormValue("eap_password"))

	_ = s.cfgMgr.UpdateStaged(func(cfg *config.Config) {
		cfg.WAN.Mode = mode
		if wanIface != "" {
			cfg.WAN.Interface = wanIface
		}
		if mode == "wireless" {
			cfg.WAN.SSID = ssid
			cfg.WAN.Security = security
			if password != "" {
				cfg.WAN.Password = password
			}
			cfg.WAN.EAPMethod = eapMethod
			cfg.WAN.EAPIdentity = eapIdentity
			if eapPassword != "" {
				cfg.WAN.EAPPassword = eapPassword
			}
		}
	})

	http.Redirect(w, r, "/wan", http.StatusSeeOther)
}

func (s *Server) handleWANScan(w http.ResponseWriter, r *http.Request) {
	networks, err := network.ScanNetworks(s.mock)
	if err != nil {
		networks = nil
	}

	_ = s.templates["wan_scan_partial.html"].Execute(w, map[string]interface{}{
		"Networks": networks,
	})
}

// Access Point Handlers
func (s *Server) handleAPGet(w http.ResponseWriter, r *http.Request) {
	data := s.baseViewData("ap")
	_ = s.templates["ap.html"].Execute(w, data)
}

func (s *Server) handleAPPost(w http.ResponseWriter, r *http.Request) {
	apIface := config.SanitizeInput(r.FormValue("ap_interface"))
	ssid := config.SanitizeInput(r.FormValue("ssid"))
	security := config.SanitizeInput(r.FormValue("security"))
	passphrase := config.SanitizeInput(r.FormValue("passphrase"))
	band := config.SanitizeInput(r.FormValue("band"))
	channel, _ := strconv.Atoi(r.FormValue("channel"))

	_ = s.cfgMgr.UpdateStaged(func(cfg *config.Config) {
		if apIface != "" {
			cfg.AP.Interface = apIface
		}
		if ssid != "" {
			cfg.AP.SSID = ssid
		}
		if security == "wpa2-psk" {
			cfg.AP.Security = "wpa2-psk"
			if passphrase != "" {
				cfg.AP.Passphrase = passphrase
			}
		} else {
			cfg.AP.Security = "open"
		}
		if band != "" {
			cfg.AP.Band = band
		}
		if channel > 0 {
			cfg.AP.Channel = channel
		}
	})

	http.Redirect(w, r, "/ap", http.StatusSeeOther)
}

// LAN Handlers
func (s *Server) handleLANGet(w http.ResponseWriter, r *http.Request) {
	data := s.baseViewData("lan")
	_ = s.templates["lan.html"].Execute(w, data)
}

func (s *Server) handleLANPost(w http.ResponseWriter, r *http.Request) {
	lanIface := config.SanitizeInput(r.FormValue("lan_interface"))
	gatewayIP := config.SanitizeInput(r.FormValue("gateway_ip"))
	subnet := config.SanitizeInput(r.FormValue("subnet"))
	offset, _ := strconv.Atoi(r.FormValue("pool_offset"))
	size, _ := strconv.Atoi(r.FormValue("pool_size"))
	leaseTime, _ := strconv.Atoi(r.FormValue("lease_time"))

	_ = s.cfgMgr.UpdateStaged(func(cfg *config.Config) {
		if lanIface != "" {
			cfg.LAN.Interface = lanIface
		}
		if gatewayIP != "" {
			cfg.LAN.GatewayIP = gatewayIP
		}
		if subnet != "" {
			cfg.LAN.Subnet = subnet
		}
		if offset > 0 {
			cfg.LAN.PoolOffset = offset
		}
		if size > 0 {
			cfg.LAN.PoolSize = size
		}
		if leaseTime > 0 {
			cfg.LAN.LeaseTimeSec = leaseTime
		}
	})

	http.Redirect(w, r, "/lan", http.StatusSeeOther)
}

// WireGuard Handlers
func (s *Server) handleWireGuardGet(w http.ResponseWriter, r *http.Request) {
	data := s.baseViewData("vpn")
	_ = s.templates["vpn_wireguard.html"].Execute(w, data)
}

func (s *Server) handleWireGuardPost(w http.ResponseWriter, r *http.Request) {
	enabled := r.FormValue("enabled") == "true"
	privKey := config.SanitizeInput(r.FormValue("private_key"))
	localIP := config.SanitizeInput(r.FormValue("local_ip"))
	peerPubKey := config.SanitizeInput(r.FormValue("peer_public_key"))
	peerPSK := config.SanitizeInput(r.FormValue("peer_preshared_key"))
	endpoint := config.SanitizeInput(r.FormValue("peer_endpoint"))
	allowedIPs := config.SanitizeInput(r.FormValue("allowed_ips"))
	keepalive, _ := strconv.Atoi(r.FormValue("persistent_keepalive"))

	_ = s.cfgMgr.UpdateStaged(func(cfg *config.Config) {
		cfg.WireGuard.Enabled = enabled
		if privKey != "" {
			cfg.WireGuard.PrivateKey = privKey
		}
		if localIP != "" {
			cfg.WireGuard.LocalIP = localIP
		}
		cfg.WireGuard.PeerPublicKey = peerPubKey
		if peerPSK != "" {
			cfg.WireGuard.PeerPresharedKey = peerPSK
		}
		cfg.WireGuard.PeerEndpoint = endpoint
		if allowedIPs != "" {
			cfg.WireGuard.AllowedIPs = allowedIPs
		}
		if keepalive > 0 {
			cfg.WireGuard.PersistentKeepalive = keepalive
		}
	})

	http.Redirect(w, r, "/vpn/wireguard", http.StatusSeeOther)
}

func (s *Server) handleWireGuardKeygen(w http.ResponseWriter, r *http.Request) {
	priv, pub, err := network.GenerateWireGuardKeyPair()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Returns updated HTML input fields for HTMX swap
	html := fmt.Sprintf(`
<div class="alert alert-success py-2 small mb-3">
    <i class="bi bi-check-circle me-1"></i> Generated fresh Curve25519 keypair. Your Peer Public Key to give to the server is: <strong>%s</strong>
</div>
<div class="mb-3">
    <label for="private_key" class="form-label small fw-bold">Interface Private Key</label>
    <input type="text" class="form-control font-monospace is-valid" id="private_key" name="private_key" value="%s" required>
</div>`, pub, priv)

	w.Header().Set("Content-Type", "text/html")
	_, _ = w.Write([]byte(html))
}

// IPSec Handlers
func (s *Server) handleIPSecGet(w http.ResponseWriter, r *http.Request) {
	data := s.baseViewData("vpn")
	_ = s.templates["vpn_ipsec.html"].Execute(w, data)
}

func (s *Server) handleIPSecPost(w http.ResponseWriter, r *http.Request) {
	enabled := r.FormValue("enabled") == "true"
	localGW := config.SanitizeInput(r.FormValue("local_gateway"))
	remoteGW := config.SanitizeInput(r.FormValue("remote_gateway"))
	psk := config.SanitizeInput(r.FormValue("psk"))
	localSubnet := config.SanitizeInput(r.FormValue("local_subnet"))
	remoteSubnet := config.SanitizeInput(r.FormValue("remote_subnet"))
	proposals := config.SanitizeInput(r.FormValue("proposals"))

	_ = s.cfgMgr.UpdateStaged(func(cfg *config.Config) {
		cfg.IPSec.Enabled = enabled
		if localGW != "" {
			cfg.IPSec.LocalGateway = localGW
		}
		cfg.IPSec.RemoteGateway = remoteGW
		if psk != "" {
			cfg.IPSec.PSK = psk
		}
		if localSubnet != "" {
			cfg.IPSec.LocalSubnet = localSubnet
		}
		cfg.IPSec.RemoteSubnet = remoteSubnet
		if proposals != "" {
			cfg.IPSec.Proposals = proposals
		}
	})

	http.Redirect(w, r, "/vpn/ipsec", http.StatusSeeOther)
}

// Config Push & Discard Handlers
func (s *Server) handleConfigPush(w http.ResponseWriter, r *http.Request) {
	if err := s.applier.PushStaged(); err != nil {
		log.Printf("ERROR: PushStaged failed: %v", err)
	}
	redirectBack(w, r, "/dashboard")
}

func (s *Server) handleConfigDiscard(w http.ResponseWriter, r *http.Request) {
	_ = s.cfgMgr.DiscardStaged()
	s.applier.ClearAlert()
	redirectBack(w, r, "/dashboard")
}
