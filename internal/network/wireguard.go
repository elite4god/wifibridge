package network

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"text/template"
	"wifibridge/internal/config"
)

const wgNetdevTemplate = `[NetDev]
Name=wg0
Kind=wireguard
Description=WifiBridge WireGuard VPN

[WireGuard]
PrivateKey={{.PrivateKey}}

[WireGuardPeer]
PublicKey={{.PeerPublicKey}}
{{if .PeerPresharedKey}}PresharedKey={{.PeerPresharedKey}}
{{end}}Endpoint={{.PeerEndpoint}}
AllowedIPs={{.AllowedIPs}}
PersistentKeepalive={{.PersistentKeepalive}}
`

const wgNetworkTemplate = `[Match]
Name=wg0

[Network]
Address={{.LocalIP}}
IPForward=yes
IPMasquerade=ipv4
`

// GenerateWireGuardKeyPair generates a new random Curve25519 WireGuard keypair.
func GenerateWireGuardKeyPair() (privateKey string, publicKey string, err error) {
	curve := ecdh.X25519()
	priv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return "", "", fmt.Errorf("failed to generate X25519 private key: %w", err)
	}

	pub := priv.PublicKey()
	privB64 := base64.StdEncoding.EncodeToString(priv.Bytes())
	pubB64 := base64.StdEncoding.EncodeToString(pub.Bytes())

	return privB64, pubB64, nil
}

// GenerateWireGuardNetdev creates the content for 30-wg0.netdev.
func GenerateWireGuardNetdev(cfg *config.WireGuardConfig) (string, error) {
	if cfg == nil {
		return "", errors.New("nil WireGuard config")
	}

	privKey := config.SanitizeInput(cfg.PrivateKey)
	pubKey := config.SanitizeInput(cfg.PeerPublicKey)
	psk := config.SanitizeInput(cfg.PeerPresharedKey)
	endpoint := config.SanitizeInput(cfg.PeerEndpoint)
	allowedIPs := config.SanitizeInput(cfg.AllowedIPs)
	if allowedIPs == "" {
		allowedIPs = "0.0.0.0/0"
	}

	keepalive := cfg.PersistentKeepalive
	if keepalive <= 0 {
		keepalive = 25
	}

	data := struct {
		PrivateKey          string
		PeerPublicKey       string
		PeerPresharedKey    string
		PeerEndpoint        string
		AllowedIPs          string
		PersistentKeepalive int
	}{
		PrivateKey:          privKey,
		PeerPublicKey:       pubKey,
		PeerPresharedKey:    psk,
		PeerEndpoint:        endpoint,
		AllowedIPs:          allowedIPs,
		PersistentKeepalive: keepalive,
	}

	tmpl, err := template.New("wgNetdev").Parse(wgNetdevTemplate)
	if err != nil {
		return "", err
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return "", err
	}

	return buf.String(), nil
}

// GenerateWireGuardNetwork creates the content for 30-wg0.network.
func GenerateWireGuardNetwork(cfg *config.WireGuardConfig) (string, error) {
	if cfg == nil {
		return "", errors.New("nil WireGuard config")
	}

	localIP := config.SanitizeInput(cfg.LocalIP)
	if localIP == "" {
		localIP = "10.100.0.2/24"
	}

	if _, _, err := net.ParseCIDR(localIP); err != nil {
		return "", fmt.Errorf("invalid LocalIP CIDR %q: %w", localIP, err)
	}

	data := struct {
		LocalIP string
	}{
		LocalIP: localIP,
	}

	tmpl, err := template.New("wgNetwork").Parse(wgNetworkTemplate)
	if err != nil {
		return "", err
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return "", err
	}

	return buf.String(), nil
}
