# Project Specification: WifiBridge

## 1. Project Overview
**WifiBridge** is a headless network appliance management daemon and Web UI designed for **Debian 13 (Trixie)**. It turns a Linux device with one Ethernet port (`eth0`), an integrated Wi-Fi radio (`wlan0`), and a USB Wi-Fi adapter (`wlan1`) into a portable travel router and VPN gateway.

### Core Architectural Principles
* **systemd-First Networking:** Utilize native `systemd` components (`systemd-networkd`, `systemd-resolved`) wherever supported.
* **Standard Linux Daemons for Missing Capabilities:** Delegate wireless authentication, Access Point hosting, and IPSec to `iwd`, `hostapd`, and `strongSwan` (`swanctl`), managed via `systemd` units and D-Bus.
* **Zero-Dependency Build & Single Binary Deployment:** Built in **Go** with vendored frontend assets embedded via `//go:embed` (no Node.js, no CSS compilers) and packaged natively via `dpkg-deb` (no external packaging wrappers).
* **Always-On Management Plane:** The downstream USB Wi-Fi Access Point (`wlan1`) remains persistently active so administrators never lose local access while reconfiguring upstream WAN connections.

---

## 2. Target Hardware & Network Topology

### Interface Assignments
To prevent interface name swapping across reboots, `systemd.link` files or driver-based matching must pin interfaces deterministically:
* **`eth0` (Onboard Ethernet):** Candidate Upstream WAN interface (Default Uplink) or LAN bridge member when WAN is wireless.
* **`wlan0` (Integrated Wi-Fi):** Candidate Upstream WAN interface (Station/Client mode via `iwd`).
* **`wlan1` (USB Wi-Fi Adapter):** Downstream LAN Access Point (`hostapd`), member of `br0`.
* **`br0` (Virtual Bridge):** Downstream LAN Bridge interface uniting `wlan1` and `eth0` (when `eth0` is not uplink).
* The `br0` bridge should always exist. When eth0 is the uplink the bridge will only have `wlan1` as a member. When `wlan0` is the uplink both `wlan1` and `eth0` should be members of the bridge.
* All LAN facing services should be bound to the bridge interface.


### Routing & NAT Model
* **No Layer 2 WAN Bridging:** Traffic is routed (Layer 3) and NATed (outbound masquerading in `wifibridge.nft` with IPSec bypass) from the downstream LAN bridge (`br0`) to the active upstream WAN interface (`eth0` or `wlan0`).
* **LAN Subnet:** `10.99.0.0/24` (Gateway/Appliance IP: `10.99.0.1` on `br0`).

---

## 3. Technology Stack & Build Environment

### Software Stack
* **Backend:** Go (1.23+), `net/http`, `://github.com`, `://github.com`, `golang.org/x/crypto/bcrypt`.
* **Frontend:** Server-rendered HTML (`html/template`), **Bootstrap 5** (`bootstrap.min.css`, `bootstrap.bundle.min.js`), **Bootstrap Icons** (`bootstrap-icons.min.css`, `bootstrap-icons.woff2`), **HTMX**, and **Alpine.js**. All static assets are vendored locally in `web/static/` so the UI functions 100% offline.
* **Packaging:** Native Debian packaging via `dpkg-deb --root-owner-group --build` producing `wifibridge_<version>_<arch>.deb`.

### Build Environment Requirements
* **Go Toolchain (1.23+)** with `CGO_ENABLED=0` for static cross-compilation (`amd64` / `arm64`).
* **`make`** (GNU Make).
* **`dpkg-deb`** (standard on Debian/Ubuntu/WSL2; fallback `tar` + `ar` archive script if building on macOS).

### Debian 13 (`apt`) Package Dependencies
Declared in `packaging/DEBIAN/control` under `Depends:`:
* `systemd`
* `systemd-resolved` *(explicitly required as it is a separate package in Debian)*
* `iwd`
* `hostapd`
* `strongswan-swanctl`
* `nftables` *(required by `systemd-networkd` for `IPMasquerade=ipv4`)*

---

## 4. Functional Requirements

### 4.1 First-Boot Setup & Authentication
* **State File:** `/var/lib/wifibridge/auth.json` (`0600`, `root:root`).
* **Onboarding Middleware:** On initial boot, if `auth.json` does not exist, all HTTP requests redirect (`302`) to `/setup`.
* **Credential Creation:** User sets an administrator `username` and `password` (stored as a bcrypt hash).
* **Session Management:** Authenticated sessions use `HttpOnly`, `SameSite=Strict` signed session cookies.

### 4.2 Default Out-of-the-Box Configuration
Upon package installation (`DEBIAN/postinst`) or initial service start without existing state:
1. **Upstream WAN:** `eth0` configured with `DHCP=yes` and `IPMasquerade=ipv4`.
2. **Downstream LAN Bridge (`br0`):** Bridge device `br0` created via `05-br0.netdev`.
3. **Downstream AP (`wlan1`):** Broadcasts an **Open** Wi-Fi network with SSID `WifiBridge` and bridges to `br0` via `bridge=br0`.
4. **LAN DHCP & DNS:** `systemd-networkd` serves DHCP leases (`10.99.0.100` – `10.99.0.250`) on `br0`; `systemd-resolved` listens on `10.99.0.1:53`.
5. **Web UI:** Listening on `10.99.0.1:80` bound to `br0`.

### 4.3 Upstream WAN Management (Uplink Switching)
Users can select either **Ethernet (`eth0`)** or **Wireless (`wlan0`)** as the active uplink:
* **Ethernet Mode:** `eth0` has `DHCP=yes` and `IPMasquerade=ipv4`. `wlan0` is disconnected/unconfigured. `eth0` is the active uplink and NOT a member of `br0`.
* **Wireless Mode:**
  * Scan available SSIDs via `iwd` D-Bus API (`net.connman.iwd`).
  * Support **Open**, **WPA2/WPA3-Personal (PSK)**, and **WPA2/WPA3-Enterprise (802.1x PEAP/TTLS/TLS)** networks.
  * Generate provisioning profiles in `/var/lib/iwd/<SSID>.open`, `.psk`, or `.8021x`.
  * `wlan0` `.network` file configured with `DHCP=yes` and `IPMasquerade=ipv4`.
  * `eth0` is enslaved to `br0` via `15-eth-bridge.network` (`Bridge=br0`).
* **Both Modes:**
  * `wlan1` is always enslaved to `br0`.
  * LAN facing services, DHCP, DNS, Admin GUI, etc are always bound to the `br0` interface.
* **Failsafe Rollback:** When switching uplinks, if the new uplink fails to acquire a lease/route within 60 seconds, automatically revert to the previous working configuration and display an alert banner in the Web UI.

### 4.4 Downstream Access Point Configuration (`wlan1`)
* Configure via `/etc/hostapd/hostapd.conf` and restart `hostapd.service`.
* Configurable fields:
  * **SSID** (Default: `WifiBridge`)
  * **Security Mode:** Open or WPA2-Personal (PSK)
  * **Passphrase:** 8–63 ASCII characters (when WPA2-PSK is selected)
  * **Channel / Band:** 2.4GHz / 5GHz channel selection (hardware dependent)

### 4.5 Local DHCP & DNS Proxy
* **DHCP Server:** Managed natively by `systemd-networkd` in `/etc/systemd/network/10-lan-ap.network` (`DHCPServer=yes`). Configurable subnet, pool range, and lease time.
* **DNS Proxy:** Managed natively by `systemd-resolved` via `/etc/systemd/resolved.conf.d/wifibridge.conf`:
  ```ini
  [Resolve]
  DNSStubListenerExtra=10.99.0.1
  ```

### 4.6 WireGuard VPN (`systemd-networkd`)
* Managed natively via `/etc/systemd/network/30-wg0.netdev` (`Kind=wireguard`) and `30-wg0.network`.
* Configurable fields:
  * Interface Private Key (with built-in Go keypair generator endpoint) & Local Tunnel IP
  * Peer Public Key, Preshared Key (optional), Endpoint (`host:port`), Persistent Keepalive
  * `AllowedIPs` (full tunnel `0.0.0.0/0` or split-tunnel subnets)
  * Toggle Enable/Disable and automatic MASQUERADE rules for tunnel traffic.

### 4.7 IPSec Site-to-Site VPN (`strongSwan`)
* Managed via `/etc/swanctl/conf.d/wifibridge-s2s.conf` and controlled via `swanctl --load-all` / `systemctl restart strongswan`.
* Configurable fields:
  * Local & Remote Gateway IPs/FQDNs
  * Authentication Method (Pre-Shared Key / IKEv2)
  * Local & Remote Traffic Selectors (Subnets)
  * IKEv2 & ESP Cipher Proposals (sensible modern defaults: AES-256-GCM / SHA256 / DH14+)
  * Toggle Enable/Disable and live tunnel status (`swanctl --list-sas`).

---

## 5. System Configuration File Layouts

The Go backend acts as a declarative configuration compiler, reading `/var/lib/wifibridge/config.json` and writing deterministic files:

| Target Path | Owner Service | Purpose |
| :--- | :--- | :--- |
| `/etc/systemd/network/05-br0.netdev` | `systemd-networkd` | Virtual bridge device definition (`Kind=bridge`). |
| `/etc/systemd/network/10-lan-br0.network` | `systemd-networkd` | Static IP (`10.99.0.1/24`), `DHCPServer=yes`, `IPv4Forwarding=yes` on `br0`. |
| `/etc/systemd/network/12-wlan-bridge.network` | `systemd-networkd` | Enslaves `wlan1` to `br0` |
| `/etc/systemd/network/15-eth-bridge.network` | `systemd-networkd` | Enslaves `eth0` to `br0` when `eth0` is not the active WAN uplink. |
| `/etc/systemd/network/20-wan.network` | `systemd-networkd` | Active WAN (`eth0` or `wlan0`), `DHCP=yes`, `IPMasquerade=ipv4`. |
| `/etc/systemd/network/30-wg0.netdev` | `systemd-networkd` | WireGuard interface & peer keys. |
| `/etc/systemd/network/30-wg0.network` | `systemd-networkd` | WireGuard IP addressing & routing. |
| `/etc/systemd/resolved.conf.d/wifibridge.conf` | `systemd-resolved` | Binds DNS stub listener to `10.99.0.1`. |
| `/etc/hostapd/hostapd.conf` | `hostapd` | USB Wi-Fi AP SSID, channel, WPA2-PSK settings, and `bridge=br0`. |
| `/var/lib/iwd/<ssid>.{open,psk,8021x}` | `iwd` | Upstream Wi-Fi credentials. |
| `/etc/swanctl/conf.d/wifibridge.conf` | `strongswan` | IPSec Site-to-Site IKEv2 connection definitions. |

---

## 6. Recommended Repository Structure

```text
wifibridge/
├── cmd/
│   └── wifibridge/
│       └── main.go                 # Entrypoint, CLI flags, HTTP server boot
├── internal/
│   ├── auth/
│   │   └── auth.go                 # First-boot setup, bcrypt, session cookies
│   ├── config/
│   │   └── state.go                # Desired state structs & JSON persistence
│   ├── network/
│   │   ├── applier.go              # Orchestrates template rendering & reloads
│   │   ├── systemd.go              # D-Bus & networkctl integration
│   │   ├── iwd.go                  # iwd D-Bus scanner & profile writer
│   │   ├── hostapd.go              # hostapd config renderer
│   │   ├── wireguard.go            # systemd .netdev/.network generator + keygen
│   │   └── ipsec.go                # strongSwan swanctl config & status parser
│   └── web/
│       ├── server.go               # HTTP router & middleware
│       ├── handlers.go             # HTMX & form handlers
│       └── embed.go                # //go:embed templates static
├── web/
│   ├── templates/                  # Go HTML templates (layout, setup, dashboard, vpn)
│   └── static/
│       ├── css/
│       │   ├── bootstrap.min.css
│       │   └── bootstrap-icons.min.css
│       ├── fonts/
│       │   └── bootstrap-icons.woff2
│       └── js/
│           ├── bootstrap.bundle.min.js
│           ├── htmx.min.js
│           └── alpine.min.js
├── packaging/
│   ├── DEBIAN/
│   │   ├── control                 # Debian package metadata & apt dependencies
│   │   ├── postinst                # Post-install script enabling systemd services
│   │   └── prerm                   # Pre-removal cleanup script
│   └── lib/
│       └── systemd/
│           └── system/
│               └── wifibridge.service  # systemd unit file for the Go daemon
├── go.mod
└── Makefile                        # Cross-compiles Go binary & runs dpkg-deb --build
```

---

## 7. Security & Service Hardening
* Web UI Binding: By default, bind the HTTP listener exclusively to the downstream LAN IP (10.99.0.1:80) so the management interface is never exposed to untrusted upstream WAN networks.
* Privilege Model: The wifibridge.service runs as root (required to write /etc/systemd/network/, /var/lib/iwd/, and invoke D-Bus unit restarts), protected by strict input sanitization on all rendered config templates to prevent newline/directive injection.
* Secrets Masking: Passwords, PSKs, and WireGuard private keys must never be echoed back in plain text in HTML inputs once saved (use placeholder indicators for existing secrets).
* Configure the firewall to block all incomming traffic on the external/public interface.

## 8. Admin GUI requirements.
* **Diff Changes:** Diff changes should be displayed in json format.
* **Interface Choices:** The GUI should present a list of available interfaces to choose from when configuring both WAN and LAN connections.
* **Dashboard:** 
  * The dashboard should also show the current public interface IP address information.
  * The active DHCP client leases should show the client DHCP leases.

## 9. Implementation Milestones (For AI Agent Execution)

1. Milestone 1 (Scaffold & Native .deb Packaging): Initialize Go module, download vendored Bootstrap 5 / Bootstrap Icons / HTMX / Alpine assets, and create Makefile, wifibridge.service, DEBIAN/control, and DEBIAN/postinst to build an installable .deb via dpkg-deb with default WifiBridge AP and eth0 NAT.
2. Milestone 2 (Auth & Bootstrap Web Shell): Implement /setup first-boot onboarding, login/session middleware, and responsive Bootstrap 5 + HTMX dashboard layout bound to 10.99.0.1:80.
3. Milestone 3 (AP & LAN Management): Build hostapd, systemd-networkd DHCP, and systemd-resolved config generators with live client lease status.
4. Milestone 4 (Uplink Switcher & iwd): Implement iwd D-Bus Wi-Fi scanning, Open/PSK/802.1x profile creation, and eth0 <-> wlan0 WAN switching.
5. Milestone 5 (VPN Modules): Implement native systemd-networkd WireGuard management and strongSwan (swanctl) IPSec Site-to-Site configuration with live tunnel status indicators.

## 10. Versioning.
* **Increment Directive:** Each time changes are made to the codebase, the version number must be incremented by 0.0.1 (patch increment).
* **Code Tree Locations:** The version exists in the following locations within the code tree, and all of these versions must match:
  1. `Makefile` (`VERSION ?= <version>`)
  2. `packaging/DEBIAN/control` (`Version: <version>`)
  3. `cmd/wifibridge/main.go` (`var Version = "<version>"`)
