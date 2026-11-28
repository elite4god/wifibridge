package network

import "fmt"

// GenerateNftablesRules produces an nftables ruleset that drops untrusted inbound
// connections on the WAN interface while allowing established traffic, IPSec tunnels,
// decapsulated VPN traffic, and provides NAT masquerade with IPSec bypass.
func GenerateNftablesRules(wanIface string) string {
	return fmt.Sprintf(`#!/usr/sbin/nft -f
# WifiBridge managed nftables rules — do not edit manually.
table inet wifibridge {
    chain input {
        type filter hook input priority filter; policy accept;
        iif lo accept comment "loopback always allowed"
        ct state established,related accept comment "allow established sessions"
        meta ipsec exists accept comment "allow inbound decapsulated ipsec traffic"
        udp dport { 500, 4500 } accept comment "allow IKE and NAT-T"
        ip protocol esp accept comment "allow ESP"
        iif %q ct state new drop comment "drop new inbound on WAN interface"
    }
    chain forward {
        type filter hook forward priority filter; policy accept;
        ip protocol tcp tcp flags syn tcp option maxseg size set rt mtu comment "TCP MSS clamping for VPN"
    }
    chain output {
        type filter hook output priority filter; policy accept;
    }
    chain postrouting {
        type nat hook postrouting priority srcnat; policy accept;
        meta ipsec exists accept comment "bypass masquerade for ipsec traffic"
        oif %q masquerade comment "masquerade outbound WAN traffic"
    }
}
`, wanIface, wanIface)
}
