package network

import "fmt"

// GenerateNftablesRules produces an nftables ruleset that drops new inbound
// connections on the WAN interface while allowing established/related traffic
// and unrestricted LAN-side traffic.
func GenerateNftablesRules(wanIface string) string {
	return fmt.Sprintf(`#!/usr/sbin/nft -f
# WifiBridge managed nftables rules — do not edit manually.
table inet wifibridge {
    chain input {
        type filter hook input priority filter; policy accept;
        iif lo accept comment "loopback always allowed"
        ct state established,related accept comment "allow established sessions"
        iif %q ct state new drop comment "drop new inbound on WAN interface"
    }
    chain forward {
        type filter hook forward priority filter; policy accept;
    }
    chain output {
        type filter hook output priority filter; policy accept;
    }
}
`, wanIface)
}
