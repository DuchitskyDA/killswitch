package policy

import "net/netip"

// LANPrefixes — назначения LAN при LAN=true: RFC1918, link-local, ULA.
// Это разрешённые назначения, а не доказанная локальная сеть.
var LANPrefixes = []netip.Prefix{
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("fc00::/7"),
	netip.MustParsePrefix("fe80::/10"),
}

// LANMulticast — mDNS и LLMNR; разрешаются только при LAN=true.
var LANMulticast = []netip.Prefix{
	netip.MustParsePrefix("224.0.0.251/32"),
	netip.MustParsePrefix("224.0.0.252/32"),
	netip.MustParsePrefix("ff02::fb/128"),
	netip.MustParsePrefix("ff02::1:3/128"),
}

// DNSPermits — что разрешено для TCP/UDP 53 на физических интерфейсах (матрица A11, рев. 5).
// Через туннельный интерфейс DNS разрешён всегда; флаг LAN на DNS не влияет.
type DNSPermits struct {
	LAN    bool           // к LANPrefixes
	DHCP   bool           // к резолверам, выданным DHCP/RA (Env.DHCPDNS)
	Listed []netip.Prefix // только к перечисленным (режим resolvers)
}

// DNSPermits считает разрешения DNS по режиму и состоянию туннеля (unknown передаётся как false).
func (p Policy) DNSPermits(tunnelUp bool) DNSPermits {
	switch p.DNS {
	case DNSResolvers:
		return DNSPermits{Listed: p.Resolvers}
	case DNSTunnelUp:
		if tunnelUp {
			return DNSPermits{}
		}
	}
	return DNSPermits{LAN: true, DHCP: true}
}
