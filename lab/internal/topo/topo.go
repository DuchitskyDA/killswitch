// Package topo описывает топологию лаборатории: имена namespace, интерфейсы и адреса.
// Все адреса вне LAN-диапазонов Policy: TEST-NET-2/3, 198.18.0.0/15 и 2001:db8::/32.
package topo

import "net/netip"

const (
	ClientNS = "ksl-client"
	WanNS    = "ksl-wan"
	VPNNS    = "ksl-vpn"
	InetNS   = "ksl-inet"

	PhysIf    = "c0" // физический интерфейс клиента
	CaptureIf = "wc" // сторона маршрутизатора на линии клиента — точка захвата

	HTTPPort      = 80
	UDPPort       = 443
	DNSPort       = 53
	NoServerTCP   = 81  // порт без сервера: проба обязана дать INCONCLUSIVE
	NoServerUDP   = 444 // то же для UDP
	MarkPort      = 9   // метка положительного контроля захвата
	MarkPrefix    = "KSLMARK:"
	DNSQueryName  = "probe.ksl.test"
	WGServerPort  = 51820
	WGClientPort  = 51821
	SingBoxPort   = 8388
	XrayPort      = 8389
	TunnelMetric  = "10"
	PhysMetric    = "100"
	ProxyMethod   = "2022-blake3-aes-128-gcm"
	ServeReadyMsg = `{"ready":true}`
)

var (
	ClientV4 = netip.MustParseAddr("198.51.100.2")
	ClientV6 = netip.MustParseAddr("2001:db8:c::2")
	WanCV4   = netip.MustParseAddr("198.51.100.1")
	WanCV6   = netip.MustParseAddr("2001:db8:c::1")

	VPNV4  = netip.MustParseAddr("203.0.113.2")
	VPNV6  = netip.MustParseAddr("2001:db8:a::2")
	WanVV4 = netip.MustParseAddr("203.0.113.1")
	WanVV6 = netip.MustParseAddr("2001:db8:a::1")

	InetV4 = netip.MustParseAddr("203.0.113.130")
	InetV6 = netip.MustParseAddr("2001:db8:b::2")
	WanIV4 = netip.MustParseAddr("203.0.113.129")
	WanIV6 = netip.MustParseAddr("2001:db8:b::1")

	DNSAnswerA    = netip.MustParseAddr("203.0.113.99")
	DNSAnswerAAAA = netip.MustParseAddr("2001:db8:b::99")

	InnerV4 = netip.MustParsePrefix("198.18.0.0/16")
	InnerV6 = netip.MustParsePrefix("2001:db8:ffff::/48")
)

// IsClientPhys — адрес физического интерфейса клиента: пакет с ним на WAN — выход мимо туннеля.
func IsClientPhys(a netip.Addr) bool {
	a = a.Unmap()
	return a == ClientV4 || a == ClientV6
}

// Inet возвращает адрес «интернет»-хоста нужного семейства.
func Inet(family int) netip.Addr {
	if family == 6 {
		return InetV6
	}
	return InetV4
}
