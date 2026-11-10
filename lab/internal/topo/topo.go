// Package topo описывает топологию лаборатории: имена namespace, интерфейсы и адреса.
// Все адреса вне LAN-диапазонов Policy: TEST-NET-2/3, 198.18.0.0/15 и 2001:db8::/32.
package topo

import "net/netip"

const (
	ClientNS = "ksl-client"
	WanNS    = "ksl-wan"
	PeerNS   = "ksl-peer"
	InetNS   = "ksl-inet"
	MountNS  = "ksl-mnt" // пустой netns держателя mount ns приёмки: kslab cleanup гасит его вместе с прочими

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
	NobodyUID     = 65534  // от него идут пробы «программы»: профили доверяют root
	BypassUID     = 65533  // «программа» мимо туннеля при sing-box auto_redirect: exclude_uid клиента, иначе redirect перехватит прямую пробу
	WGMark        = 0xca6c // fwmark транспорта WireGuard, как у wg-quick (профиль wireguard доверяет ей)
)

var (
	ClientV4 = netip.MustParseAddr("198.51.100.2")
	ClientV6 = netip.MustParseAddr("2001:db8:c::2")
	WanCV4   = netip.MustParseAddr("198.51.100.1")
	WanCV6   = netip.MustParseAddr("2001:db8:c::1")

	PeerV4 = netip.MustParseAddr("203.0.113.2")
	PeerV6 = netip.MustParseAddr("2001:db8:a::2")
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

// LAN на линии клиента (c0 ↔ wc): RFC1918 и ULA — диапазоны LAN Policy. HTTP и DNS «LAN-хоста» слушает ksl-wan.
var (
	LanClientV4 = netip.MustParseAddr("192.168.77.2")
	LanHostV4   = netip.MustParseAddr("192.168.77.1")
	LanClientV6 = netip.MustParseAddr("fd77::2")
	LanHostV6   = netip.MustParseAddr("fd77::1")
)

// IsClientLAN — LAN-адрес клиента.
func IsClientLAN(a netip.Addr) bool {
	a = a.Unmap()
	return a == LanClientV4 || a == LanClientV6
}

// Lan возвращает адрес LAN-хоста нужного семейства.
func Lan(family int) netip.Addr {
	if family == 6 {
		return LanHostV6
	}
	return LanHostV4
}
