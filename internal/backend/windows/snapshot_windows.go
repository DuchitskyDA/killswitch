package windows

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"time"
	"unsafe"

	"github.com/DuchitskyDA/killswitch/internal/env"
	"github.com/DuchitskyDA/killswitch/internal/policy"
	"github.com/DuchitskyDA/killswitch/internal/third_party/wf"
	xwin "golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

const resolveTimeout = 3 * time.Second

// Типы интерфейсов IANA, которые считаются физическими: Ethernet, Wi-Fi, WWAN.
var physicalTypes = map[uint32]bool{6: true, 71: true, 243: true, 244: true}

// Snapshot — всё с побочными эффектами: адаптеры, app-id программ, разрешение имён, маршруты, резолверы, boot id.
func (b *Backend) Snapshot(p policy.Policy) (env.Env, error) {
	ifaces, dns, err := adapters(p)
	if err != nil {
		return env.Env{}, err
	}
	rows, err := defaultRouteRows()
	markDefaultRoutes(ifaces, rows, err)
	e := env.Env{OS: "windows", Ifaces: ifaces, DHCPDNS: dns, Health: env.HealthUnknown}
	if e.Programs, err = programs(p); err != nil {
		return env.Env{}, err
	}
	e.Resolved, e.ResolveErr = resolve(p)
	e.Routes = routes(p, e)
	if e.BootID, err = bootID(); err != nil {
		return env.Env{}, err
	}
	return e, nil
}

// adapters — интерфейсы и DNS-серверы физических адаптеров (выданные DHCP/RA или заданные вручную).
func adapters(p policy.Policy) ([]env.Iface, []netip.Addr, error) {
	size := uint32(32 << 10)
	var buf []byte
	for {
		buf = make([]byte, size)
		err := xwin.GetAdaptersAddresses(xwin.AF_UNSPEC, xwin.GAA_FLAG_INCLUDE_ALL_INTERFACES, 0,
			(*xwin.IpAdapterAddresses)(unsafe.Pointer(&buf[0])), &size)
		if err == xwin.ERROR_BUFFER_OVERFLOW {
			continue
		}
		if err != nil {
			return nil, nil, fmt.Errorf("GetAdaptersAddresses: %w", err)
		}
		break
	}
	probeEnv := env.Env{OS: "windows"}
	var ifaces []env.Iface
	var dns []netip.Addr
	for a := (*xwin.IpAdapterAddresses)(unsafe.Pointer(&buf[0])); a != nil; a = a.Next {
		name := xwin.UTF16PtrToString(a.FriendlyName)
		i := env.Iface{Name: name, Alias: name, Description: xwin.UTF16PtrToString(a.Description),
			Index: int(a.IfIndex), LUID: a.Luid, Up: a.OperStatus == xwin.IfOperStatusUp}
		if i.Index == 0 {
			i.Index = int(a.Ipv6IfIndex)
		}
		for u := a.FirstUnicastAddress; u != nil; u = u.Next {
			if ip, ok := netip.AddrFromSlice(u.Address.IP()); ok {
				i.Addrs = append(i.Addrs, netip.PrefixFrom(ip.Unmap(), int(u.OnLinkPrefixLength)))
			}
		}
		probeEnv.Ifaces = []env.Iface{i}
		tunnel := len(probeEnv.MatchIfaces(p.Tunnel.Interfaces)) > 0
		i.Physical = physicalTypes[a.IfType] && !tunnel
		if i.Physical {
			for d := a.FirstDnsServerAddress; d != nil; d = d.Next {
				if ip, ok := netip.AddrFromSlice(d.Address.IP()); ok {
					dns = append(dns, ip.Unmap())
				}
			}
		}
		ifaces = append(ifaces, i)
	}
	return ifaces, dns, nil
}

// programs раскрывает все glob политики (Trust и Repair — независимо от режима) в app-id и находит программы
// по именам repair.names.
func programs(p policy.Policy) (map[string][]string, error) {
	globs := append([]string{}, p.Repair.Programs...)
	for _, t := range p.Trust {
		if t.Kind == policy.KindProgram {
			globs = append(globs, t.Value)
		}
	}
	out := map[string][]string{}
	for _, g := range globs {
		paths, err := filepath.Glob(ExpandProgramGlob(g, os.Getenv))
		if err != nil {
			return nil, fmt.Errorf("шаблон %q: %w", g, err)
		}
		sort.Strings(paths)
		var ids []string
		for _, path := range paths {
			id, err := wf.AppID(path)
			if err != nil {
				return nil, fmt.Errorf("app-id %s: %w", path, err)
			}
			ids = append(ids, id)
		}
		out[g] = ids
	}
	return out, addNamed(out, p.Repair.Names)
}

// resolve разрешает имена Endpoints.
func resolve(p policy.Policy) (map[string][]netip.Addr, map[string]string) {
	resolved, errs := map[string][]netip.Addr{}, map[string]string{}
	for _, ep := range p.Tunnel.Endpoints {
		if _, ok := ep.Addr(); ok {
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), resolveTimeout)
		addrs, err := net.DefaultResolver.LookupNetIP(ctx, "ip", ep.Host)
		cancel()
		if err != nil {
			errs[ep.Host] = err.Error()
			continue
		}
		resolved[ep.Host] = addrs
	}
	return resolved, errs
}

// defaultRouteRows — маршруты по умолчанию (0.0.0.0/0, ::/0) таблицы маршрутов: интерфейс и семейство.
func defaultRouteRows() ([]routeRow, error) {
	var rows []routeRow
	for _, fam := range []uint16{xwin.AF_INET, xwin.AF_INET6} {
		var t *xwin.MibIpForwardTable2
		if err := xwin.GetIpForwardTable2(fam, &t); err != nil {
			return nil, fmt.Errorf("GetIpForwardTable2: %w", err)
		}
		for _, r := range t.Rows() {
			if r.DestinationPrefix.PrefixLength == 0 {
				rows = append(rows, routeRow{LUID: r.InterfaceLuid, V4: fam == xwin.AF_INET})
			}
		}
		xwin.FreeMibTable(unsafe.Pointer(t))
	}
	return rows, nil
}

// routes — эффективный интерфейс к адресам целей check, Endpoints и dns.health.
func routes(p policy.Policy, e env.Env) map[netip.Addr]env.Route {
	targets := routeTargets(p, e)
	tunnel := map[int]bool{}
	for _, i := range e.MatchIfaces(p.Tunnel.Interfaces) {
		tunnel[i.Index] = true
	}
	out := map[netip.Addr]env.Route{}
	for _, a := range targets {
		var idx uint32
		if err := xwin.GetBestInterfaceEx(sockaddrOf(a), &idx); err != nil {
			continue
		}
		out[a] = env.Route{IfaceIndex: int(idx), ViaTunnel: tunnel[int(idx)]}
	}
	return out
}

// bootID — счётчик загрузок Windows (PrefetchParameters\BootId); его нет — время загрузки с точностью до минуты.
func bootID() (string, error) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters`, registry.QUERY_VALUE)
	if err == nil {
		defer k.Close()
		if v, _, err := k.GetIntegerValue("BootId"); err == nil {
			return fmt.Sprintf("bootid:%d", v), nil
		}
	}
	up := time.Duration(xwin.DurationSinceBoot())
	return "boottime:" + time.Now().Add(-up).UTC().Truncate(time.Minute).Format(time.RFC3339), nil
}

// sockaddrOf — адрес для GetBestInterfaceEx по семейству (IPv4-в-IPv6 — как IPv4).
func sockaddrOf(a netip.Addr) xwin.Sockaddr {
	if a = a.Unmap(); a.Is4() {
		return &xwin.SockaddrInet4{Addr: a.As4()}
	}
	return &xwin.SockaddrInet6{Addr: a.As16()}
}
