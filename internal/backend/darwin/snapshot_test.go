package darwin

import (
	"testing"

	"github.com/DuchitskyDA/killswitch/internal/env"
)

const netstatInet = `Routing tables

Internet:
Destination        Gateway            Flags               Netif Expire
default            192.168.1.1        UGScg                 en0
default            link#18            UCSIg               utun3
default            192.168.64.1       UGRScIg             bridge100
127                127.0.0.1          UCS                   lo0
192.168.1          link#6             UCS                   en0      !
`

const netstatInet6 = `Routing tables

Internet6:
Destination                             Gateway                                 Flags               Netif Expire
default                                 fe80::%utun0                            UGcIg               utun0
default                                 fe80::1%en0                             UGc                   en0
::1                                     ::1                                     UHL                   lo0
`

func darwinIfaces() []env.Iface {
	return []env.Iface{{Name: "en0"}, {Name: "en5"}, {Name: "bridge100"}, {Name: "utun3"}}
}

func darwinDefaults(ifaces []env.Iface) map[string][2]bool {
	out := map[string][2]bool{}
	for _, i := range ifaces {
		out[i.Name] = [2]bool{i.DefaultRoute4, i.DefaultRoute6}
	}
	return out
}

// (в) Маршрут по умолчанию — по строкам default `netstat -rn` каждого семейства; reject (R) и blackhole (B) — нет.
func TestDefaultRoutesFromNetstat(t *testing.T) {
	f := newFixture(t)
	f.run.on("netstat -rn -f inet", netstatInet)
	f.run.on("netstat -rn -f inet6", netstatInet6)
	ifs := darwinIfaces()
	f.b.markDefaultRoutes(ifs)
	got := darwinDefaults(ifs)
	if got["en0"] != [2]bool{true, true} || got["en5"] != [2]bool{false, false} || got["bridge100"] != [2]bool{false, false} {
		t.Fatalf("маршруты по умолчанию: %v", got)
	}
}

// Таблицу маршрутов не прочитать — маршрут считается у каждого: пробы check идут, как раньше.
func TestDefaultRoutesUnreadableAssumesRoute(t *testing.T) {
	f := newFixture(t)
	f.run.fails["netstat -rn -f inet"] = true
	f.run.on("netstat -rn -f inet6", netstatInet6)
	ifs := darwinIfaces()
	f.b.markDefaultRoutes(ifs)
	if got := darwinDefaults(ifs); got["en5"] != [2]bool{true, false} {
		t.Fatalf("без таблицы v4: %v", got)
	}
}
