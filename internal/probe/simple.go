package probe

import (
	"fmt"
	"net/netip"
)

// SimpleHost — сайт простой проверки: check без своих целей ([check] targets).
const SimpleHost = "example.com"

// simpleService — единственная проба простой проверки: HTTP к SimpleHost.
var simpleService = Service{Name: "http", Proto: "tcp", Port: 80, Host: SimpleHost}

// Служебные диапазоны, которые клиенты туннеля отдают вместо настоящего адреса (подмена имён), и общий NAT
// провайдера: с физического интерфейса такой адрес не ответит при любой защите.
var notPublic = []netip.Prefix{netip.MustParsePrefix("198.18.0.0/15"), netip.MustParsePrefix("100.64.0.0/10")}

// simple — простая проверка: SimpleHost должен ответить обычным путём и не ответить ни через один физический
// интерфейс. Свидетельство отброса не требуется, поэтому молчание сервера засчитывается, только если обычным
// путём он отвечает. Ответ через физический интерфейс — утечка при любом ответе обычным путём.
func (r *runner) simple(in Input) []ProbeResult {
	s := simpleService
	unsure := func(detail string) []ProbeResult {
		return []ProbeResult{{Target: SimpleHost, Proto: s.Name, Class: Inconclusive, Detail: detail}}
	}
	addrs, err := r.p.Resolve(r.ctx, SimpleHost)
	if err != nil {
		return unsure("имя не разрешилось: " + err.Error())
	}
	if len(addrs) == 0 {
		return unsure("имя не разрешилось: адресов нет")
	}
	dsts := publicPerFamily(addrs)
	if len(dsts) == 0 {
		return unsure(fmt.Sprintf("имя разрешилось в служебный адрес %s: похоже на подмену имён клиентом туннеля, "+
			"простая проверка не подходит — задайте свои адреса ([check] targets)", addrs[0].Unmap()))
	}
	var plainErr error
	reached := false
	for _, dst := range dsts {
		if err := r.p.Plain(r.ctx, s, dst); err == nil {
			reached = true
		} else if plainErr == nil {
			plainErr = err
		}
	}
	silent := func(ProbeID) (Class, string) {
		if !reached {
			return Inconclusive, "ответа нет, но и обычным путём " + SimpleHost + " не ответил: " + plainErr.Error()
		}
		return Blocked, "ответа нет, обычным путём " + SimpleHost + " отвечает"
	}
	var out []ProbeResult
	for _, dst := range dsts {
		out = append(out, r.physical(in, s, dst, "", silent)...)
	}
	return out
}

// publicPerFamily — первый публичный адрес каждого семейства, v4 раньше v6.
func publicPerFamily(addrs []netip.Addr) []netip.Addr {
	var v4, v6 []netip.Addr
	for _, a := range addrs {
		a = a.Unmap().WithZone("")
		switch {
		case !public(a):
		case a.Is4() && v4 == nil:
			v4 = []netip.Addr{a}
		case a.Is6() && v6 == nil:
			v6 = []netip.Addr{a}
		}
	}
	return append(v4, v6...)
}

func public(a netip.Addr) bool {
	if !a.IsGlobalUnicast() || a.IsPrivate() {
		return false
	}
	for _, p := range notPublic {
		if p.Contains(a) {
			return false
		}
	}
	return true
}
