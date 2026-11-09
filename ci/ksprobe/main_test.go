package main

import "testing"

func TestParseArgsBindsServiceAddressAndInterface(t *testing.T) {
	r, err := parseArgs([]string{"dns-udp", "168.63.129.16", "Ethernet"})
	if err != nil || r.service.Port != 53 || r.service.Proto != "udp" || r.dst.String() != "168.63.129.16" || r.iface != "Ethernet" {
		t.Errorf("dns-udp к резолверу через Ethernet: %+v, %v", r, err)
	}
}

func TestParseArgsRejectsUnknownProbe(t *testing.T) {
	if _, err := parseArgs([]string{"icmp", "1.1.1.1"}); err == nil {
		t.Error("неизвестная проба должна быть ошибкой (код 2)")
	}
}
