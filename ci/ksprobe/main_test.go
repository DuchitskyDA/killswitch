package main

import (
	"errors"
	"syscall"
	"testing"
)

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

func TestParseArgsWithoutInterface(t *testing.T) {
	r, err := parseArgs([]string{"http", "1.1.1.1"})
	if err != nil || r.iface != "" || r.service.Name != "http" {
		t.Errorf("проба без привязки: %+v, %v", r, err)
	}
}

func TestParseArgsRejectsExtraArgument(t *testing.T) {
	if _, err := parseArgs([]string{"http", "1.1.1.1", "en0", "лишний"}); err == nil {
		t.Error("лишний аргумент должен быть ошибкой (код 2)")
	}
}

func TestExitCodeBindErrorIsNotBlocked(t *testing.T) {
	if got := exitCode(errors.New("нет ответа"), errors.New("setsockopt")); got != 2 {
		t.Errorf("ошибка привязки — код 2, а не «закрыто» (1): %d", got)
	}
}

func TestExitCodeNoAnswerIsBlocked(t *testing.T) {
	if got := exitCode(errors.New("i/o timeout"), nil); got != 1 {
		t.Errorf("нет ответа без ошибки привязки — код 1: %d", got)
	}
}

func TestRecordBindKeepsControlError(t *testing.T) {
	var got error
	ctrl := recordBind(func(string, string, syscall.RawConn) error { return errors.New("setsockopt") }, &got)
	if err := ctrl("udp4", "1.1.1.1:53", nil); err == nil || got == nil {
		t.Errorf("ошибка привязки должна вернуться и сохраниться: %v / %v", err, got)
	}
}

func TestExitCodeAnswerIsZero(t *testing.T) {
	if got := exitCode(nil, nil); got != 0 {
		t.Errorf("ответ сервера — код 0: %d", got)
	}
}
