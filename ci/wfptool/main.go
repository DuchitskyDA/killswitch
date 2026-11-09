//go:build windows

// Команда wfptool — чужие вмешательства в WFP для живых сценариев CI (ci.yml, live-windows). Только на одноразовом
// раннере GitHub: без GITHUB_ACTIONS=true и RUNNER_ENVIRONMENT=github-hosted — выход 2 до любого вызова WFP.
//
//	wfptool tie <ready-файл> <stop-файл> <секунды> — чужой sublayer 0xFFFF с hard permit на CONNECT_V4 (dynamic-сессия)
//	                                             живёт, пока нет stop-файла или не вышло время
//	wfptool strip                                — удалить наши persistent-фильтры («правила сняты вручную»);
//	                                             provider, sublayer и boot-time остаются
//	wfptool collect                              — включить сбор событий отброса
//	wfptool drops <ip> <с RFC3339>               — отбросы к адресу после момента; код 0 — есть отброс нашим фильтром
package main

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"strconv"
	"time"

	"github.com/DuchitskyDA/killswitch/internal/third_party/wf"
	xwin "golang.org/x/sys/windows"
)

// ourProvider — GUID provider killswitch (internal/backend/windows/wfp_windows.go): фиксирован контрактом.
var ourProvider = wf.ProviderID(xwin.GUID{Data1: 0x8f2c6a41, Data2: 0x93d7, Data3: 0x4b0e,
	Data4: [8]byte{0xa5, 0xf1, 0x27, 0xc9, 0x4e, 0x6d, 0x0b, 0x3a}})

var ourLayers = []wf.LayerID{wf.LayerALEAuthConnectV4, wf.LayerALEAuthConnectV6,
	wf.LayerALEAuthRecvAcceptV4, wf.LayerALEAuthRecvAcceptV6}

func main() {
	if os.Getenv("GITHUB_ACTIONS") != "true" || os.Getenv("RUNNER_ENVIRONMENT") != "github-hosted" {
		fmt.Fprintln(os.Stderr, "wfptool — только на одноразовом раннере GitHub")
		os.Exit(2)
	}
	code, err := run(os.Args[1:])
	if err != nil {
		fmt.Fprintln(os.Stderr, "wfptool:", err)
	}
	os.Exit(code)
}

func run(args []string) (int, error) {
	if len(args) == 0 {
		return 2, errors.New("нет команды")
	}
	switch {
	case args[0] == "tie" && len(args) == 4:
		secs, err := strconv.Atoi(args[3])
		if err != nil {
			return 2, err
		}
		return tie(args[1], args[2], time.Duration(secs)*time.Second)
	case args[0] == "strip" && len(args) == 1:
		return strip()
	case args[0] == "collect" && len(args) == 1:
		return collect()
	case args[0] == "drops" && len(args) == 3:
		ip, err := netip.ParseAddr(args[1])
		if err != nil {
			return 2, err
		}
		since, err := time.Parse(time.RFC3339Nano, args[2])
		if err != nil {
			return 2, err
		}
		return drops(ip, since)
	}
	return 2, fmt.Errorf("неизвестная команда %q", args)
}

func tie(ready, stop string, limit time.Duration) (int, error) {
	s, err := wf.New(&wf.Options{Name: "ks-ci-foreign", Dynamic: true})
	if err != nil {
		return 2, err
	}
	defer s.Close()
	sub := wf.SublayerID(xwin.GUID{Data1: 0x5a5a0101, Data2: 0x1, Data3: 0x4000, Data4: [8]byte{0x80, 1, 2, 3, 4, 5, 6, 7}})
	if err := s.AddSublayer(&wf.Sublayer{ID: sub, Name: "ks-ci-foreign", Weight: 0xFFFF}); err != nil {
		return 2, err
	}
	rule := &wf.Rule{ID: wf.RuleID(xwin.GUID{Data1: 0x5a5a0102, Data2: 0x1, Data3: 0x4000, Data4: [8]byte{0x80, 1, 2, 3, 4, 5, 6, 8}}),
		Name: "ks-ci-foreign permit all", Layer: wf.LayerALEAuthConnectV4, Sublayer: sub, Weight: 15,
		Action: wf.ActionPermit, HardAction: true}
	if err := s.AddRule(rule); err != nil {
		return 2, err
	}
	if err := os.WriteFile(ready, []byte("ready\n"), 0o644); err != nil {
		return 2, err
	}
	fmt.Println("чужой sublayer 0xFFFF с hard permit создан")
	for end := time.Now().Add(limit); time.Now().Before(end); time.Sleep(500 * time.Millisecond) {
		if _, err := os.Stat(stop); err == nil {
			fmt.Println("stop-файл: чужой sublayer снят")
			return 0, nil
		}
	}
	return 1, errors.New("время вышло без stop-файла")
}

func strip() (int, error) {
	s, err := wf.New(&wf.Options{Name: "ks-ci-strip"})
	if err != nil {
		return 2, err
	}
	defer s.Close()
	pid, n := ourProvider, 0
	for _, l := range ourLayers {
		rules, err := s.RulesOf(wf.RuleFilter{Provider: &pid, Layer: l, IncludeDisabled: true})
		if err != nil {
			return 2, err
		}
		for _, r := range rules {
			if r.BootTime {
				continue
			}
			if err := s.DeleteRule(r.ID); err != nil {
				return 2, fmt.Errorf("удалить %s: %w", r.Name, err)
			}
			n++
		}
	}
	fmt.Printf("удалено наших фильтров: %d\n", n)
	if n == 0 {
		return 1, errors.New("наших фильтров не было")
	}
	return 0, nil
}

func collect() (int, error) {
	s, err := wf.New(&wf.Options{Name: "ks-ci-collect", Dynamic: true})
	if err != nil {
		return 2, err
	}
	defer s.Close()
	if err := s.SetCollectNetEvents(true); err != nil {
		return 2, err
	}
	return 0, nil
}

func drops(ip netip.Addr, since time.Time) (int, error) {
	s, err := wf.New(&wf.Options{Name: "ks-ci-drops", Dynamic: true})
	if err != nil {
		return 2, err
	}
	defer s.Close()
	ours := map[uint64]bool{}
	pid := ourProvider
	for _, l := range ourLayers {
		rules, err := s.RulesOf(wf.RuleFilter{Provider: &pid, Layer: l, IncludeDisabled: true})
		if err != nil {
			return 2, err
		}
		for _, r := range rules {
			ours[r.KernelID] = r.Action == wf.ActionBlock
		}
	}
	evs, err := s.DropEventsSince(since, time.Now().Add(time.Minute))
	if err != nil {
		return 2, err
	}
	found := 0
	for _, ev := range evs {
		if ev.RemoteAddr.Addr() != ip {
			continue
		}
		mark := "чужой"
		if ours[ev.FilterID] {
			mark, found = "наш block", found+1
		}
		fmt.Printf("отброс %s proto=%d %s -> %s filter=%d (%s) app=%q\n", ev.Timestamp.Format(time.RFC3339Nano),
			ev.IPProtocol, ev.LocalAddr, ev.RemoteAddr, ev.FilterID, mark, ev.AppID)
	}
	if found == 0 {
		return 1, nil
	}
	return 0, nil
}
