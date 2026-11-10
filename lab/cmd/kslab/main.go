// kslab — раннер лаборатории киллсвитча в Linux network namespace.
//
//	kslab run [--dir /opt/killswitch-lab] [--tunnels wireguard,sing-box,xray]   первый прогон: наивная политика nft
//	kslab accept --client wireguard|sing-box|sing-box-ar|xray [--dir …]        живая приёмка против настоящего killswitch
//	kslab summary results-*.json                                              сводная таблица прогонов (любая ОС)
//	kslab cleanup
//	kslab nsexec --ns-path PATH -- КОМАНДА   (демонстрация защиты: корневой ns → выход 2)
//
// Подкоманды serve, capture, probe, mark, wgset, http, ksexec вызываются раннером внутри своих ns и сами сверяют --expect-ino
// (ksexec — ещё и --expect-mnt). Коды выхода: 0 — критерий выполнен, 1 — нет или ошибка, 2 — защита хоста отказала.
package main

import (
	"fmt"
	"os"

	"github.com/DuchitskyDA/killswitch/lab/internal/lab"
	"github.com/DuchitskyDA/killswitch/lab/internal/nsguard"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "использование: kslab run|accept|summary|cleanup|nsexec|serve|capture|probe|mark|wgset|http|ksexec")
		os.Exit(2)
	}
	if os.Args[1] == "summary" {
		os.Exit(exitCode(lab.SummaryMain(os.Args[2:], os.Stdout)))
	}
	os.Exit(exitCode(dispatch(os.Args[1], os.Args[2:])))
}

func exitCode(err error) int {
	if err == nil {
		return 0
	}
	fmt.Fprintln(os.Stderr, "kslab:", err)
	if nsguard.IsGuard(err) {
		return 2
	}
	return 1
}
