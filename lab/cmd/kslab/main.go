// kslab — раннер лаборатории киллсвитча в Linux network namespace.
//
//	kslab run [--dir /opt/killswitch-lab] [--tunnels wireguard,sing-box,xray]
//	kslab cleanup
//	kslab nsexec --ns-path PATH -- КОМАНДА   (демонстрация защиты: корневой ns → выход 2)
//
// Подкоманды serve, capture, probe, mark, wgset вызываются раннером внутри своих ns и сами сверяют --expect-ino.
// Коды выхода: 0 — критерий выполнен, 1 — нет или ошибка, 2 — защита хоста отказала (цель — корневой ns и т. п.).
package main

import (
	"fmt"
	"os"

	"github.com/DuchitskyDA/killswitch/lab/internal/nsguard"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "использование: kslab run|cleanup|nsexec|serve|capture|probe|mark|wgset")
		os.Exit(2)
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
